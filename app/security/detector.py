import math
import re
import time
from collections import Counter
from enum import Enum
from typing import List, Optional, Tuple

from pydantic import BaseModel, Field

from app.config import settings
from app.security.rules import (
    CREDIT_CARD_CANDIDATE_REGEX,
    INJECTION_PATTERNS,
    PATTERNS,
    validate_luhn,
)


class PolicyMode(str, Enum):
    ALLOW = "ALLOW"
    REDACT = "REDACT"
    BLOCK = "BLOCK"


class FindingCategory(str, Enum):
    PII = "PII"
    SECRET = "SECRET"
    PROMPT_INJECTION = "PROMPT_INJECTION"


class Finding(BaseModel):
    type: str
    category: FindingCategory
    rule_name: str
    safe_preview: str
    start: int
    end: int
    entropy: Optional[float] = None
    details: Optional[str] = None


class InspectionResult(BaseModel):
    action: str  # "ALLOW", "REDACT", "BLOCK"
    is_blocked: bool
    block_reason: Optional[str] = None
    sanitized_text: str
    original_text: str
    findings: List[Finding] = Field(default_factory=list)
    inspection_ms: float = 0.0


def calculate_shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy in bits per symbol for a given string."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return round(entropy, 3)


def make_safe_preview(val: str, finding_type: str) -> str:
    """Creates a non-sensitive preview of a matched entity."""
    if finding_type == "EMAIL":
        parts = val.split("@", 1)
        if len(parts) == 2:
            user, domain = parts
            masked_user = user[:2] + "***" if len(user) > 2 else "***"
            return f"{masked_user}@{domain}"
        return "***@***"
    elif finding_type == "CREDIT_CARD":
        digits = re.sub(r"\D", "", val)
        last4 = digits[-4:] if len(digits) >= 4 else "****"
        return f"****-****-****-{last4}"
    elif finding_type in ("AWS_KEY", "OPENAI_KEY", "GITHUB_TOKEN", "HIGH_ENTROPY_SECRET"):
        if len(val) > 8:
            return f"{val[:4]}...{val[-4:]}"
        return "****"
    elif finding_type == "PROMPT_INJECTION":
        # Truncate prompt injection preview to 40 chars
        return val[:40] + ("..." if len(val) > 40 else "")
    return val[:10] + "..."


class SecurityDetector:
    """
    Deterministic security engine for detecting PII, Secrets (regex & Shannon entropy),
    and Prompt Injection/Jailbreak heuristics.
    """

    def __init__(
        self,
        entropy_threshold: float = settings.ENTROPY_THRESHOLD,
        min_entropy_len: int = settings.MIN_ENTROPY_STRING_LEN,
    ):
        self.entropy_threshold = entropy_threshold
        self.min_entropy_len = min_entropy_len
        self.candidate_entropy_regex = re.compile(r"\b[A-Za-z0-9+/=_~-]{" + str(min_entropy_len) + r",}\b")

    def inspect(
        self,
        text: str,
        policy_mode: PolicyMode = PolicyMode.REDACT,
        block_injections: bool = True,
        check_entropy: bool = True,
    ) -> InspectionResult:
        """
        Inspects text against security rules and returns an InspectionResult
        evaluating policy mode (ALLOW, REDACT, BLOCK).
        """
        start_time = time.perf_counter()
        findings: List[Finding] = []
        replacement_spans: List[Tuple[int, int, str]] = []

        if not text:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 3)
            return InspectionResult(
                action="ALLOW",
                is_blocked=False,
                block_reason=None,
                sanitized_text="",
                original_text="",
                findings=[],
                inspection_ms=elapsed_ms,
            )

        # 1. Deterministic Regex Scanning (Secrets & PII)
        for pattern_name, regex in PATTERNS.items():
            for match in regex.finditer(text):
                matched_val = match.group()
                start, end = match.span()
                category = FindingCategory.PII if pattern_name == "EMAIL" else FindingCategory.SECRET

                findings.append(
                    Finding(
                        type=pattern_name,
                        category=category,
                        rule_name=f"REGEX_{pattern_name}",
                        safe_preview=make_safe_preview(matched_val, pattern_name),
                        start=start,
                        end=end,
                    )
                )
                replacement_spans.append((start, end, f"[REDACTED_{pattern_name}]"))

        # 2. Credit Card Candidate Detection with Luhn Algorithm
        for match in CREDIT_CARD_CANDIDATE_REGEX.finditer(text):
            candidate = match.group()
            start, end = match.span()

            # Avoid re-detecting spans already matched by other rules
            if any(s <= start < e or s < end <= e for s, e, _ in replacement_spans):
                continue

            if validate_luhn(candidate):
                findings.append(
                    Finding(
                        type="CREDIT_CARD",
                        category=FindingCategory.PII,
                        rule_name="LUHN_CREDIT_CARD",
                        safe_preview=make_safe_preview(candidate, "CREDIT_CARD"),
                        start=start,
                        end=end,
                    )
                )
                replacement_spans.append((start, end, "[REDACTED_CREDIT_CARD]"))

        # 3. High-Entropy Secret Detection (Shannon Entropy)
        if check_entropy:
            for match in self.candidate_entropy_regex.finditer(text):
                token = match.group()
                start, end = match.span()

                # Skip spans already claimed by regex/credit card
                if any(s <= start < e or s < end <= e for s, e, _ in replacement_spans):
                    continue

                # Strip typical separators
                clean_token = token.strip(".-_")
                if len(clean_token) < self.min_entropy_len:
                    continue

                entropy = calculate_shannon_entropy(clean_token)
                if entropy >= self.entropy_threshold:
                    findings.append(
                        Finding(
                            type="HIGH_ENTROPY_SECRET",
                            category=FindingCategory.SECRET,
                            rule_name="SHANNON_ENTROPY",
                            safe_preview=make_safe_preview(token, "HIGH_ENTROPY_SECRET"),
                            start=start,
                            end=end,
                            entropy=entropy,
                            details=f"Entropy: {entropy:.2f} >= {self.entropy_threshold}",
                        )
                    )
                    replacement_spans.append((start, end, "[REDACTED_SECRET]"))

        # 4. Prompt Injection & Jailbreak Heuristics
        has_prompt_injection = False
        injection_reasons: List[str] = []

        for rule in INJECTION_PATTERNS:
            for match in rule["pattern"].finditer(text):
                has_prompt_injection = True
                matched_val = match.group()
                start, end = match.span()
                category_name = rule["category"]
                description = rule["description"]
                injection_reasons.append(f"{category_name}: {description}")

                findings.append(
                    Finding(
                        type="PROMPT_INJECTION",
                        category=FindingCategory.PROMPT_INJECTION,
                        rule_name=category_name,
                        safe_preview=make_safe_preview(matched_val, "PROMPT_INJECTION"),
                        start=start,
                        end=end,
                        details=description,
                    )
                )
                replacement_spans.append((start, end, "[REDACTED_PROMPT_INJECTION]"))

        # 5. Policy Decision Evaluation
        non_injection_findings = [
            f for f in findings if f.category != FindingCategory.PROMPT_INJECTION
        ]

        # Prompt injection blocking takes precedence regardless of DLP mode when enabled
        if has_prompt_injection and block_injections:
            action = "BLOCK"
            is_blocked = True
            block_reason = f"Prompt injection detected: {'; '.join(injection_reasons)}"
            sanitized_text = text
        elif policy_mode == PolicyMode.BLOCK:
            # When block_injections is False, injection findings do NOT cause BLOCK
            if len(non_injection_findings) > 0:
                action = "BLOCK"
                is_blocked = True
                reasons = [f"{f.category.value} ({f.type})" for f in non_injection_findings]
                block_reason = f"Security policy blocked request: {', '.join(set(reasons))}"
            else:
                action = "ALLOW"
                is_blocked = False
                block_reason = None
            sanitized_text = text
        elif policy_mode == PolicyMode.REDACT:
            if len(findings) > 0:
                action = "REDACT"
                sanitized_text = self._apply_replacements(text, replacement_spans)
            else:
                action = "ALLOW"
                sanitized_text = text
            is_blocked = False
            block_reason = None
        else:  # PolicyMode.ALLOW
            # ALLOW mode (log-only monitor mode): never blocks non-injections and never redacts
            action = "ALLOW"
            is_blocked = False
            block_reason = None
            sanitized_text = text

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 3)

        return InspectionResult(
            action=action,
            is_blocked=is_blocked,
            block_reason=block_reason,
            sanitized_text=sanitized_text,
            original_text=text,
            findings=findings,
            inspection_ms=elapsed_ms,
        )

    def _apply_replacements(self, text: str, spans: List[Tuple[int, int, str]]) -> str:
        """Applies non-overlapping replacements from end to start."""
        if not spans:
            return text

        # Sort spans by start position ascending
        sorted_spans = sorted(spans, key=lambda x: (x[0], -(x[1] - x[0])))

        # Filter out overlaps
        resolved_spans: List[Tuple[int, int, str]] = []
        last_end = -1
        for start, end, replacement in sorted_spans:
            if start >= last_end:
                resolved_spans.append((start, end, replacement))
                last_end = end

        # Apply from back to front so indices remain valid
        result = list(text)
        for start, end, replacement in reversed(resolved_spans):
            result[start:end] = list(replacement)

        return "".join(result)


# Global singleton instance
detector = SecurityDetector()
