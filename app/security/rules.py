import re
from typing import Dict, List, Pattern

# Regex patterns for deterministic PII and secrets
PATTERNS: Dict[str, Pattern[str]] = {
    "AWS_KEY": re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
    "OPENAI_KEY": re.compile(
        r"\b(?:sk-proj-[a-zA-Z0-9_\-]{20,}|sk-admin-[a-zA-Z0-9_\-]{20,}|sk-[a-zA-Z0-9]{20,})\b"
    ),
    "GITHUB_TOKEN": re.compile(
        r"\b(?:ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{22,}|gho_[a-zA-Z0-9]{36}|ghu_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|ghr_[a-zA-Z0-9]{36})\b"
    ),
    "EMAIL": re.compile(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b"),
}

# Candidate credit card pattern (13-19 digits, optional spaces/hyphens)
CREDIT_CARD_CANDIDATE_REGEX = re.compile(r"\b(?:\d[ -]*?){13,19}\b")


def validate_luhn(card_number_str: str) -> bool:
    """
    Validates a credit card candidate using card length, prefix filters,
    and the Luhn algorithm (mod 10).
    """
    digits = [int(c) for c in card_number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    num_str = "".join(str(d) for d in digits)

    # Validate major card brand prefixes
    # Visa: 4
    # Mastercard: 51-55, 2221-2720
    # Amex: 34, 37
    # Discover: 6011, 622126-622925, 644-649, 65
    # Diners Club: 300-305, 36, 38
    # JCB: 3528-3589
    is_valid_prefix = (
        num_str.startswith("4")
        or any(num_str.startswith(str(p)) for p in range(51, 56))
        or any(num_str.startswith(str(p)) for p in range(2221, 2721))
        or num_str.startswith(("34", "37"))
        or num_str.startswith(("6011", "65"))
        or any(num_str.startswith(str(p)) for p in range(644, 650))
        or num_str.startswith(("36", "38"))
        or any(num_str.startswith(str(p)) for p in range(300, 306))
        or any(num_str.startswith(str(p)) for p in range(3528, 3590))
    )

    if not is_valid_prefix:
        return False

    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d = d * 2
            if d > 9:
                d -= 9
        checksum += d

    return checksum % 10 == 0


# Prompt injection and jailbreak heuristic patterns
INJECTION_PATTERNS: List[Dict[str, any]] = [
    # 1. Instruction Overrides
    {
        "category": "INSTRUCTION_OVERRIDE",
        "pattern": re.compile(
            r"\b(ignore|disregard|forget|bypass|dismiss|override)\s+(all\s+|any\s+|the\s+)?(previous|prior|above|existing|initial)\s+(instructions|prompts|rules|directives|constraints|guidelines|commands)\b",
            re.IGNORECASE,
        ),
        "description": "Attempt to override or disregard prior instructions",
    },
    {
        "category": "INSTRUCTION_OVERRIDE",
        "pattern": re.compile(
            r"\b(system\s+override|new\s+instructions\s*:|reset\s+(all\s+)?(parameters|system\s+prompt|directives|rules))\b",
            re.IGNORECASE,
        ),
        "description": "Explicit command to trigger system override or reset",
    },
    {
        "category": "INSTRUCTION_OVERRIDE",
        "pattern": re.compile(
            r"\bstop\s+following\s+(your\s+)?(instructions|rules|safety\s+guidelines)\b",
            re.IGNORECASE,
        ),
        "description": "Directive to stop following safety or baseline instructions",
    },

    # 2. System Prompt Extraction
    {
        "category": "SYSTEM_PROMPT_EXTRACTION",
        "pattern": re.compile(
            r"\b(repeat|print|reveal|output|display|show|tell\s+me|echo)\s+(all\s+|the\s+|your\s+)?(entire\s+)?(initial\s+|original\s+|system\s+|hidden\s+|base\s+)?(system\s+prompt|instructions|directive|prompt\s+above|text\s+above)\b",
            re.IGNORECASE,
        ),
        "description": "Attempt to extract or leak the system prompt",
    },
    {
        "category": "SYSTEM_PROMPT_EXTRACTION",
        "pattern": re.compile(
            r"\bwhat\s+(are|were)\s+(your\s+)?(original\s+|initial\s+|system\s+)?(instructions|rules|system\s+prompt|directives)\b",
            re.IGNORECASE,
        ),
        "description": "Inquiry seeking disclosure of system rules or prompt",
    },
    {
        "category": "SYSTEM_PROMPT_EXTRACTION",
        "pattern": re.compile(
            r"\bshow\s+(me\s+)?everything\s+above\s+(this\s+line|here)\b",
            re.IGNORECASE,
        ),
        "description": "Attempt to read pre-prompt buffer",
    },

    # 3. Roleplay / Jailbreak Bypasses
    {
        "category": "ROLEPLAY_JAILBREAK",
        "pattern": re.compile(
            r"\b(DAN\s+mode|do\s+anything\s+now|jailbreak|developer\s+mode\s+(is\s+)?(enabled|active|on)|god\s*mode)\b",
            re.IGNORECASE,
        ),
        "description": "Known jailbreak persona activation (DAN, developer mode, etc.)",
    },
    {
        "category": "ROLEPLAY_JAILBREAK",
        "pattern": re.compile(
            r"\bpretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(unfiltered|unrestricted|evil|jailbroken|lawless|amoral)\s+(ai|model|assistant|bot)?\b",
            re.IGNORECASE,
        ),
        "description": "Roleplay bypass coercing model into unfiltered persona",
    },
    {
        "category": "ROLEPLAY_JAILBREAK",
        "pattern": re.compile(
            r"\b(bypass|disable|ignore)\s+(all\s+)?(safety|content|ethical)\s+(filters|guardrails|policies|limits)\b",
            re.IGNORECASE,
        ),
        "description": "Direct instruction to bypass safety filters or guardrails",
    },
    {
        "category": "ROLEPLAY_JAILBREAK",
        "pattern": re.compile(
            r"\b(unrestricted\s+mode|acting\s+as\s+an\s+ai\s+without\s+(ethics|morals|rules|limits|safety))\b",
            re.IGNORECASE,
        ),
        "description": "Persona simulation removing constraints",
    },
]
