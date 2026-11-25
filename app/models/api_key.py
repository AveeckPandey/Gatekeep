import re
import uuid
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field, field_validator

from app.config import settings
from app.security.detector import calculate_shannon_entropy
from app.security.rules import PATTERNS

_CREDENTIAL_PREFIXES_LOWER = (
    "gw_live_",
    "nvapi-",
    "sk-",
    "pk_live_",
    "pk_test_",
    "rk_live_",
    "rk_test_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "xoxb-",
    "xoxp-",
    "bearer ",
)
_EXACT_CASE_CREDENTIAL_PREFIXES = ("AIza", "AKIA", "ABIA", "ACCA", "ASIA")
_HEX_SECRET_RE = re.compile(r"^[0-9a-fA-F]{24,}$")


def is_credential_like_name(value: str) -> bool:
    """Return True if a gateway key label appears to be an API key or secret credential."""
    trimmed = value.strip()
    if not trimmed:
        return False

    for pattern_name, regex in PATTERNS.items():
        if pattern_name != "EMAIL" and regex.search(trimmed):
            return True

    lower = trimmed.lower()
    if lower.startswith(_CREDENTIAL_PREFIXES_LOWER) or trimmed.startswith(_EXACT_CASE_CREDENTIAL_PREFIXES):
        return True

    for token in trimmed.split():
        if len(token) >= 40:
            return True
        if _HEX_SECRET_RE.match(token):
            return True
        if len(token) >= 24:
            has_digit = any(ch.isdigit() for ch in token)
            has_upper = any(ch.isupper() for ch in token)
            has_lower = any(ch.islower() for ch in token)
            if has_digit or (has_upper and has_lower):
                clean_tok = token.strip(".-_")
                if len(clean_tok) >= 24 and calculate_shannon_entropy(clean_tok) >= settings.ENTROPY_THRESHOLD:
                    return True

    return False


class ApiKey(BaseModel):
    id: str = Field(default_factory=lambda: f"key_{uuid.uuid4().hex[:12]}")
    workspace_id: str
    name: str = "Default Gateway Key"
    key_hash: str
    prefix: str
    is_revoked: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_used_at: Optional[datetime] = None


class ApiKeyCreateRequest(BaseModel):
    name: str = Field(default="Default Gateway Key", max_length=100)

    @field_validator("name")
    @classmethod
    def validate_name_not_credential(cls, v: str) -> str:
        trimmed = v.strip()
        if not trimmed:
            return "Default Gateway Key"
        if is_credential_like_name(trimmed):
            raise ValueError(
                "Key name looks like an API credential. Use a short label here and enter provider credentials under Firewall Policies."
            )
        return trimmed


class ApiKeyCreateResponse(BaseModel):
    id: str
    workspace_id: str
    name: str
    api_key: str  # Plaintext key returned ONLY ONCE!
    prefix: str
    created_at: datetime
    message: str = "Store this API key safely. You will not be able to see it again."


class ApiKeyResponse(BaseModel):
    id: str
    workspace_id: str
    name: str
    prefix: str
    is_revoked: bool
    created_at: datetime
    last_used_at: Optional[datetime] = None
