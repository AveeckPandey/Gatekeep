from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field, field_validator

from app.config import settings
from app.security.detector import PolicyMode
from app.security.ssrf import validate_upstream_url


class Policy(BaseModel):
    workspace_id: str
    mode: PolicyMode = PolicyMode.REDACT
    block_injections: bool = True
    inspect_responses: bool = True  # Response DLP: inspect LLM output for leaked secrets/PII
    rate_limit_rpm: int = 60  # Rate limiting: max requests per minute per workspace
    upstream_base_url: str = Field(default_factory=lambda: settings.DEFAULT_UPSTREAM_BASE_URL)
    encrypted_upstream_api_key: Optional[str] = None
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("upstream_base_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        return validate_upstream_url(v)


class PolicyUpdateRequest(BaseModel):
    mode: Optional[PolicyMode] = None
    block_injections: Optional[bool] = None
    inspect_responses: Optional[bool] = None
    rate_limit_rpm: Optional[int] = Field(default=None, ge=1, le=1000)
    upstream_base_url: Optional[str] = None
    upstream_api_key: Optional[str] = Field(
        default=None,
        description="NVIDIA Nemotron / OpenAI-compatible upstream API key (encrypted at rest)",
    )

    @field_validator("upstream_base_url")
    @classmethod
    def validate_url(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            return validate_upstream_url(v)
        return v


class PolicyResponse(BaseModel):
    workspace_id: str
    mode: PolicyMode
    block_injections: bool
    inspect_responses: bool
    rate_limit_rpm: int
    upstream_base_url: str
    has_upstream_api_key: bool
    upstream_api_key_preview: Optional[str] = None
    updated_at: datetime
