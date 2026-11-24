from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field

from app.config import settings
from app.security.detector import PolicyMode


class Policy(BaseModel):
    workspace_id: str
    mode: PolicyMode = PolicyMode.REDACT
    block_injections: bool = True
    upstream_base_url: str = Field(default_factory=lambda: settings.DEFAULT_UPSTREAM_BASE_URL)
    encrypted_upstream_api_key: Optional[str] = None
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PolicyUpdateRequest(BaseModel):
    mode: Optional[PolicyMode] = None
    block_injections: Optional[bool] = None
    upstream_base_url: Optional[str] = None
    upstream_api_key: Optional[str] = Field(
        default=None,
        description="NVIDIA Nemotron / OpenAI-compatible upstream API key (encrypted at rest)",
    )


class PolicyResponse(BaseModel):
    workspace_id: str
    mode: PolicyMode
    block_injections: bool
    upstream_base_url: str
    has_upstream_api_key: bool
    upstream_api_key_preview: Optional[str] = None
    updated_at: datetime
