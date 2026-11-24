import uuid
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


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
