from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field
import uuid


class Workspace(BaseModel):
    id: str = Field(default_factory=lambda: f"ws_{uuid.uuid4().hex[:12]}")
    name: str = Field(min_length=1, max_length=100)
    owner_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class WorkspaceCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)


class WorkspaceResponse(BaseModel):
    id: str
    name: str
    owner_id: str
    created_at: datetime
    updated_at: datetime
