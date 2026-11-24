from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
import uuid


class AuditLog(BaseModel):
    id: str = Field(default_factory=lambda: f"log_{uuid.uuid4().hex[:12]}")
    workspace_id: str
    key_id: Optional[str] = None
    model: str
    action: str  # "ALLOW", "REDACT", "BLOCK"
    is_blocked: bool = False
    block_reason: Optional[str] = None
    findings_count: int = 0
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    inspection_ms: float = 0.0
    upstream_ms: Optional[float] = None
    total_ms: float = 0.0
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AuditLogResponse(BaseModel):
    id: str
    workspace_id: str
    key_id: Optional[str]
    model: str
    action: str
    is_blocked: bool
    block_reason: Optional[str]
    findings_count: int
    findings: List[Dict[str, Any]]
    inspection_ms: float
    upstream_ms: Optional[float]
    total_ms: float
    prompt_tokens: Optional[int]
    completion_tokens: Optional[int]
    created_at: datetime
