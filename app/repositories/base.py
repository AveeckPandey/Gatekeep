from abc import ABC, abstractmethod
from typing import List, Optional

from app.models.api_key import ApiKey
from app.models.audit_log import AuditLog
from app.models.policy import Policy
from app.models.user import User
from app.models.workspace import Workspace


class BaseRepository(ABC):
    """Abstract interface for all GateKeep data storage operations."""

    # User operations
    @abstractmethod
    async def create_user(self, user: User) -> User:
        pass

    @abstractmethod
    async def get_user_by_email(self, email: str) -> Optional[User]:
        pass

    @abstractmethod
    async def get_user_by_id(self, user_id: str) -> Optional[User]:
        pass

    # Workspace operations
    @abstractmethod
    async def create_workspace(self, workspace: Workspace) -> Workspace:
        pass

    @abstractmethod
    async def get_workspace(self, workspace_id: str) -> Optional[Workspace]:
        pass

    @abstractmethod
    async def list_workspaces_for_user(self, owner_id: str) -> List[Workspace]:
        pass

    @abstractmethod
    async def delete_workspace(self, workspace_id: str) -> bool:
        pass

    # Policy operations
    @abstractmethod
    async def get_policy(self, workspace_id: str) -> Optional[Policy]:
        pass

    @abstractmethod
    async def upsert_policy(self, policy: Policy) -> Policy:
        pass

    # API Key operations
    @abstractmethod
    async def create_api_key(self, api_key: ApiKey) -> ApiKey:
        pass

    @abstractmethod
    async def get_api_key_by_hash(self, key_hash: str) -> Optional[ApiKey]:
        pass

    @abstractmethod
    async def get_api_key_by_id(self, key_id: str, workspace_id: str) -> Optional[ApiKey]:
        pass

    @abstractmethod
    async def list_api_keys_for_workspace(self, workspace_id: str) -> List[ApiKey]:
        pass

    @abstractmethod
    async def revoke_api_key(self, key_id: str, workspace_id: str) -> bool:
        pass

    @abstractmethod
    async def update_api_key_last_used(
        self,
        key_id: str,
        workspace_id: Optional[str] = None,
        key_hash: Optional[str] = None,
    ) -> None:
        pass

    # Audit Log operations
    @abstractmethod
    async def create_audit_log(self, log: AuditLog) -> AuditLog:
        pass

    @abstractmethod
    async def list_audit_logs_for_workspace(self, workspace_id: str, limit: int = 100) -> List[AuditLog]:
        pass
