import asyncio
from datetime import datetime, timezone
from typing import Dict, List, Optional

from app.models.user import User
from app.models.workspace import Workspace
from app.models.policy import Policy
from app.models.api_key import ApiKey
from app.models.audit_log import AuditLog
from app.repositories.base import BaseRepository


class InMemoryRepository(BaseRepository):
    """
    Thread-safe in-memory repository implementing the BaseRepository interface.
    Used for Phase 1 local development and isolated automated unit/integration testing.
    """

    def __init__(self):
        self._lock = asyncio.Lock()
        self._users: Dict[str, User] = {}  # user_id -> User
        self._users_by_email: Dict[str, str] = {}  # email -> user_id
        self._workspaces: Dict[str, Workspace] = {}  # workspace_id -> Workspace
        self._policies: Dict[str, Policy] = {}  # workspace_id -> Policy
        self._api_keys: Dict[str, ApiKey] = {}  # key_id -> ApiKey
        self._api_keys_by_hash: Dict[str, str] = {}  # key_hash -> key_id
        self._audit_logs: List[AuditLog] = []

    async def reset(self) -> None:
        """Clears all stored data in the repository (useful for test isolation)."""
        async with self._lock:
            self._users.clear()
            self._users_by_email.clear()
            self._workspaces.clear()
            self._policies.clear()
            self._api_keys.clear()
            self._api_keys_by_hash.clear()
            self._audit_logs.clear()

    # User operations
    async def create_user(self, user: User) -> User:
        async with self._lock:
            if user.email in self._users_by_email:
                raise ValueError("User with this email already exists")
            self._users[user.id] = user
            self._users_by_email[user.email] = user.id
            return user

    async def get_user_by_email(self, email: str) -> Optional[User]:
        async with self._lock:
            user_id = self._users_by_email.get(email)
            if user_id:
                return self._users.get(user_id)
            return None

    async def get_user_by_id(self, user_id: str) -> Optional[User]:
        async with self._lock:
            return self._users.get(user_id)

    # Workspace operations
    async def create_workspace(self, workspace: Workspace) -> Workspace:
        async with self._lock:
            self._workspaces[workspace.id] = workspace
            # Automatically create default policy for workspace
            if workspace.id not in self._policies:
                self._policies[workspace.id] = Policy(workspace_id=workspace.id)
            return workspace

    async def get_workspace(self, workspace_id: str) -> Optional[Workspace]:
        async with self._lock:
            return self._workspaces.get(workspace_id)

    async def list_workspaces_for_user(self, owner_id: str) -> List[Workspace]:
        async with self._lock:
            return [ws for ws in self._workspaces.values() if ws.owner_id == owner_id]

    async def delete_workspace(self, workspace_id: str) -> bool:
        async with self._lock:
            if workspace_id in self._workspaces:
                del self._workspaces[workspace_id]
                self._policies.pop(workspace_id, None)
                # Remove associated API keys
                keys_to_remove = [k_id for k_id, k in self._api_keys.items() if k.workspace_id == workspace_id]
                for k_id in keys_to_remove:
                    k = self._api_keys.pop(k_id)
                    self._api_keys_by_hash.pop(k.key_hash, None)
                return True
            return False

    # Policy operations
    async def get_policy(self, workspace_id: str) -> Optional[Policy]:
        async with self._lock:
            policy = self._policies.get(workspace_id)
            if not policy and workspace_id in self._workspaces:
                policy = Policy(workspace_id=workspace_id)
                self._policies[workspace_id] = policy
            return policy

    async def upsert_policy(self, policy: Policy) -> Policy:
        async with self._lock:
            policy.updated_at = datetime.now(timezone.utc)
            self._policies[policy.workspace_id] = policy
            return policy

    # API Key operations
    async def create_api_key(self, api_key: ApiKey) -> ApiKey:
        async with self._lock:
            self._api_keys[api_key.id] = api_key
            self._api_keys_by_hash[api_key.key_hash] = api_key.id
            return api_key

    async def get_api_key_by_hash(self, key_hash: str) -> Optional[ApiKey]:
        async with self._lock:
            key_id = self._api_keys_by_hash.get(key_hash)
            if key_id:
                return self._api_keys.get(key_id)
            return None

    async def get_api_key_by_id(self, key_id: str, workspace_id: str) -> Optional[ApiKey]:
        async with self._lock:
            key = self._api_keys.get(key_id)
            if key and key.workspace_id == workspace_id:
                return key
            return None

    async def list_api_keys_for_workspace(self, workspace_id: str) -> List[ApiKey]:
        async with self._lock:
            return [k for k in self._api_keys.values() if k.workspace_id == workspace_id]

    async def revoke_api_key(self, key_id: str, workspace_id: str) -> bool:
        async with self._lock:
            key = self._api_keys.get(key_id)
            if key and key.workspace_id == workspace_id:
                key.is_revoked = True
                return True
            return False

    async def update_api_key_last_used(self, key_id: str) -> None:
        async with self._lock:
            key = self._api_keys.get(key_id)
            if key:
                key.last_used_at = datetime.now(timezone.utc)

    # Audit Log operations
    async def create_audit_log(self, log: AuditLog) -> AuditLog:
        async with self._lock:
            self._audit_logs.append(log)
            return log

    async def list_audit_logs_for_workspace(self, workspace_id: str, limit: int = 100) -> List[AuditLog]:
        async with self._lock:
            workspace_logs = [log for log in self._audit_logs if log.workspace_id == workspace_id]
            # Sort newest first
            workspace_logs.sort(key=lambda x: x.created_at, reverse=True)
            return workspace_logs[:limit]


# Global repository singleton instance for Phase 1
repo = InMemoryRepository()


def get_repository() -> BaseRepository:
    """Dependency provider for repository."""
    return repo
