from typing import Optional, Tuple
from fastapi import Depends, HTTPException, Header, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.security import decode_access_token, hash_api_key
from app.models.api_key import ApiKey
from app.models.policy import Policy
from app.models.user import User
from app.models.workspace import Workspace
from app.repositories.base import BaseRepository
from app.repositories.in_memory import get_repository

bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    repo: BaseRepository = Depends(get_repository),
) -> User:
    """
    Authenticates a control-plane user via JWT in Authorization: Bearer <token>.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload["sub"]
    user = await repo.get_user_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User no longer exists",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


async def get_workspace_for_user(
    ws_id: str,
    current_user: User = Depends(get_current_user),
    repo: BaseRepository = Depends(get_repository),
) -> Workspace:
    """
    BOLA / IDOR Protection: Verifies that the requested workspace exists
    AND strictly belongs to the currently authenticated user.
    """
    workspace = await repo.get_workspace(ws_id)
    if not workspace:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workspace '{ws_id}' not found",
        )

    if workspace.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: you do not have permission to access this workspace",
        )

    return workspace


async def get_gateway_auth(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    repo: BaseRepository = Depends(get_repository),
) -> Tuple[ApiKey, Workspace, Policy]:
    """
    Data Plane Authentication:
    Authenticates proxy requests via workspace-scoped Gateway API key (gw_live_...).
    Verifies key hash against the repository and loads active workspace policy.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Gateway API key in Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    raw_key = credentials.credentials.strip()
    if not raw_key.startswith("gw_live_"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Gateway API key format. Expected 'gw_live_...'",
            headers={"WWW-Authenticate": "Bearer"},
        )

    key_hash = hash_api_key(raw_key)
    api_key = await repo.get_api_key_by_hash(key_hash)

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or unrecognized Gateway API key",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if api_key.is_revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Gateway API key has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Fetch workspace and policy
    workspace = await repo.get_workspace(api_key.workspace_id)
    if not workspace:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Associated workspace not found",
        )

    policy = await repo.get_policy(workspace.id)
    if not policy:
        policy = Policy(workspace_id=workspace.id)

    # Track usage asynchronously
    await repo.update_api_key_last_used(api_key.id)

    return api_key, workspace, policy
