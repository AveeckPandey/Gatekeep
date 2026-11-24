from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status

from app.core.dependencies import get_current_user, get_workspace_for_user
from app.core.security import (
    decrypt_secret,
    encrypt_secret,
    generate_gateway_api_key,
)
from app.models.api_key import (
    ApiKey,
    ApiKeyCreateRequest,
    ApiKeyCreateResponse,
    ApiKeyResponse,
)
from app.models.audit_log import AuditLogResponse
from app.models.policy import Policy, PolicyResponse, PolicyUpdateRequest
from app.models.user import User
from app.models.workspace import (
    Workspace,
    WorkspaceCreateRequest,
    WorkspaceResponse,
)
from app.repositories.base import BaseRepository
from app.repositories.in_memory import get_repository

router = APIRouter(prefix="/api/workspaces", tags=["Control Plane Workspaces"])


def _build_policy_response(policy: Policy) -> PolicyResponse:
    """Helper to convert stored Policy into safe PolicyResponse without exposing secret."""
    has_key = bool(policy.encrypted_upstream_api_key)
    preview = None
    if has_key:
        try:
            decrypted = decrypt_secret(policy.encrypted_upstream_api_key)
            if len(decrypted) > 8:
                preview = f"{decrypted[:4]}...{decrypted[-4:]}"
            else:
                preview = "****"
        except Exception:
            preview = "[ENCRYPTED_KEY]"

    return PolicyResponse(
        workspace_id=policy.workspace_id,
        mode=policy.mode,
        block_injections=policy.block_injections,
        upstream_base_url=policy.upstream_base_url,
        has_upstream_api_key=has_key,
        upstream_api_key_preview=preview,
        updated_at=policy.updated_at,
    )


# 1. Workspace CRUD
@router.post("", response_model=WorkspaceResponse, status_code=status.HTTP_201_CREATED)
async def create_workspace(
    payload: WorkspaceCreateRequest,
    current_user: User = Depends(get_current_user),
    repo: BaseRepository = Depends(get_repository),
):
    """
    Create a new workspace owned by the authenticated tenant user.
    """
    workspace = Workspace(name=payload.name, owner_id=current_user.id)
    created_ws = await repo.create_workspace(workspace)
    return WorkspaceResponse(
        id=created_ws.id,
        name=created_ws.name,
        owner_id=created_ws.owner_id,
        created_at=created_ws.created_at,
        updated_at=created_ws.updated_at,
    )


@router.get("", response_model=List[WorkspaceResponse])
async def list_workspaces(
    current_user: User = Depends(get_current_user),
    repo: BaseRepository = Depends(get_repository),
):
    """
    List all workspaces strictly owned by the authenticated tenant user.
    """
    workspaces = await repo.list_workspaces_for_user(current_user.id)
    return [
        WorkspaceResponse(
            id=ws.id,
            name=ws.name,
            owner_id=ws.owner_id,
            created_at=ws.created_at,
            updated_at=ws.updated_at,
        )
        for ws in workspaces
    ]


@router.get("/{ws_id}", response_model=WorkspaceResponse)
async def get_workspace(
    workspace: Workspace = Depends(get_workspace_for_user),
):
    """
    Get workspace details (protected against BOLA/IDOR).
    """
    return WorkspaceResponse(
        id=workspace.id,
        name=workspace.name,
        owner_id=workspace.owner_id,
        created_at=workspace.created_at,
        updated_at=workspace.updated_at,
    )


# 2. Workspace Policy Management
@router.get("/{ws_id}/policy", response_model=PolicyResponse)
async def get_workspace_policy(
    workspace: Workspace = Depends(get_workspace_for_user),
    repo: BaseRepository = Depends(get_repository),
):
    """
    Retrieve security policy for the workspace.
    """
    policy = await repo.get_policy(workspace.id)
    if not policy:
        policy = Policy(workspace_id=workspace.id)
        await repo.upsert_policy(policy)

    return _build_policy_response(policy)


@router.put("/{ws_id}/policy", response_model=PolicyResponse)
async def update_workspace_policy(
    payload: PolicyUpdateRequest,
    workspace: Workspace = Depends(get_workspace_for_user),
    repo: BaseRepository = Depends(get_repository),
):
    """
    Update security policy, mode (ALLOW, REDACT, BLOCK), injection blocking,
    upstream LLM endpoint, and encrypted BYOK API key.
    """
    policy = await repo.get_policy(workspace.id)
    if not policy:
        policy = Policy(workspace_id=workspace.id)

    if payload.mode is not None:
        policy.mode = payload.mode

    if payload.block_injections is not None:
        policy.block_injections = payload.block_injections

    if payload.upstream_base_url is not None:
        policy.upstream_base_url = payload.upstream_base_url

    if payload.upstream_api_key is not None:
        # Encrypt BYOK API key at rest using Fernet
        policy.encrypted_upstream_api_key = encrypt_secret(payload.upstream_api_key)

    updated_policy = await repo.upsert_policy(policy)
    return _build_policy_response(updated_policy)


# 3. Workspace API Keys Management
@router.post("/{ws_id}/keys", response_model=ApiKeyCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    payload: ApiKeyCreateRequest,
    workspace: Workspace = Depends(get_workspace_for_user),
    repo: BaseRepository = Depends(get_repository),
):
    """
    Generate a new Gateway API Key (`gw_live_...`).
    The plaintext key is returned ONCE. Only its SHA-256 hash is persisted.
    """
    plaintext_key, key_hash, prefix = generate_gateway_api_key()

    api_key_record = ApiKey(
        workspace_id=workspace.id,
        name=payload.name,
        key_hash=key_hash,
        prefix=prefix,
    )
    created_key = await repo.create_api_key(api_key_record)

    return ApiKeyCreateResponse(
        id=created_key.id,
        workspace_id=created_key.workspace_id,
        name=created_key.name,
        api_key=plaintext_key,  # Returned only once
        prefix=created_key.prefix,
        created_at=created_key.created_at,
    )


@router.get("/{ws_id}/keys", response_model=List[ApiKeyResponse])
async def list_api_keys(
    workspace: Workspace = Depends(get_workspace_for_user),
    repo: BaseRepository = Depends(get_repository),
):
    """
    List all Gateway API keys for the workspace (hashes/plaintext are omitted).
    """
    keys = await repo.list_api_keys_for_workspace(workspace.id)
    return [
        ApiKeyResponse(
            id=k.id,
            workspace_id=k.workspace_id,
            name=k.name,
            prefix=k.prefix,
            is_revoked=k.is_revoked,
            created_at=k.created_at,
            last_used_at=k.last_used_at,
        )
        for k in keys
    ]


@router.delete("/{ws_id}/keys/{key_id}", status_code=status.HTTP_200_OK)
async def revoke_api_key(
    key_id: str,
    workspace: Workspace = Depends(get_workspace_for_user),
    repo: BaseRepository = Depends(get_repository),
):
    """
    Instantly revoke a Gateway API Key. Revoked keys cannot be used for proxy requests.
    """
    key = await repo.get_api_key_by_id(key_id, workspace.id)
    if not key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"API Key '{key_id}' not found in workspace '{workspace.id}'",
        )

    await repo.revoke_api_key(key_id, workspace.id)
    return {"message": f"API Key '{key_id}' successfully revoked", "revoked": True}


# 4. Workspace Audit Logs
@router.get("/{ws_id}/logs", response_model=List[AuditLogResponse])
async def get_workspace_audit_logs(
    limit: int = 100,
    workspace: Workspace = Depends(get_workspace_for_user),
    repo: BaseRepository = Depends(get_repository),
):
    """
    Retrieve security inspection and proxy audit logs scoped strictly to this workspace.
    """
    logs = await repo.list_audit_logs_for_workspace(workspace.id, limit=limit)
    return [
        AuditLogResponse(
            id=log.id,
            workspace_id=log.workspace_id,
            key_id=log.key_id,
            model=log.model,
            action=log.action,
            is_blocked=log.is_blocked,
            block_reason=log.block_reason,
            findings_count=log.findings_count,
            findings=log.findings,
            inspection_ms=log.inspection_ms,
            upstream_ms=log.upstream_ms,
            total_ms=log.total_ms,
            prompt_tokens=log.prompt_tokens,
            completion_tokens=log.completion_tokens,
            created_at=log.created_at,
        )
        for log in logs
    ]
