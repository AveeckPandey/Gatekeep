import json
import time
from typing import Any, Dict, List, Optional, Tuple
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
import httpx

from app.core.dependencies import get_gateway_auth
from app.core.security import decrypt_secret
from app.models.api_key import ApiKey
from app.models.audit_log import AuditLog
from app.models.policy import Policy
from app.models.proxy import (
    AegisGateMeta,
    ChatCompletionRequest,
    ChatMessage,
)
from app.models.workspace import Workspace
from app.repositories.base import BaseRepository
from app.repositories.in_memory import get_repository
from app.security.detector import (
    Finding,
    InspectionResult,
    PolicyMode,
    detector,
)

router = APIRouter(tags=["Data Plane Proxy"])


@router.post("/v1/chat/completions")
async def chat_completions_proxy(
    request: Request,
    payload: ChatCompletionRequest,
    auth_context: Tuple[ApiKey, Workspace, Policy] = Depends(get_gateway_auth),
    repo: BaseRepository = Depends(get_repository),
):
    """
    OpenAI-Compatible Data Plane Gateway Proxy:
    1. Authenticates request via Gateway API Key (`gw_live_...`).
    2. Inspects user messages for PII, secrets, and prompt injection attacks.
    3. Enforces workspace policy: ALLOW, REDACT, or BLOCK (HTTP 403).
    4. Forwards sanitized payload to upstream LLM (e.g. NVIDIA Nemotron).
    5. Returns response with `aegisgate_meta` telemetry and records audit log.
    """
    start_total = time.perf_counter()
    api_key, workspace, policy = auth_context

    # 1. Security Inspection of Messages
    all_findings: List[Finding] = []
    has_blocked = False
    block_reasons: List[str] = []
    inspection_duration_ms = 0.0
    sanitized_messages: List[Dict[str, Any]] = []
    overall_action = "ALLOW"

    for msg in payload.messages:
        content = msg.content
        if isinstance(content, str):
            res: InspectionResult = detector.inspect(
                text=content,
                policy_mode=policy.mode,
                block_injections=policy.block_injections,
            )
            inspection_duration_ms += res.inspection_ms
            all_findings.extend(res.findings)

            if res.is_blocked:
                has_blocked = True
                if res.block_reason:
                    block_reasons.append(res.block_reason)

            if res.action == "BLOCK":
                overall_action = "BLOCK"
            elif res.action == "REDACT" and overall_action != "BLOCK":
                overall_action = "REDACT"

            sanitized_messages.append({"role": msg.role, "content": res.sanitized_text})
        else:
            # Handle structured content array if present
            sanitized_messages.append(msg.model_dump())

    inspection_duration_ms = round(inspection_duration_ms, 3)

    # 2. Enforcement: If Blocked, return HTTP 403 immediately and record audit log
    if has_blocked or overall_action == "BLOCK":
        total_duration_ms = round((time.perf_counter() - start_total) * 1000, 3)
        block_reason_str = "; ".join(block_reasons) if block_reasons else "Security policy blocked request"

        # Log blocked attempt
        await repo.create_audit_log(
            AuditLog(
                workspace_id=workspace.id,
                key_id=api_key.id,
                model=payload.model,
                action="BLOCK",
                is_blocked=True,
                block_reason=block_reason_str,
                findings_count=len(all_findings),
                findings=[f.model_dump() for f in all_findings],
                inspection_ms=inspection_duration_ms,
                upstream_ms=None,
                total_ms=total_duration_ms,
            )
        )

        error_meta = AegisGateMeta(
            action="BLOCK",
            is_blocked=True,
            block_reason=block_reason_str,
            findings_count=len(all_findings),
            findings=[f.model_dump() for f in all_findings],
            inspection_ms=inspection_duration_ms,
            upstream_ms=None,
            total_ms=total_duration_ms,
            policy_mode=policy.mode.value,
        )

        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "error": {
                    "message": f"GateKeep Security Firewall blocked request: {block_reason_str}",
                    "type": "security_policy_violation",
                    "code": 403,
                    "aegisgate_meta": error_meta.model_dump(),
                }
            },
        )

    # 3. Decrypt Upstream BYOK Key
    upstream_key = None
    if policy.encrypted_upstream_api_key:
        try:
            upstream_key = decrypt_secret(policy.encrypted_upstream_api_key)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to decrypt workspace upstream API key",
            )

    if not upstream_key:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="No upstream API key configured for this workspace. Please configure your NVIDIA Nemotron / LLM API key in workspace policy.",
        )

    # 4. Prepare Forwarding Payload
    forward_dict = payload.model_dump(exclude_unset=True)
    forward_dict["messages"] = sanitized_messages

    base_url = policy.upstream_base_url.rstrip("/")
    target_url = f"{base_url}/chat/completions"

    upstream_headers = {
        "Authorization": f"Bearer {upstream_key}",
        "Content-Type": "application/json",
    }

    # 5. Forward to Upstream LLM via httpx
    upstream_start = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            upstream_resp = await client.post(
                target_url,
                headers=upstream_headers,
                json=forward_dict,
            )
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to connect to upstream LLM service: {str(exc)}",
        )

    upstream_duration_ms = round((time.perf_counter() - upstream_start) * 1000, 3)
    total_duration_ms = round((time.perf_counter() - start_total) * 1000, 3)

    if upstream_resp.status_code >= 400:
        # Pass upstream error through
        try:
            err_json = upstream_resp.json()
            return JSONResponse(status_code=upstream_resp.status_code, content=err_json)
        except Exception:
            return Response(
                content=upstream_resp.content,
                status_code=upstream_resp.status_code,
                media_type=upstream_resp.headers.get("content-type", "application/json"),
            )

    upstream_data = upstream_resp.json()

    # 6. Extract token usage and build aegisgate_meta
    usage_info = upstream_data.get("usage", {})
    prompt_tokens = usage_info.get("prompt_tokens")
    completion_tokens = usage_info.get("completion_tokens")

    meta = AegisGateMeta(
        action=overall_action,
        is_blocked=False,
        block_reason=None,
        findings_count=len(all_findings),
        findings=[f.model_dump() for f in all_findings],
        inspection_ms=inspection_duration_ms,
        upstream_ms=upstream_duration_ms,
        total_ms=total_duration_ms,
        policy_mode=policy.mode.value,
    )
    upstream_data["aegisgate_meta"] = meta.model_dump()

    # 7. Record Audit Log
    await repo.create_audit_log(
        AuditLog(
            workspace_id=workspace.id,
            key_id=api_key.id,
            model=payload.model,
            action=overall_action,
            is_blocked=False,
            block_reason=None,
            findings_count=len(all_findings),
            findings=[f.model_dump() for f in all_findings],
            inspection_ms=inspection_duration_ms,
            upstream_ms=upstream_duration_ms,
            total_ms=total_duration_ms,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )
    )

    return JSONResponse(status_code=status.HTTP_200_OK, content=upstream_data)
