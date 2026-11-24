import asyncio
import json
import time
from typing import Any, Dict, List, Tuple, Union

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, StreamingResponse

from app.core.dependencies import get_gateway_auth
from app.core.providers import resolve_provider
from app.core.security import decrypt_secret
from app.models.api_key import ApiKey
from app.models.audit_log import AuditLog
from app.models.policy import Policy
from app.models.proxy import (
    AegisGateMeta,
    ChatCompletionRequest,
)
from app.models.workspace import Workspace
from app.repositories.base import BaseRepository
from app.repositories.in_memory import get_repository
from app.security.detector import (
    Finding,
    PolicyMode,
    detector,
)
from app.security.rate_limiter import workspace_rate_limiter
from app.security.ssrf import validate_upstream_url

router = APIRouter(tags=["Data Plane Proxy"])


def inspect_and_sanitize_content(
    content: Union[str, List[Any], Any],
    policy_mode: PolicyMode,
    block_injections: bool,
) -> Tuple[Union[str, List[Any], Any], List[Finding], bool, List[str], str, float]:
    """
    Recursively inspects and sanitizes message content:
    - If None: returns (None, [], False, [], "ALLOW", 0.0).
    - If string: runs detector.inspect(text).
    - If list: recursively inspects each item (dict with type=text, nested lists, or raw strings).
    - If unsupported/unexpected object: leaves as-is if primitive, or serializes/inspects text representations.
    Returns: (sanitized_content, findings, is_blocked, block_reasons, action, inspection_ms)
    """
    if content is None:
        return (None, [], False, [], "ALLOW", 0.0)

    if isinstance(content, str):
        res = detector.inspect(
            text=content,
            policy_mode=policy_mode,
            block_injections=block_injections,
        )
        return (
            res.sanitized_text,
            res.findings,
            res.is_blocked,
            [res.block_reason] if res.block_reason else [],
            res.action,
            res.inspection_ms,
        )

    if isinstance(content, list):
        sanitized_list = []
        findings: List[Finding] = []
        is_blocked = False
        block_reasons: List[str] = []
        action = "ALLOW"
        total_ms = 0.0

        for item in content:
            if isinstance(item, dict):
                item_copy = dict(item)
                item_type = item_copy.get("type")
                if item_type == "text" and "text" in item_copy and isinstance(item_copy["text"], str):
                    res = detector.inspect(
                        text=item_copy["text"],
                        policy_mode=policy_mode,
                        block_injections=block_injections,
                    )
                    total_ms += res.inspection_ms
                    findings.extend(res.findings)
                    if res.is_blocked:
                        is_blocked = True
                        if res.block_reason:
                            block_reasons.append(res.block_reason)
                    if res.action == "BLOCK":
                        action = "BLOCK"
                    elif res.action == "REDACT" and action != "BLOCK":
                        action = "REDACT"
                    item_copy["text"] = res.sanitized_text
                sanitized_list.append(item_copy)
            elif isinstance(item, str):
                res = detector.inspect(
                    text=item,
                    policy_mode=policy_mode,
                    block_injections=block_injections,
                )
                total_ms += res.inspection_ms
                findings.extend(res.findings)
                if res.is_blocked:
                    is_blocked = True
                    if res.block_reason:
                        block_reasons.append(res.block_reason)
                if res.action == "BLOCK":
                    action = "BLOCK"
                elif res.action == "REDACT" and action != "BLOCK":
                    action = "REDACT"
                sanitized_list.append(res.sanitized_text)
            else:
                sanitized_list.append(item)

        return (sanitized_list, findings, is_blocked, block_reasons, action, total_ms)

    return (content, [], False, [], "ALLOW", 0.0)


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

    # 0. Enforce Per-Workspace Rate Limiting
    allowed, retry_after = workspace_rate_limiter.check_and_record(
        workspace_id=workspace.id,
        limit_rpm=policy.rate_limit_rpm,
    )
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded: {policy.rate_limit_rpm} requests per minute limit reached for workspace.",
            headers={"Retry-After": str(retry_after)},
        )

    # 1. Security Inspection of Messages
    all_findings: List[Finding] = []
    has_blocked = False
    block_reasons: List[str] = []
    inspection_duration_ms = 0.0
    sanitized_messages: List[Dict[str, Any]] = []
    overall_action = "ALLOW"

    for msg in payload.messages:
        sanitized_content, findings, is_blocked, reasons, action, dur_ms = inspect_and_sanitize_content(
            content=msg.content,
            policy_mode=policy.mode,
            block_injections=policy.block_injections,
        )
        inspection_duration_ms += dur_ms
        all_findings.extend(findings)
        if is_blocked:
            has_blocked = True
            block_reasons.extend(reasons)
        if action == "BLOCK":
            overall_action = "BLOCK"
        elif action == "REDACT" and overall_action != "BLOCK":
            overall_action = "REDACT"

        msg_dict: Dict[str, Any] = {"role": msg.role, "content": sanitized_content}
        if msg.name:
            if isinstance(msg.name, str):
                name_sanitized, name_findings, name_blocked, name_reasons, name_action, name_ms = inspect_and_sanitize_content(
                    content=msg.name,
                    policy_mode=policy.mode,
                    block_injections=policy.block_injections,
                )
                inspection_duration_ms += name_ms
                all_findings.extend(name_findings)
                if name_blocked:
                    has_blocked = True
                    block_reasons.extend(name_reasons)
                if name_action == "BLOCK":
                    overall_action = "BLOCK"
                elif name_action == "REDACT" and overall_action != "BLOCK":
                    overall_action = "REDACT"
                msg_dict["name"] = name_sanitized
            else:
                msg_dict["name"] = msg.name

        if msg.tool_call_id:
            msg_dict["tool_call_id"] = msg.tool_call_id

        if msg.tool_calls:
            sanitized_tc_list = []
            for tc in msg.tool_calls:
                tc_copy = dict(tc)
                if "function" in tc_copy and isinstance(tc_copy["function"], dict):
                    fn_copy = dict(tc_copy["function"])
                    args = fn_copy.get("arguments")
                    if isinstance(args, str):
                        s_args, tc_f, tc_b, tc_r, tc_a, tc_m = inspect_and_sanitize_content(
                            content=args,
                            policy_mode=policy.mode,
                            block_injections=policy.block_injections,
                        )
                        inspection_duration_ms += tc_m
                        all_findings.extend(tc_f)
                        if tc_b:
                            has_blocked = True
                            block_reasons.extend(tc_r)
                        if tc_a == "BLOCK":
                            overall_action = "BLOCK"
                        elif tc_a == "REDACT" and overall_action != "BLOCK":
                            overall_action = "REDACT"
                        fn_copy["arguments"] = s_args
                    tc_copy["function"] = fn_copy
                sanitized_tc_list.append(tc_copy)
            msg_dict["tool_calls"] = sanitized_tc_list

        if msg.function_call:
            fc_copy = dict(msg.function_call)
            args = fc_copy.get("arguments")
            if isinstance(args, str):
                s_args, fc_f, fc_b, fc_r, fc_a, fc_m = inspect_and_sanitize_content(
                    content=args,
                    policy_mode=policy.mode,
                    block_injections=policy.block_injections,
                )
                inspection_duration_ms += fc_m
                all_findings.extend(fc_f)
                if fc_b:
                    has_blocked = True
                    block_reasons.extend(fc_r)
                if fc_a == "BLOCK":
                    overall_action = "BLOCK"
                elif fc_a == "REDACT" and overall_action != "BLOCK":
                    overall_action = "REDACT"
                fc_copy["arguments"] = s_args
            msg_dict["function_call"] = fc_copy

        sanitized_messages.append(msg_dict)

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

    # 3. Upstream Dispatch (or Demo Workspace Mock)
    is_demo_workspace = (workspace.id.startswith("ws_demo") or policy.upstream_base_url.startswith("https://demo.gatekeep.local")) and not payload.provider
    upstream_key = None
    upstream_base_url = policy.upstream_base_url

    if payload.provider:
        try:
            upstream_base_url, upstream_key = resolve_provider(payload.provider, workspace.id)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    if not (is_demo_workspace and not policy.encrypted_upstream_api_key):
        if not upstream_key and policy.encrypted_upstream_api_key:
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
                detail="No upstream API key configured for this workspace or selected provider.",
            )

        # Validate target upstream URL to prevent SSRF before dispatch
        try:
            validate_upstream_url(upstream_base_url)
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid upstream URL configured in workspace policy: {e}",
            )

    # 4. Handle Server-Sent Events (SSE) Streaming if stream=True
    if payload.stream:
        if is_demo_workspace and not policy.encrypted_upstream_api_key:
            async def demo_sse_generator():
                words = [
                    "GateKeep ",
                    "Gateway ",
                    "Streaming: ",
                    f"Processed {len(payload.messages)} message(s). ",
                    f"Firewall policy: {policy.mode.value}.",
                ]
                chunk_id = f"chatcmpl-demo-{int(time.time())}"
                created_ts = int(time.time())
                for word in words:
                    chunk_obj = {
                        "id": chunk_id,
                        "object": "chat.completion.chunk",
                        "created": created_ts,
                        "model": payload.model or "demo-nemotron-70b",
                        "choices": [
                            {
                                "index": 0,
                                "delta": {"content": word},
                                "finish_reason": None,
                            }
                        ],
                    }
                    yield f"data: {json.dumps(chunk_obj)}\n\n"
                    await asyncio.sleep(0.01)

                done_chunk = {
                    "id": chunk_id,
                    "object": "chat.completion.chunk",
                    "created": created_ts,
                    "model": payload.model or "demo-nemotron-70b",
                    "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                }
                yield f"data: {json.dumps(done_chunk)}\n\n"
                yield "data: [DONE]\n\n"

                total_duration_ms = round((time.perf_counter() - start_total) * 1000, 3)
                await repo.create_audit_log(
                    AuditLog(
                        workspace_id=workspace.id,
                        key_id=api_key.id,
                        model=payload.model,
                        action=overall_action,
                        is_blocked=False,
                        findings_count=len(all_findings),
                        findings=[f.model_dump() for f in all_findings],
                        inspection_ms=inspection_duration_ms,
                        upstream_ms=8.5,
                        total_ms=total_duration_ms,
                    )
                )

            return StreamingResponse(demo_sse_generator(), media_type="text/event-stream")

        # Live upstream SSE forward
        forward_dict = payload.model_dump(exclude_unset=True, exclude={"provider"})
        forward_dict["messages"] = sanitized_messages
        base_url = upstream_base_url.rstrip("/")
        target_url = f"{base_url}/chat/completions"
        upstream_headers = {
            "Authorization": f"Bearer {upstream_key}",
            "Content-Type": "application/json",
        }

        async def upstream_sse_generator():
            nonlocal overall_action
            upstream_start = time.perf_counter()
            response_findings_stream: List[Finding] = []
            stream_error = None
            dlp_policy_mode = (
                PolicyMode.ALLOW if policy.mode == PolicyMode.ALLOW else PolicyMode.REDACT
            )

            try:
                async with httpx.AsyncClient(timeout=60.0, follow_redirects=False) as client:
                    async with client.stream(
                        "POST",
                        target_url,
                        headers=upstream_headers,
                        json=forward_dict,
                    ) as upstream_resp:
                        if upstream_resp.status_code >= 400:
                            err_body = await upstream_resp.aread()
                            total_duration_ms = round((time.perf_counter() - start_total) * 1000, 3)
                            upstream_duration_ms = round((time.perf_counter() - upstream_start) * 1000, 3)
                            await repo.create_audit_log(
                                AuditLog(
                                    workspace_id=workspace.id,
                                    key_id=api_key.id,
                                    model=payload.model,
                                    action="ERROR",
                                    is_blocked=False,
                                    block_reason=f"Upstream returned HTTP {upstream_resp.status_code}",
                                    findings_count=len(all_findings),
                                    findings=[f.model_dump() for f in all_findings],
                                    inspection_ms=inspection_duration_ms,
                                    upstream_ms=upstream_duration_ms,
                                    total_ms=total_duration_ms,
                                )
                            )
                            yield f"data: {err_body.decode(errors='replace')}\n\n"
                            yield "data: [DONE]\n\n"
                            return

                        async for line in upstream_resp.aiter_lines():
                            if not line:
                                continue
                            if line.startswith("data: "):
                                data_str = line[6:].strip()
                                if data_str == "[DONE]":
                                    yield "data: [DONE]\n\n"
                                    break
                                try:
                                    chunk_json = json.loads(data_str)
                                    if policy.inspect_responses:
                                        for ch in chunk_json.get("choices", []):
                                            delta = ch.get("delta", {})
                                            delta_content = delta.get("content")
                                            if isinstance(delta_content, str):
                                                dlp_res = detector.inspect(
                                                    text=delta_content,
                                                    policy_mode=dlp_policy_mode,
                                                    block_injections=False,
                                                )
                                                if dlp_res.findings:
                                                    delta["content"] = dlp_res.sanitized_text
                                                    response_findings_stream.extend(dlp_res.findings)
                                                    if overall_action != "BLOCK" and policy.mode != PolicyMode.ALLOW:
                                                        overall_action = "REDACT"
                                    yield f"data: {json.dumps(chunk_json)}\n\n"
                                except json.JSONDecodeError:
                                    yield f"{line}\n\n"
                            else:
                                yield f"{line}\n\n"

            except Exception as exc:
                stream_error = str(exc)
                yield f'data: {{"error": {{"message": "Stream interrupted: {stream_error}"}}}}\n\n'
                yield "data: [DONE]\n\n"
            finally:
                upstream_duration_ms = round((time.perf_counter() - upstream_start) * 1000, 3)
                total_duration_ms = round((time.perf_counter() - start_total) * 1000, 3)
                all_combined_findings = [f.model_dump() for f in all_findings]
                for rf in response_findings_stream:
                    rf_dict = rf.model_dump()
                    rf_dict["source"] = "response_dlp"
                    all_combined_findings.append(rf_dict)

                await repo.create_audit_log(
                    AuditLog(
                        workspace_id=workspace.id,
                        key_id=api_key.id,
                        model=payload.model,
                        action="ERROR" if stream_error else overall_action,
                        is_blocked=False,
                        block_reason=stream_error,
                        findings_count=len(all_combined_findings),
                        findings=all_combined_findings,
                        inspection_ms=inspection_duration_ms,
                        upstream_ms=upstream_duration_ms,
                        total_ms=total_duration_ms,
                    )
                )

        return StreamingResponse(upstream_sse_generator(), media_type="text/event-stream")

    # 5. Non-Streaming Dispatch
    if is_demo_workspace and not policy.encrypted_upstream_api_key:
        # Synthesize simulated completion for instant 10-second demo/recruiter playground
        upstream_duration_ms = 8.5
        upstream_data = {
            "id": f"chatcmpl-demo-{int(time.time())}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": payload.model or "demo-nemotron-70b",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": f"GateKeep Gateway Demo Response: Processed {len(payload.messages)} message(s) successfully. Active firewall policy: {policy.mode.value}.",
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": 12,
                "completion_tokens": 20,
                "total_tokens": 32,
            },
        }
    else:
        # Prepare Forwarding Payload
        forward_dict = payload.model_dump(exclude_unset=True, exclude={"provider"})
        forward_dict["messages"] = sanitized_messages

        base_url = upstream_base_url.rstrip("/")
        target_url = f"{base_url}/chat/completions"

        upstream_headers = {
            "Authorization": f"Bearer {upstream_key}",
            "Content-Type": "application/json",
        }

        # Forward to Upstream LLM via httpx (follow_redirects=False prevents redirect SSRF)
        upstream_start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=60.0, follow_redirects=False) as client:
                upstream_resp = await client.post(
                    target_url,
                    headers=upstream_headers,
                    json=forward_dict,
                )
        except httpx.RequestError as exc:
            total_duration_ms = round((time.perf_counter() - start_total) * 1000, 3)
            upstream_duration_ms = round((time.perf_counter() - upstream_start) * 1000, 3)
            await repo.create_audit_log(
                AuditLog(
                    workspace_id=workspace.id,
                    key_id=api_key.id,
                    model=payload.model,
                    action="ERROR",
                    is_blocked=False,
                    block_reason=f"Failed to connect to upstream LLM service: {str(exc)}",
                    findings_count=len(all_findings),
                    findings=[f.model_dump() for f in all_findings],
                    inspection_ms=inspection_duration_ms,
                    upstream_ms=upstream_duration_ms,
                    total_ms=total_duration_ms,
                )
            )
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Failed to connect to upstream LLM service: {str(exc)}",
            )

        upstream_duration_ms = round((time.perf_counter() - upstream_start) * 1000, 3)

        if upstream_resp.status_code >= 400:
            total_duration_ms = round((time.perf_counter() - start_total) * 1000, 3)
            # Log upstream failure in audit ledger to prevent repudiation
            await repo.create_audit_log(
                AuditLog(
                    workspace_id=workspace.id,
                    key_id=api_key.id,
                    model=payload.model,
                    action="ERROR",
                    is_blocked=False,
                    block_reason=f"Upstream returned HTTP {upstream_resp.status_code}",
                    findings_count=len(all_findings),
                    findings=[f.model_dump() for f in all_findings],
                    inspection_ms=inspection_duration_ms,
                    upstream_ms=upstream_duration_ms,
                    total_ms=total_duration_ms,
                )
            )
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

    # 6. Response DLP (Output Inspection)
    response_findings: List[Finding] = []
    dlp_policy_mode = (
        PolicyMode.ALLOW if policy.mode == PolicyMode.ALLOW else PolicyMode.REDACT
    )
    if policy.inspect_responses and "choices" in upstream_data:
        for choice in upstream_data.get("choices", []):
            choice_msg = choice.get("message", {})
            choice_content = choice_msg.get("content")
            if choice_content is not None:
                sanitized_choice_content, c_findings, _, _, _, c_ms = inspect_and_sanitize_content(
                    content=choice_content,
                    policy_mode=dlp_policy_mode,
                    block_injections=False,
                )
                inspection_duration_ms += c_ms
                if c_findings:
                    if policy.mode != PolicyMode.ALLOW:
                        choice_msg["content"] = sanitized_choice_content
                        if overall_action != "BLOCK":
                            overall_action = "REDACT"
                    response_findings.extend(c_findings)

            # Inspect tool_calls function arguments for leaked secrets
            tool_calls = choice_msg.get("tool_calls")
            if isinstance(tool_calls, list):
                for tc in tool_calls:
                    if isinstance(tc, dict) and "function" in tc and isinstance(tc["function"], dict):
                        fn = tc["function"]
                        args = fn.get("arguments")
                        if isinstance(args, str):
                            sanitized_args, tc_findings, _, _, _, tc_ms = inspect_and_sanitize_content(
                                content=args,
                                policy_mode=dlp_policy_mode,
                                block_injections=False,
                            )
                            inspection_duration_ms += tc_ms
                            if tc_findings:
                                if policy.mode != PolicyMode.ALLOW:
                                    fn["arguments"] = sanitized_args
                                    if overall_action != "BLOCK":
                                        overall_action = "REDACT"
                                response_findings.extend(tc_findings)

            # Inspect function_call arguments for leaked secrets
            function_call = choice_msg.get("function_call")
            if isinstance(function_call, dict):
                args = function_call.get("arguments")
                if isinstance(args, str):
                    sanitized_args, fc_findings, _, _, _, fc_ms = inspect_and_sanitize_content(
                        content=args,
                        policy_mode=dlp_policy_mode,
                        block_injections=False,
                    )
                    inspection_duration_ms += fc_ms
                    if fc_findings:
                        if policy.mode != PolicyMode.ALLOW:
                            function_call["arguments"] = sanitized_args
                            if overall_action != "BLOCK":
                                overall_action = "REDACT"
                        response_findings.extend(fc_findings)

    total_duration_ms = round((time.perf_counter() - start_total) * 1000, 3)

    # 7. Extract token usage and build aegisgate_meta
    usage_info = upstream_data.get("usage", {})
    prompt_tokens = usage_info.get("prompt_tokens")
    completion_tokens = usage_info.get("completion_tokens")

    all_combined_findings = [f.model_dump() for f in all_findings]
    for rf in response_findings:
        rf_dict = rf.model_dump()
        rf_dict["source"] = "response_dlp"
        all_combined_findings.append(rf_dict)

    meta = AegisGateMeta(
        action=overall_action,
        is_blocked=False,
        block_reason=None,
        findings_count=len(all_findings),
        findings=[f.model_dump() for f in all_findings],
        response_findings_count=len(response_findings),
        response_findings=[f.model_dump() for f in response_findings],
        inspection_ms=inspection_duration_ms,
        upstream_ms=upstream_duration_ms,
        total_ms=total_duration_ms,
        policy_mode=policy.mode.value,
    )
    upstream_data["aegisgate_meta"] = meta.model_dump()

    # 8. Record Audit Log
    await repo.create_audit_log(
        AuditLog(
            workspace_id=workspace.id,
            key_id=api_key.id,
            model=payload.model,
            action=overall_action,
            is_blocked=False,
            block_reason=None,
            findings_count=len(all_combined_findings),
            findings=all_combined_findings,
            inspection_ms=inspection_duration_ms,
            upstream_ms=upstream_duration_ms,
            total_ms=total_duration_ms,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )
    )

    return JSONResponse(status_code=status.HTTP_200_OK, content=upstream_data)
