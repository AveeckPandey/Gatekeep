import asyncio
import json
import time
from typing import Any, Dict, List, Optional, Tuple, Union

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
from app.security.stream_dlp import StreamingDlpSanitizer

router = APIRouter(tags=["Data Plane Proxy"])

_UNSUPPORTED_MEDIA_TYPES = {"image_url", "input_image", "input_audio", "audio", "file", "image"}
_UNSUPPORTED_MEDIA_KEYS = {"image_url", "input_audio", "audio", "file", "images", "files", "attachments"}
_STRUCTURAL_KEYS_SKIP_ENTROPY = {"id", "tool_call_id", "type", "required", "$schema", "format", "model"}
_ALLOWED_CONTENT_PART_KEYS = {"type", "text", "cache_control", "annotations"}


class UnsupportedFormatError(ValueError):
    """Raised when a proxy payload contains an unsupported or uninspectable format."""


class _InspectionAccumulator:
    """Collects findings, timings, and aggregate policy action across inspected fields."""

    def __init__(self, policy_mode: PolicyMode, block_injections: bool) -> None:
        self.policy_mode = policy_mode
        self.block_injections = block_injections
        self.findings: List[Finding] = []
        self.is_blocked = False
        self.block_reasons: List[str] = []
        self.action = "ALLOW"
        self.inspection_ms = 0.0

    def inspect_text(self, text: str, *, check_entropy: bool = True) -> str:
        res = detector.inspect(
            text=text,
            policy_mode=self.policy_mode,
            block_injections=self.block_injections,
            check_entropy=check_entropy,
        )
        self.inspection_ms += res.inspection_ms
        self.findings.extend(res.findings)
        if res.is_blocked:
            self.is_blocked = True
            if res.block_reason:
                self.block_reasons.append(res.block_reason)
        if res.action == "BLOCK":
            self.action = "BLOCK"
        elif res.action == "REDACT" and self.action != "BLOCK":
            self.action = "REDACT"
        return res.sanitized_text


def inspect_and_sanitize_content(
    content: Union[str, List[Any], Any],
    policy_mode: PolicyMode,
    block_injections: bool,
) -> Tuple[Union[str, List[Any], Any], List[Finding], bool, List[str], str, float]:
    """
    Inspects and sanitizes message content (`None`, `str`, or `[{"type": "text", "text": ...}]`).
    Rejects unsupported multimodal/binary parts rather than forwarding them uninspected.
    """
    acc = _InspectionAccumulator(policy_mode=policy_mode, block_injections=block_injections)
    sanitized = _inspect_message_content(content, acc, strict=True)
    return (
        sanitized,
        acc.findings,
        acc.is_blocked,
        acc.block_reasons,
        acc.action,
        acc.inspection_ms,
    )


def _reject_if_media_value(value: Any, context: str) -> None:
    if isinstance(value, str) and value.strip().lower().startswith(("data:image/", "data:audio/", "data:video/", "data:application/octet-stream")):
        raise UnsupportedFormatError(f"Unsupported binary/data URI in {context}")


def _inspect_json_strings(
    value: Any,
    acc: _InspectionAccumulator,
    *,
    context: str,
    skip_entropy: bool = False,
    reject_media: bool = True,
) -> Any:
    """Recursively inspect all string values in supported JSON structures."""
    if value is None or isinstance(value, (bool, int, float)):
        return value

    if isinstance(value, str):
        if reject_media:
            _reject_if_media_value(value, context)
        return acc.inspect_text(value, check_entropy=not skip_entropy)

    if isinstance(value, list):
        return [
            _inspect_json_strings(
                item,
                acc,
                context=f"{context}[]",
                skip_entropy=skip_entropy,
                reject_media=reject_media,
            )
            for item in value
        ]

    if isinstance(value, dict):
        if reject_media:
            item_type = value.get("type")
            if isinstance(item_type, str) and item_type in _UNSUPPORTED_MEDIA_TYPES:
                raise UnsupportedFormatError(
                    f"Unsupported media/content type '{item_type}' in {context}"
                )
            for key in value:
                if key in _UNSUPPORTED_MEDIA_KEYS and value[key] is not None:
                    raise UnsupportedFormatError(
                        f"Unsupported media field '{key}' in {context}"
                    )

        sanitized_dict: Dict[str, Any] = {}
        for k, v in value.items():
            key_skip_entropy = skip_entropy or (k in _STRUCTURAL_KEYS_SKIP_ENTROPY)
            # Tool/function identifiers like `calculate_monthly_revenue` can trip entropy checks;
            # still run deterministic secret/PII/injection regexes on `function.name`.
            if k == "name" and context.endswith((".function", ".function_call", ".json_schema")) or (
                k == "name" and context.startswith("functions")
            ):
                key_skip_entropy = True
            sanitized_dict[k] = _inspect_json_strings(
                v,
                acc,
                context=f"{context}.{k}",
                skip_entropy=key_skip_entropy,
                reject_media=reject_media,
            )
        return sanitized_dict

    raise UnsupportedFormatError(f"Unsupported value type in {context}")


def _inspect_message_content(
    content: Any,
    acc: _InspectionAccumulator,
    *,
    strict: bool,
) -> Any:
    if content is None:
        return None
    if isinstance(content, str):
        return acc.inspect_text(content)
    if isinstance(content, list):
        sanitized_list: List[Any] = []
        for idx, item in enumerate(content):
            if not isinstance(item, dict):
                if strict:
                    raise UnsupportedFormatError(
                        f"Unsupported content part at index {idx}: expected object with type='text'"
                    )
                sanitized_list.append(_inspect_json_strings(item, acc, context=f"content[{idx}]", reject_media=False))
                continue

            item_type = item.get("type")
            if item_type != "text" or not isinstance(item.get("text"), str):
                if strict:
                    raise UnsupportedFormatError(
                        f"Unsupported content part type '{item_type}' at index {idx}; only 'text' parts are supported"
                    )
                sanitized_list.append(_inspect_json_strings(item, acc, context=f"content[{idx}]", reject_media=False))
                continue

            unknown_keys = set(item.keys()) - _ALLOWED_CONTENT_PART_KEYS
            if strict and unknown_keys:
                raise UnsupportedFormatError(
                    f"Unsupported field(s) {sorted(unknown_keys)} in text content part at index {idx}"
                )

            item_copy = dict(item)
            item_copy["text"] = acc.inspect_text(item_copy["text"])
            for extra_key in item_copy:
                if extra_key not in ("type", "text"):
                    item_copy[extra_key] = _inspect_json_strings(
                        item_copy[extra_key],
                        acc,
                        context=f"content[{idx}].{extra_key}",
                        reject_media=strict,
                    )
            sanitized_list.append(item_copy)
        return sanitized_list

    if strict:
        raise UnsupportedFormatError("Unsupported message content format")
    return _inspect_json_strings(content, acc, context="content", reject_media=False)


def _validate_and_inspect_message(
    raw_msg: Dict[str, Any],
    acc: _InspectionAccumulator,
    msg_idx: int,
) -> Dict[str, Any]:
    """Preserve all message fields, inspect every text field, and reject unsupported formats."""
    msg_copy = dict(raw_msg)

    role = msg_copy.get("role")
    if not isinstance(role, str) or not role.strip():
        raise UnsupportedFormatError(f"Message at index {msg_idx} must have a non-empty string 'role'")
    msg_copy["role"] = acc.inspect_text(role, check_entropy=False)

    if "content" in msg_copy:
        msg_copy["content"] = _inspect_message_content(msg_copy["content"], acc, strict=True)

    if "name" in msg_copy and msg_copy["name"] is not None:
        if not isinstance(msg_copy["name"], str):
            raise UnsupportedFormatError(f"Message 'name' at index {msg_idx} must be a string")
        msg_copy["name"] = acc.inspect_text(msg_copy["name"])

    if "tool_call_id" in msg_copy and msg_copy["tool_call_id"] is not None:
        if not isinstance(msg_copy["tool_call_id"], str):
            raise UnsupportedFormatError(f"Message 'tool_call_id' at index {msg_idx} must be a string")
        msg_copy["tool_call_id"] = acc.inspect_text(msg_copy["tool_call_id"], check_entropy=False)

    if "tool_calls" in msg_copy and msg_copy["tool_calls"] is not None:
        tool_calls = msg_copy["tool_calls"]
        if not isinstance(tool_calls, list):
            raise UnsupportedFormatError(f"Message 'tool_calls' at index {msg_idx} must be a list")
        sanitized_tcs: List[Dict[str, Any]] = []
        for tc_idx, tc in enumerate(tool_calls):
            if not isinstance(tc, dict):
                raise UnsupportedFormatError(f"Tool call at index {tc_idx} must be an object")
            tc_type = tc.get("type")
            if tc_type is not None and tc_type != "function":
                raise UnsupportedFormatError(
                    f"Unsupported tool_call type '{tc_type}' at message {msg_idx}; only 'function' is supported"
                )
            fn = tc.get("function")
            if fn is not None:
                if not isinstance(fn, dict):
                    raise UnsupportedFormatError(f"tool_call.function at message {msg_idx} must be an object")
                if "name" in fn and fn["name"] is not None and not isinstance(fn["name"], str):
                    raise UnsupportedFormatError(f"tool_call.function.name at message {msg_idx} must be a string")
                if "arguments" in fn and fn["arguments"] is not None and not isinstance(fn["arguments"], str):
                    raise UnsupportedFormatError(
                        f"tool_call.function.arguments at message {msg_idx} must be a string"
                    )
            sanitized_tcs.append(
                _inspect_json_strings(
                    tc,
                    acc,
                    context=f"messages[{msg_idx}].tool_calls[{tc_idx}]",
                )
            )
        msg_copy["tool_calls"] = sanitized_tcs

    if "function_call" in msg_copy and msg_copy["function_call"] is not None:
        fc = msg_copy["function_call"]
        if not isinstance(fc, dict):
            raise UnsupportedFormatError(f"Message 'function_call' at index {msg_idx} must be an object")
        if "name" in fc and fc["name"] is not None and not isinstance(fc["name"], str):
            raise UnsupportedFormatError(f"function_call.name at message {msg_idx} must be a string")
        if "arguments" in fc and fc["arguments"] is not None and not isinstance(fc["arguments"], str):
            raise UnsupportedFormatError(f"function_call.arguments at message {msg_idx} must be a string")
        msg_copy["function_call"] = _inspect_json_strings(
            fc,
            acc,
            context=f"messages[{msg_idx}].function_call",
        )

    # Preserve and inspect all extra message fields (e.g., reasoning_content, refusal, metadata)
    known_keys = {"role", "content", "name", "tool_calls", "tool_call_id", "function_call"}
    for extra_key in list(msg_copy.keys()):
        if extra_key in known_keys:
            continue
        if extra_key in _UNSUPPORTED_MEDIA_KEYS and msg_copy[extra_key] is not None:
            raise UnsupportedFormatError(
                f"Unsupported media field '{extra_key}' in message {msg_idx}"
            )
        msg_copy[extra_key] = _inspect_json_strings(
            msg_copy[extra_key],
            acc,
            context=f"messages[{msg_idx}].{extra_key}",
        )

    return msg_copy


def _validate_and_inspect_payload(
    payload: ChatCompletionRequest,
    policy: Policy,
) -> Tuple[Dict[str, Any], _InspectionAccumulator]:
    """Validate payload format and inspect all text-bearing request fields."""
    if not payload.model or not payload.model.strip():
        raise UnsupportedFormatError("Request 'model' must be a non-empty string")
    if not payload.messages:
        raise UnsupportedFormatError("Request 'messages' must contain at least one message")

    acc = _InspectionAccumulator(policy_mode=policy.mode, block_injections=policy.block_injections)
    forward_dict = payload.model_dump(exclude_unset=True, exclude={"provider"})

    # Reject unsupported media/non-chat top-level parameters before inspection
    for media_key in ("audio", "images", "files", "attachments"):
        if media_key in forward_dict and forward_dict[media_key] is not None:
            raise UnsupportedFormatError(
                f"Unsupported request field '{media_key}': /v1/chat/completions supports text chat only"
            )
    if "modalities" in forward_dict and forward_dict["modalities"] is not None:
        modalities = forward_dict["modalities"]
        if not isinstance(modalities, list) or any(m != "text" for m in modalities):
            raise UnsupportedFormatError(
                "Unsupported 'modalities': only ['text'] is supported by /v1/chat/completions"
            )

    forward_dict["model"] = acc.inspect_text(payload.model, check_entropy=False)

    # Validate & inspect messages while preserving supported extra fields
    sanitized_messages: List[Dict[str, Any]] = []
    for idx, msg in enumerate(payload.messages):
        raw_msg = msg.model_dump(exclude_unset=True)
        sanitized_messages.append(_validate_and_inspect_message(raw_msg, acc, idx))
    forward_dict["messages"] = sanitized_messages

    # Validate & inspect tool/function definitions and remaining text-bearing fields
    if "tools" in forward_dict and forward_dict["tools"] is not None:
        tools = forward_dict["tools"]
        if not isinstance(tools, list):
            raise UnsupportedFormatError("'tools' must be a list of tool definitions")
        sanitized_tools: List[Dict[str, Any]] = []
        for t_idx, tool in enumerate(tools):
            if not isinstance(tool, dict):
                raise UnsupportedFormatError(f"Tool definition at index {t_idx} must be an object")
            if tool.get("type") != "function" or not isinstance(tool.get("function"), dict):
                raise UnsupportedFormatError(
                    f"Unsupported tool definition at index {t_idx}; only type='function' with a 'function' object is supported"
                )
            fn = tool["function"]
            if not isinstance(fn.get("name"), str) or not fn["name"].strip():
                raise UnsupportedFormatError(f"Tool function at index {t_idx} must have a string 'name'")
            sanitized_tools.append(
                _inspect_json_strings(tool, acc, context=f"tools[{t_idx}]")
            )
        forward_dict["tools"] = sanitized_tools

    if "functions" in forward_dict and forward_dict["functions"] is not None:
        functions = forward_dict["functions"]
        if not isinstance(functions, list) or any(not isinstance(f, dict) for f in functions):
            raise UnsupportedFormatError("'functions' must be a list of function objects")
        forward_dict["functions"] = _inspect_json_strings(functions, acc, context="functions")

    skip_top_level = {"model", "messages", "tools", "functions"}
    for key, val in list(forward_dict.items()):
        if key in skip_top_level:
            continue
        forward_dict[key] = _inspect_json_strings(val, acc, context=key)

    return forward_dict, acc


async def _record_audit_log(
    repo: BaseRepository,
    *,
    workspace_id: str,
    key_id: str,
    model: str,
    action: str,
    is_blocked: bool,
    block_reason: Optional[str],
    findings: List[Dict[str, Any]],
    inspection_ms: float,
    upstream_ms: Optional[float],
    start_total: float,
    prompt_tokens: Optional[int] = None,
    completion_tokens: Optional[int] = None,
) -> float:
    total_duration_ms = round((time.perf_counter() - start_total) * 1000, 3)
    await repo.create_audit_log(
        AuditLog(
            workspace_id=workspace_id,
            key_id=key_id,
            model=model,
            action=action,
            is_blocked=is_blocked,
            block_reason=block_reason,
            findings_count=len(findings),
            findings=findings,
            inspection_ms=round(inspection_ms, 3),
            upstream_ms=upstream_ms,
            total_ms=total_duration_ms,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )
    )
    return total_duration_ms


def _inspect_non_streaming_response(
    upstream_data: Dict[str, Any],
    policy: Policy,
    acc: _InspectionAccumulator,
) -> List[Finding]:
    """Run response DLP on completion content, tool_calls, function_call, and text extras."""
    response_findings: List[Finding] = []
    if not policy.inspect_responses or "choices" not in upstream_data:
        return response_findings

    dlp_policy_mode = PolicyMode.ALLOW if policy.mode == PolicyMode.ALLOW else PolicyMode.REDACT
    resp_acc = _InspectionAccumulator(policy_mode=dlp_policy_mode, block_injections=False)

    for choice in upstream_data.get("choices", []):
        if not isinstance(choice, dict):
            continue
        choice_msg = choice.get("message")
        if not isinstance(choice_msg, dict):
            continue

        if choice_msg.get("content") is not None:
            sanitized_content = _inspect_message_content(choice_msg["content"], resp_acc, strict=False)
            if policy.mode != PolicyMode.ALLOW and resp_acc.action == "REDACT":
                choice_msg["content"] = sanitized_content

        for text_key in ("refusal", "reasoning_content"):
            if isinstance(choice_msg.get(text_key), str):
                sanitized_val = resp_acc.inspect_text(choice_msg[text_key])
                if policy.mode != PolicyMode.ALLOW:
                    choice_msg[text_key] = sanitized_val

        tool_calls = choice_msg.get("tool_calls")
        if isinstance(tool_calls, list):
            for tc in tool_calls:
                if isinstance(tc, dict) and isinstance(tc.get("function"), dict):
                    fn = tc["function"]
                    if isinstance(fn.get("name"), str):
                        sanitized_name = resp_acc.inspect_text(fn["name"])
                        if policy.mode != PolicyMode.ALLOW:
                            fn["name"] = sanitized_name
                    if isinstance(fn.get("arguments"), str):
                        sanitized_args = resp_acc.inspect_text(fn["arguments"])
                        if policy.mode != PolicyMode.ALLOW:
                            fn["arguments"] = sanitized_args

        function_call = choice_msg.get("function_call")
        if isinstance(function_call, dict):
            if isinstance(function_call.get("name"), str):
                sanitized_name = resp_acc.inspect_text(function_call["name"])
                if policy.mode != PolicyMode.ALLOW:
                    function_call["name"] = sanitized_name
            if isinstance(function_call.get("arguments"), str):
                sanitized_args = resp_acc.inspect_text(function_call["arguments"])
                if policy.mode != PolicyMode.ALLOW:
                    function_call["arguments"] = sanitized_args

    acc.inspection_ms += resp_acc.inspection_ms
    response_findings.extend(resp_acc.findings)
    if response_findings and policy.mode != PolicyMode.ALLOW and acc.action != "BLOCK":
        acc.action = "REDACT"
    return response_findings


@router.post("/v1/chat/completions")
async def chat_completions_proxy(
    request: Request,
    payload: ChatCompletionRequest,
    auth_context: Tuple[ApiKey, Workspace, Policy] = Depends(get_gateway_auth),
    repo: BaseRepository = Depends(get_repository),
):
    """
    Compatible Chat Completions Data Plane Gateway Proxy:
    1. Authenticates request via Gateway API Key (`gw_live_...`).
    2. Validates format and inspects messages, tool definitions, and text fields.
    3. Enforces workspace policy: ALLOW, REDACT, or BLOCK (HTTP 403).
    4. Forwards sanitized payload to the configured upstream Bearer endpoint.
    5. Returns response with `aegisgate_meta` telemetry and records a single final audit entry.
    """
    start_total = time.perf_counter()
    api_key, workspace, policy = auth_context

    # 0. Enforce Per-Workspace Rate Limiting
    allowed, retry_after = workspace_rate_limiter.check_and_record(
        workspace_id=workspace.id,
        limit_rpm=policy.rate_limit_rpm,
    )
    if not allowed:
        detail = f"Rate limit exceeded: {policy.rate_limit_rpm} requests per minute limit reached for workspace."
        await _record_audit_log(
            repo,
            workspace_id=workspace.id,
            key_id=api_key.id,
            model=payload.model,
            action="ERROR",
            is_blocked=False,
            block_reason=detail,
            findings=[],
            inspection_ms=0.0,
            upstream_ms=None,
            start_total=start_total,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=detail,
            headers={"Retry-After": str(retry_after)},
        )

    # 1. Validate format & inspect all text-bearing request fields
    try:
        forward_dict, acc = _validate_and_inspect_payload(payload, policy)
    except UnsupportedFormatError as exc:
        detail = str(exc)
        await _record_audit_log(
            repo,
            workspace_id=workspace.id,
            key_id=api_key.id,
            model=payload.model,
            action="ERROR",
            is_blocked=False,
            block_reason=detail,
            findings=[],
            inspection_ms=0.0,
            upstream_ms=None,
            start_total=start_total,
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail) from exc

    inspection_duration_ms = round(acc.inspection_ms, 3)
    serialized_req_findings = [f.model_dump() for f in acc.findings]

    # 2. Enforcement: If Blocked, return HTTP 403 immediately and record single audit log
    if acc.is_blocked or acc.action == "BLOCK":
        block_reason_str = "; ".join(acc.block_reasons) if acc.block_reasons else "Security policy blocked request"
        total_duration_ms = await _record_audit_log(
            repo,
            workspace_id=workspace.id,
            key_id=api_key.id,
            model=payload.model,
            action="BLOCK",
            is_blocked=True,
            block_reason=block_reason_str,
            findings=serialized_req_findings,
            inspection_ms=inspection_duration_ms,
            upstream_ms=None,
            start_total=start_total,
        )

        error_meta = AegisGateMeta(
            action="BLOCK",
            is_blocked=True,
            block_reason=block_reason_str,
            findings_count=len(acc.findings),
            findings=serialized_req_findings,
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

    # 3. Upstream Dispatch Configuration (or Demo Workspace Mock)
    is_demo_workspace = (
        workspace.id.startswith("ws_demo")
        or policy.upstream_base_url.startswith("https://demo.gatekeep.local")
    ) and not payload.provider
    upstream_key = None
    upstream_base_url = policy.upstream_base_url

    async def _fail_config(status_code: int, detail: str) -> None:
        await _record_audit_log(
            repo,
            workspace_id=workspace.id,
            key_id=api_key.id,
            model=payload.model,
            action="ERROR",
            is_blocked=False,
            block_reason=detail,
            findings=serialized_req_findings,
            inspection_ms=inspection_duration_ms,
            upstream_ms=None,
            start_total=start_total,
        )
        raise HTTPException(status_code=status_code, detail=detail)

    if payload.provider:
        try:
            upstream_base_url, upstream_key = resolve_provider(payload.provider, workspace.id)
        except PermissionError as exc:
            await _fail_config(status.HTTP_403_FORBIDDEN, str(exc))
        except ValueError as exc:
            await _fail_config(status.HTTP_400_BAD_REQUEST, str(exc))

    if not (is_demo_workspace and not policy.encrypted_upstream_api_key):
        if not upstream_key and policy.encrypted_upstream_api_key:
            try:
                upstream_key = decrypt_secret(policy.encrypted_upstream_api_key)
            except Exception:
                await _fail_config(
                    status.HTTP_500_INTERNAL_SERVER_ERROR,
                    "Failed to decrypt workspace upstream API key",
                )

        if not upstream_key:
            await _fail_config(
                status.HTTP_502_BAD_GATEWAY,
                "No upstream API key configured for this workspace or selected provider.",
            )

        # Validate target upstream URL to prevent SSRF before dispatch
        try:
            validate_upstream_url(upstream_base_url)
        except ValueError as exc:
            await _fail_config(
                status.HTTP_400_BAD_REQUEST,
                f"Invalid upstream URL configured in workspace policy: {exc}",
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
                        "model": payload.model or "demo-model",
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
                    "model": payload.model or "demo-model",
                    "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                }
                yield f"data: {json.dumps(done_chunk)}\n\n"
                yield "data: [DONE]\n\n"

                await _record_audit_log(
                    repo,
                    workspace_id=workspace.id,
                    key_id=api_key.id,
                    model=payload.model,
                    action=acc.action,
                    is_blocked=False,
                    block_reason=None,
                    findings=serialized_req_findings,
                    inspection_ms=inspection_duration_ms,
                    upstream_ms=8.5,
                    start_total=start_total,
                )

            return StreamingResponse(demo_sse_generator(), media_type="text/event-stream")

        # Live upstream SSE: connect and inspect upstream status BEFORE starting HTTP 200 stream
        target_url = f"{upstream_base_url.rstrip('/')}/chat/completions"
        upstream_headers = {
            "Authorization": f"Bearer {upstream_key}",
            "Content-Type": "application/json",
        }
        client = httpx.AsyncClient(timeout=60.0, follow_redirects=False)
        upstream_start = time.perf_counter()
        try:
            req = client.build_request("POST", target_url, headers=upstream_headers, json=forward_dict)
            upstream_resp = await client.send(req, stream=True)
        except httpx.RequestError as exc:
            await client.aclose()
            upstream_duration_ms = round((time.perf_counter() - upstream_start) * 1000, 3)
            detail = f"Failed to connect to upstream LLM service: {exc}"
            await _record_audit_log(
                repo,
                workspace_id=workspace.id,
                key_id=api_key.id,
                model=payload.model,
                action="ERROR",
                is_blocked=False,
                block_reason=detail,
                findings=serialized_req_findings,
                inspection_ms=inspection_duration_ms,
                upstream_ms=upstream_duration_ms,
                start_total=start_total,
            )
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=detail) from exc

        if upstream_resp.status_code >= 400:
            err_body = await upstream_resp.aread()
            upstream_duration_ms = round((time.perf_counter() - upstream_start) * 1000, 3)
            media_type = upstream_resp.headers.get("content-type", "application/json")
            status_code = upstream_resp.status_code
            await upstream_resp.aclose()
            await client.aclose()
            await _record_audit_log(
                repo,
                workspace_id=workspace.id,
                key_id=api_key.id,
                model=payload.model,
                action="ERROR",
                is_blocked=False,
                block_reason=f"Upstream returned HTTP {status_code}",
                findings=serialized_req_findings,
                inspection_ms=inspection_duration_ms,
                upstream_ms=upstream_duration_ms,
                start_total=start_total,
            )
            try:
                err_json = json.loads(err_body.decode("utf-8"))
                return JSONResponse(status_code=status_code, content=err_json)
            except Exception:
                return Response(content=err_body, status_code=status_code, media_type=media_type)

        sanitizer = StreamingDlpSanitizer(
            policy_mode=policy.mode,
            inspect_responses=policy.inspect_responses,
        )

        async def upstream_sse_generator():
            stream_error: Optional[str] = None
            overall_action = acc.action
            done_sent = False
            try:
                async for line in upstream_resp.aiter_lines():
                    if not line:
                        continue
                    if line.startswith("data: "):
                        data_str = line[6:].strip()
                        if data_str == "[DONE]":
                            for flushed_chunk in sanitizer.flush_all():
                                yield f"data: {json.dumps(flushed_chunk)}\n\n"
                            yield "data: [DONE]\n\n"
                            done_sent = True
                            break
                        try:
                            chunk_json = json.loads(data_str)
                            for out_chunk in sanitizer.process_chunk(chunk_json):
                                yield f"data: {json.dumps(out_chunk)}\n\n"
                        except json.JSONDecodeError:
                            yield f"{line}\n\n"
                    else:
                        yield f"{line}\n\n"

                if not done_sent:
                    for flushed_chunk in sanitizer.flush_all():
                        yield f"data: {json.dumps(flushed_chunk)}\n\n"
            except Exception as exc:
                stream_error = str(exc)
                yield f"data: {json.dumps({'error': {'message': f'Stream interrupted: {stream_error}'}})}\n\n"
                yield "data: [DONE]\n\n"
            finally:
                await upstream_resp.aclose()
                await client.aclose()
                upstream_duration_ms = round((time.perf_counter() - upstream_start) * 1000, 3)
                if sanitizer.redacted and overall_action != "BLOCK":
                    overall_action = "REDACT"
                all_combined_findings = list(serialized_req_findings)
                for rf in sanitizer.response_findings:
                    rf_dict = rf.model_dump()
                    rf_dict["source"] = "response_dlp"
                    all_combined_findings.append(rf_dict)

                usage_info = sanitizer.usage or {}
                await _record_audit_log(
                    repo,
                    workspace_id=workspace.id,
                    key_id=api_key.id,
                    model=payload.model,
                    action="ERROR" if stream_error else overall_action,
                    is_blocked=False,
                    block_reason=stream_error,
                    findings=all_combined_findings,
                    inspection_ms=inspection_duration_ms + sanitizer.inspection_ms,
                    upstream_ms=upstream_duration_ms,
                    start_total=start_total,
                    prompt_tokens=usage_info.get("prompt_tokens"),
                    completion_tokens=usage_info.get("completion_tokens"),
                )

        return StreamingResponse(upstream_sse_generator(), media_type="text/event-stream")

    # 5. Non-Streaming Dispatch
    if is_demo_workspace and not policy.encrypted_upstream_api_key:
        upstream_duration_ms = 8.5
        upstream_data = {
            "id": f"chatcmpl-demo-{int(time.time())}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": payload.model or "demo-model",
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
        target_url = f"{upstream_base_url.rstrip('/')}/chat/completions"
        upstream_headers = {
            "Authorization": f"Bearer {upstream_key}",
            "Content-Type": "application/json",
        }

        upstream_start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=60.0, follow_redirects=False) as client:
                upstream_resp = await client.post(
                    target_url,
                    headers=upstream_headers,
                    json=forward_dict,
                )
        except httpx.RequestError as exc:
            upstream_duration_ms = round((time.perf_counter() - upstream_start) * 1000, 3)
            detail = f"Failed to connect to upstream LLM service: {exc}"
            await _record_audit_log(
                repo,
                workspace_id=workspace.id,
                key_id=api_key.id,
                model=payload.model,
                action="ERROR",
                is_blocked=False,
                block_reason=detail,
                findings=serialized_req_findings,
                inspection_ms=inspection_duration_ms,
                upstream_ms=upstream_duration_ms,
                start_total=start_total,
            )
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=detail) from exc

        upstream_duration_ms = round((time.perf_counter() - upstream_start) * 1000, 3)

        if upstream_resp.status_code >= 400:
            await _record_audit_log(
                repo,
                workspace_id=workspace.id,
                key_id=api_key.id,
                model=payload.model,
                action="ERROR",
                is_blocked=False,
                block_reason=f"Upstream returned HTTP {upstream_resp.status_code}",
                findings=serialized_req_findings,
                inspection_ms=inspection_duration_ms,
                upstream_ms=upstream_duration_ms,
                start_total=start_total,
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

        try:
            upstream_data = upstream_resp.json()
        except Exception as exc:
            detail = "Upstream returned invalid JSON response"
            await _record_audit_log(
                repo,
                workspace_id=workspace.id,
                key_id=api_key.id,
                model=payload.model,
                action="ERROR",
                is_blocked=False,
                block_reason=detail,
                findings=serialized_req_findings,
                inspection_ms=inspection_duration_ms,
                upstream_ms=upstream_duration_ms,
                start_total=start_total,
            )
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=detail) from exc

    # 6. Response DLP (Output Inspection)
    response_findings = _inspect_non_streaming_response(upstream_data, policy, acc)
    inspection_duration_ms = round(acc.inspection_ms, 3)

    # 7. Extract token usage and build aegisgate_meta
    usage_info = upstream_data.get("usage") or {}
    prompt_tokens = usage_info.get("prompt_tokens")
    completion_tokens = usage_info.get("completion_tokens")

    all_combined_findings = list(serialized_req_findings)
    for rf in response_findings:
        rf_dict = rf.model_dump()
        rf_dict["source"] = "response_dlp"
        all_combined_findings.append(rf_dict)

    # 8. Record single final Audit Log
    total_duration_ms = await _record_audit_log(
        repo,
        workspace_id=workspace.id,
        key_id=api_key.id,
        model=payload.model,
        action=acc.action,
        is_blocked=False,
        block_reason=None,
        findings=all_combined_findings,
        inspection_ms=inspection_duration_ms,
        upstream_ms=upstream_duration_ms,
        start_total=start_total,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
    )

    meta = AegisGateMeta(
        action=acc.action,
        is_blocked=False,
        block_reason=None,
        findings_count=len(acc.findings),
        findings=serialized_req_findings,
        response_findings_count=len(response_findings),
        response_findings=[f.model_dump() for f in response_findings],
        inspection_ms=inspection_duration_ms,
        upstream_ms=upstream_duration_ms,
        total_ms=total_duration_ms,
        policy_mode=policy.mode.value,
    )
    upstream_data["aegisgate_meta"] = meta.model_dump()

    return JSONResponse(status_code=status.HTTP_200_OK, content=upstream_data)
