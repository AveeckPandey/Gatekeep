"""Validate compatible provider responses before inspection or forwarding."""

import math
from typing import Any, AsyncIterator


class UpstreamProtocolError(ValueError):
    """An upstream response cannot be safely interpreted as a completion."""


async def iter_sse_data(lines: AsyncIterator[str]) -> AsyncIterator[str]:
    """Decode SSE data events (optional space, multiline data, comments, UTF-8 BOM).

    Transport fields such as event/id/retry are not completion payloads. We emit
    normalized data events after validation, never arbitrary upstream wire lines.
    See https://html.spec.whatwg.org/multipage/server-sent-events.html.
    """
    data = []
    first_line = True
    async for line in lines:
        if first_line:
            line = line.removeprefix("\ufeff")
            first_line = False
        if not line:
            if data:
                yield "\n".join(data)
                data = []
            continue
        if line.startswith(":"):
            continue
        field, _, value = line.partition(":")
        if value.startswith(" "):
            value = value[1:]
        if field == "data":
            data.append(value)
    if data:
        # An incomplete event is not safe to pass through or silently call success.
        raise UpstreamProtocolError("Upstream ended with an incomplete SSE event")


def _validate_function(function: Any) -> None:
    if not isinstance(function, dict):
        raise UpstreamProtocolError("Upstream returned an invalid function call")
    for key in ("name", "arguments"):
        if function.get(key) is not None and not isinstance(function[key], str):
            raise UpstreamProtocolError("Upstream returned an invalid function field")


def validate_completion(data: Any, *, streaming: bool = False) -> None:
    """Validate fields used by DLP and audit logging without requiring vendor IDs."""
    if not isinstance(data, dict):
        raise UpstreamProtocolError("Upstream completion must be a JSON object")
    # Python's JSON decoder accepts NaN/Infinity, but JSON responses (and the
    # audit store) cannot serialize them. Catch this before recording success.
    pending = [data]
    while pending:
        value = pending.pop()
        if isinstance(value, float) and not math.isfinite(value):
            raise UpstreamProtocolError("Upstream returned a non-finite JSON number")
        if isinstance(value, dict):
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    if data.get("error") is not None:
        # Provider messages may contain credentials or uninspected generated text.
        raise UpstreamProtocolError("Upstream provider reported a generation error")
    usage = data.get("usage")
    if usage is not None:
        if not isinstance(usage, dict):
            raise UpstreamProtocolError("Upstream returned invalid token usage")
        for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
            value = usage.get(key)
            if value is not None and (type(value) is not int or value < 0):
                raise UpstreamProtocolError("Upstream returned invalid token counts")
    choices = data.get("choices")
    if streaming and choices is None and isinstance(usage, dict):
        return
    if not isinstance(choices, list) or (not streaming and not choices):
        raise UpstreamProtocolError("Upstream returned invalid completion choices")
    for choice in choices:
        if not isinstance(choice, dict):
            raise UpstreamProtocolError("Upstream returned an invalid completion choice")
        if "index" in choice and (type(choice["index"]) is not int or choice["index"] < 0):
            raise UpstreamProtocolError("Upstream returned an invalid choice index")
        if choice.get("finish_reason") is not None and not isinstance(choice["finish_reason"], str):
            raise UpstreamProtocolError("Upstream returned an invalid finish reason")
        message = choice.get("delta" if streaming else "message")
        if streaming and message is None and choice.get("finish_reason") is not None:
            message = {}
        if not isinstance(message, dict):
            raise UpstreamProtocolError("Upstream returned an invalid completion message")
        for key in ("role", "refusal", "reasoning_content"):
            if message.get(key) is not None and not isinstance(message[key], str):
                raise UpstreamProtocolError("Upstream returned an invalid text field")
        content = message.get("content")
        if content is not None and not isinstance(content, str):
            if streaming or not isinstance(content, list):
                raise UpstreamProtocolError("Upstream returned unsupported completion content")
            for part in content:
                if not isinstance(part, dict) or part.get("type") != "text" or not isinstance(part.get("text"), str):
                    raise UpstreamProtocolError("Upstream returned unsupported completion content")
        if message.get("function_call") is not None:
            _validate_function(message["function_call"])
        calls = message.get("tool_calls")
        if calls is not None:
            if not isinstance(calls, list):
                raise UpstreamProtocolError("Upstream returned invalid tool calls")
            for call in calls:
                if not isinstance(call, dict):
                    raise UpstreamProtocolError("Upstream returned an invalid tool call")
                if "index" in call and (type(call["index"]) is not int or call["index"] < 0):
                    raise UpstreamProtocolError("Upstream returned an invalid tool index")
                if call.get("function") is not None:
                    _validate_function(call["function"])
