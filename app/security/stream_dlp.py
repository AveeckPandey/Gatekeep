"""Chunk-boundary-safe DLP sanitization for OpenAI-compatible SSE streams."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.security.detector import Finding, PolicyMode, detector
from app.security.upstream_protocol import UpstreamProtocolError, validate_completion

_STREAM_HOLDBACK_CHARS = 256


def _find_safe_flush_cut(text: str, holdback: int = _STREAM_HOLDBACK_CHARS) -> int:
    """Return a prefix length at least `holdback` chars from the end that avoids splitting secrets or cards."""
    if len(text) <= holdback:
        return 0
    idx = len(text) - holdback
    while idx > 0:
        if text[idx - 1].isspace():
            if text[idx - 1] == "\n":
                return idx
            before = text[: idx - 1].rstrip(" \t-")
            if not before or not before[-1].isdigit():
                return idx
        idx -= 1
    return 0


@dataclass
class _ChoiceBuffer:
    index: int
    content: str = ""
    reasoning_content: str = ""
    refusal: str = ""
    pending_role: Optional[str] = None
    tool_calls: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    function_call: Optional[Dict[str, Any]] = None
    last_meta: Dict[str, Any] = field(default_factory=dict)
    extra_text: Dict[str, str] = field(default_factory=dict)
    extra_scalars: Dict[str, Any] = field(default_factory=dict)
    metadata_events: List[Any] = field(default_factory=list)


class StreamingDlpSanitizer:
    """Buffers streamed text/tool arguments across SSE chunks before response DLP inspection."""

    def __init__(self, policy_mode: PolicyMode, inspect_responses: bool) -> None:
        self.policy_mode = policy_mode
        self.inspect_responses = inspect_responses
        self.dlp_policy_mode = (
            PolicyMode.ALLOW if policy_mode == PolicyMode.ALLOW else PolicyMode.REDACT
        )
        self.choices: Dict[int, _ChoiceBuffer] = {}
        self.response_findings: List[Finding] = []
        self.redacted = False
        self.inspection_ms = 0.0
        self.usage: Optional[Dict[str, Any]] = None
        self.seen_choices: set[int] = set()
        self.finished_choices: set[int] = set()

    @property
    def is_complete(self) -> bool:
        return bool(self.seen_choices) and self.seen_choices == self.finished_choices

    def _inspect_str(self, text: str, *, check_entropy: bool = True) -> str:
        if not text:
            return text
        res = detector.inspect(
            text=text,
            policy_mode=self.dlp_policy_mode,
            block_injections=False,
            check_entropy=check_entropy,
        )
        self.inspection_ms += res.inspection_ms
        if res.findings:
            self.response_findings.extend(res.findings)
            if self.policy_mode != PolicyMode.ALLOW:
                self.redacted = True
                return res.sanitized_text
        return text

    def _inspect_json(self, value: Any, *, identifier: bool = False) -> Any:
        """Inspect complete metadata values, preserving their JSON structure."""
        if isinstance(value, str):
            return self._inspect_str(value, check_entropy=not identifier)
        if isinstance(value, list):
            return [self._inspect_json(item) for item in value]
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                if self._inspect_str(key, check_entropy=False) != key:
                    raise UpstreamProtocolError("Upstream metadata contains a sensitive property name")
                result[key] = self._inspect_json(item, identifier=key in {
                    "id", "model", "object", "system_fingerprint", "type", "name",
                })
            return result
        return value

    def _flush_metadata(self, buf: _ChoiceBuffer) -> List[Dict[str, Any]]:
        # Logprob tokens and byte arrays can reconstruct redacted content. Hold
        # them until the complete choice has been inspected, including tokens
        # split across events. Safe metadata is preserved event for event.
        token_parts: Dict[tuple, List[str]] = {}
        token_bytes: Dict[tuple, List[int]] = {}

        def collect(value: Any, path: tuple = ()) -> None:
            if isinstance(value, dict):
                if isinstance(value.get("token"), str):
                    token_parts.setdefault(path, []).append(value["token"])
                raw_bytes = value.get("bytes")
                if isinstance(raw_bytes, list) and all(type(b) is int and 0 <= b <= 255 for b in raw_bytes):
                    token_bytes.setdefault(path, []).extend(raw_bytes)
                for key, item in value.items():
                    if key not in ("token", "bytes"):
                        collect(item, path + (key,))
            elif isinstance(value, list):
                for item in value:
                    collect(item, path)

        for choice_fields, _ in buf.metadata_events:
            collect(choice_fields.get("logprobs"))
        for parts in token_parts.values():
            self._inspect_str("".join(parts))
        for raw_bytes in token_bytes.values():
            self._inspect_str(bytes(raw_bytes).decode("utf-8", errors="replace"))
        inspected_events = [
            (self._inspect_json(choice_fields), self._inspect_json(chunk_fields))
            for choice_fields, chunk_fields in buf.metadata_events
        ]
        output = []
        for choice_fields, chunk_fields in inspected_events:
            if self.redacted and choice_fields.get("logprobs") is not None:
                choice_fields["logprobs"] = None
                choice_fields["gatekeep_logprobs_redacted"] = True
            output.append(self._make_chunk(buf, {}, extra_choice_fields=choice_fields,
                                           extra_chunk_fields=chunk_fields))
        buf.metadata_events.clear()
        return output

    def _get_choice_buf(self, idx: int, chunk_json: Dict[str, Any]) -> _ChoiceBuffer:
        if idx not in self.choices:
            self.choices[idx] = _ChoiceBuffer(index=idx)
        buf = self.choices[idx]
        for key in ("id", "object", "created", "model", "system_fingerprint"):
            if key in chunk_json:
                buf.last_meta[key] = chunk_json[key]
        return buf

    def _make_chunk(
        self,
        buf: _ChoiceBuffer,
        delta: Dict[str, Any],
        finish_reason: Optional[str] = None,
        extra_choice_fields: Optional[Dict[str, Any]] = None,
        extra_chunk_fields: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        chunk: Dict[str, Any] = dict(buf.last_meta)
        if "object" not in chunk:
            chunk["object"] = "chat.completion.chunk"
        choice_obj: Dict[str, Any] = {
            "index": buf.index,
            "delta": delta,
            "finish_reason": finish_reason,
        }
        if extra_choice_fields:
            choice_obj.update(extra_choice_fields)
        chunk["choices"] = [choice_obj]
        if extra_chunk_fields:
            chunk.update(extra_chunk_fields)
        return chunk

    def _accumulate_tool_calls(self, buf: _ChoiceBuffer, tc_deltas: List[Any]) -> None:
        for tc in tc_deltas:
            if not isinstance(tc, dict):
                continue
            tc_idx = tc.get("index", 0)
            if not isinstance(tc_idx, int):
                tc_idx = 0
            entry = buf.tool_calls.setdefault(tc_idx, {"index": tc_idx})
            for key in ("id", "type"):
                if key in tc and tc[key] is not None:
                    entry[key] = tc[key]
            if isinstance(tc.get("function"), dict):
                fn_delta = tc["function"]
                fn_entry = entry.setdefault("function", {})
                if isinstance(fn_delta.get("name"), str):
                    fn_entry["name"] = fn_entry.get("name", "") + fn_delta["name"]
                if isinstance(fn_delta.get("arguments"), str):
                    fn_entry["arguments"] = fn_entry.get("arguments", "") + fn_delta["arguments"]
                for k, v in fn_delta.items():
                    if k not in ("name", "arguments"):
                        fn_entry[k] = v

    def _accumulate_function_call(self, buf: _ChoiceBuffer, fc_delta: Dict[str, Any]) -> None:
        if buf.function_call is None:
            buf.function_call = {}
        if isinstance(fc_delta.get("name"), str):
            buf.function_call["name"] = buf.function_call.get("name", "") + fc_delta["name"]
        if isinstance(fc_delta.get("arguments"), str):
            buf.function_call["arguments"] = (
                buf.function_call.get("arguments", "") + fc_delta["arguments"]
            )
        for k, v in fc_delta.items():
            if k not in ("name", "arguments"):
                buf.function_call[k] = v

    def _flush_safe_text_prefixes(self, buf: _ChoiceBuffer) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        delta: Dict[str, Any] = {}

        for field_name in ("content", "reasoning_content", "refusal"):
            value = getattr(buf, field_name)
            cut = _find_safe_flush_cut(value)
            if cut > 0:
                delta[field_name] = self._inspect_str(value[:cut])
                setattr(buf, field_name, value[cut:])

        if delta:
            if buf.pending_role is not None:
                delta["role"] = buf.pending_role
                buf.pending_role = None
            out.append(self._make_chunk(buf, delta))
        return out

    def _flush_choice(self, buf: _ChoiceBuffer) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        text_delta: Dict[str, Any] = {}

        for field_name in ("content", "reasoning_content", "refusal"):
            value = getattr(buf, field_name)
            if value:
                text_delta[field_name] = self._inspect_str(value)
                setattr(buf, field_name, "")

        for key, value in buf.extra_text.items():
            text_delta[key] = self._inspect_str(value)
        text_delta.update(buf.extra_scalars)
        buf.extra_text.clear()
        buf.extra_scalars.clear()

        if buf.pending_role is not None and (text_delta or not buf.tool_calls and not buf.function_call):
            text_delta["role"] = buf.pending_role
            buf.pending_role = None

        if text_delta:
            out.append(self._make_chunk(buf, text_delta))

        if buf.tool_calls:
            sanitized_tcs: List[Dict[str, Any]] = []
            for tc_idx in sorted(buf.tool_calls):
                tc = dict(buf.tool_calls[tc_idx])
                if isinstance(tc.get("function"), dict):
                    fn = dict(tc["function"])
                    if isinstance(fn.get("name"), str):
                        fn["name"] = self._inspect_str(fn["name"], check_entropy=False)
                    if isinstance(fn.get("arguments"), str):
                        fn["arguments"] = self._inspect_str(fn["arguments"])
                    tc["function"] = fn
                sanitized_tcs.append(tc)
            buf.tool_calls.clear()

            tc_delta: Dict[str, Any] = {"tool_calls": sanitized_tcs}
            if buf.pending_role is not None:
                tc_delta["role"] = buf.pending_role
                buf.pending_role = None
            out.append(self._make_chunk(buf, tc_delta))

        if buf.function_call is not None:
            fc = dict(buf.function_call)
            if isinstance(fc.get("name"), str):
                fc["name"] = self._inspect_str(fc["name"], check_entropy=False)
            if isinstance(fc.get("arguments"), str):
                fc["arguments"] = self._inspect_str(fc["arguments"])
            buf.function_call = None

            fc_delta: Dict[str, Any] = {"function_call": fc}
            if buf.pending_role is not None:
                fc_delta["role"] = buf.pending_role
                buf.pending_role = None
            out.append(self._make_chunk(buf, fc_delta))

        out.extend(self._flush_metadata(buf))
        return out

    def process_chunk(self, chunk_json: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process one parsed SSE chunk and return zero or more sanitized chunks ready to emit."""
        validate_completion(chunk_json, streaming=True)
        choices = chunk_json.get("choices") or []
        for choice in choices:
            idx = choice.get("index", 0)
            if idx in self.finished_choices:
                raise UpstreamProtocolError("Upstream sent data after finishing a choice")
            self.seen_choices.add(idx)
            if choice.get("finish_reason") is not None:
                self.finished_choices.add(idx)
        if isinstance(chunk_json.get("usage"), dict):
            self.usage = chunk_json["usage"]

        if not self.inspect_responses:
            return [chunk_json]

        if not choices:
            # Usage/metadata events are not boundaries in generated text.
            return [self._inspect_json(chunk_json)]

        emitted: List[Dict[str, Any]] = []
        extra_chunk_fields = {
            k: v
            for k, v in chunk_json.items()
            if k not in ("id", "object", "created", "model", "system_fingerprint", "choices")
        }

        for choice_number, choice in enumerate(choices):
            if not isinstance(choice, dict):
                continue
            idx = choice.get("index", 0)
            if not isinstance(idx, int):
                idx = 0
            buf = self._get_choice_buf(idx, chunk_json)
            delta = choice.get("delta")
            extra_choice = {k: v for k, v in choice.items()
                            if k not in ("index", "delta", "finish_reason")}
            chunk_fields = extra_chunk_fields if choice_number == 0 else {}
            if extra_choice or chunk_fields:
                buf.metadata_events.append((extra_choice, chunk_fields))

            if isinstance(delta, dict):
                if isinstance(delta.get("role"), str):
                    buf.pending_role = delta["role"]
                if isinstance(delta.get("content"), str):
                    buf.content += delta["content"]
                if isinstance(delta.get("reasoning_content"), str):
                    buf.reasoning_content += delta["reasoning_content"]
                if isinstance(delta.get("refusal"), str):
                    buf.refusal += delta["refusal"]
                if isinstance(delta.get("tool_calls"), list):
                    self._accumulate_tool_calls(buf, delta["tool_calls"])
                if isinstance(delta.get("function_call"), dict):
                    self._accumulate_function_call(buf, delta["function_call"])

                # Text extensions are deltas too: inspect after joining fragments.
                for key, val in delta.items():
                    if key in ("role", "content", "reasoning_content", "refusal", "tool_calls", "function_call"):
                        continue
                    if self._inspect_str(key, check_entropy=False) != key:
                        raise UpstreamProtocolError("Upstream delta contains a sensitive property name")
                    if isinstance(val, str):
                        if buf.extra_scalars.get(key) is not None:
                            raise UpstreamProtocolError("Upstream delta field changed type")
                        buf.extra_scalars.pop(key, None)
                        buf.extra_text[key] = buf.extra_text.get(key, "") + val
                    elif val is None or isinstance(val, (bool, int, float)):
                        if key in buf.extra_text and val is not None:
                            raise UpstreamProtocolError("Upstream delta field changed type")
                        if key not in buf.extra_text:
                            buf.extra_scalars[key] = val
                    else:
                        raise UpstreamProtocolError("Unsupported structured delta extension; use text or tool_calls")

            finish_reason = choice.get("finish_reason")
            if finish_reason is not None:
                emitted.extend(self._flush_choice(buf))
                emitted.append(
                    self._make_chunk(
                        buf,
                        delta={},
                        finish_reason=finish_reason,
                    )
                )
            else:
                emitted.extend(self._flush_safe_text_prefixes(buf))

        return emitted

    def flush_all(self) -> List[Dict[str, Any]]:
        """Flush all remaining buffered content and tool arguments at stream completion."""
        if not self.inspect_responses:
            return []
        emitted: List[Dict[str, Any]] = []
        for idx in sorted(self.choices):
            emitted.extend(self._flush_choice(self.choices[idx]))
        return emitted
