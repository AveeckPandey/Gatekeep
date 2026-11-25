"""Chunk-boundary-safe DLP sanitization for OpenAI-compatible SSE streams."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.security.detector import Finding, PolicyMode, detector

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

    def _inspect_str(self, text: str) -> str:
        if not text:
            return text
        res = detector.inspect(
            text=text,
            policy_mode=self.dlp_policy_mode,
            block_injections=False,
        )
        self.inspection_ms += res.inspection_ms
        if res.findings:
            self.response_findings.extend(res.findings)
            if self.policy_mode != PolicyMode.ALLOW:
                self.redacted = True
                return res.sanitized_text
        return text

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
                        fn["name"] = self._inspect_str(fn["name"])
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
                fc["name"] = self._inspect_str(fc["name"])
            if isinstance(fc.get("arguments"), str):
                fc["arguments"] = self._inspect_str(fc["arguments"])
            buf.function_call = None

            fc_delta: Dict[str, Any] = {"function_call": fc}
            if buf.pending_role is not None:
                fc_delta["role"] = buf.pending_role
                buf.pending_role = None
            out.append(self._make_chunk(buf, fc_delta))

        return out

    def process_chunk(self, chunk_json: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process one parsed SSE chunk and return zero or more sanitized chunks ready to emit."""
        if isinstance(chunk_json.get("usage"), dict):
            self.usage = chunk_json["usage"]

        if not self.inspect_responses:
            return [chunk_json]

        choices = chunk_json.get("choices")
        if not isinstance(choices, list) or len(choices) == 0:
            emitted = self.flush_all()
            emitted.append(chunk_json)
            return emitted

        emitted: List[Dict[str, Any]] = []
        extra_chunk_fields = {
            k: v
            for k, v in chunk_json.items()
            if k not in ("id", "object", "created", "model", "system_fingerprint", "choices")
        }

        for choice in choices:
            if not isinstance(choice, dict):
                continue
            idx = choice.get("index", 0)
            if not isinstance(idx, int):
                idx = 0
            buf = self._get_choice_buf(idx, chunk_json)
            delta = choice.get("delta")

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

                # Inspect any unexpected text delta fields inline (outside buffered keys)
                for key, val in delta.items():
                    if key in ("role", "content", "reasoning_content", "refusal", "tool_calls", "function_call"):
                        continue
                    if isinstance(val, str):
                        delta[key] = self._inspect_str(val)

            finish_reason = choice.get("finish_reason")
            if finish_reason is not None:
                emitted.extend(self._flush_choice(buf))
                extra_choice = {
                    k: v
                    for k, v in choice.items()
                    if k not in ("index", "delta", "finish_reason")
                }
                emitted.append(
                    self._make_chunk(
                        buf,
                        delta={},
                        finish_reason=finish_reason,
                        extra_choice_fields=extra_choice or None,
                        extra_chunk_fields=extra_chunk_fields or None,
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
