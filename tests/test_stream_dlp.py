"""Regression cases for stream boundaries, tool names and preserved metadata."""

import json

import pytest

from app.models.policy import PolicyMode
from app.security.stream_dlp import StreamingDlpSanitizer
from app.security.upstream_protocol import UpstreamProtocolError


SECRET = "AKIAIOSFODNN7EXAMPLE"  # AWS documentation's fictitious example key.


def chunk(delta, **choice_fields):
    return {"choices": [{"index": 0, "delta": delta, **choice_fields}]}


def collect_deltas(events):
    return [choice["delta"] for event in events for choice in event.get("choices", [])]


@pytest.mark.parametrize("mode", [PolicyMode.REDACT, PolicyMode.BLOCK, PolicyMode.ALLOW])
@pytest.mark.parametrize("field", ["content", "reasoning_content", "refusal", "custom_text"])
def test_usage_event_cannot_split_a_secret(mode, field):
    sanitizer = StreamingDlpSanitizer(mode, True)
    events = sanitizer.process_chunk(chunk({field: SECRET[:8]}))
    usage = {"choices": [], "usage": {"completion_tokens": 2}}
    events += sanitizer.process_chunk(usage)
    # Metadata must not emit the unfinished text fragment.
    assert not any(field in delta for delta in collect_deltas(events))
    events += sanitizer.process_chunk(chunk({field: SECRET[8:]}, finish_reason="stop"))
    text = "".join(delta.get(field, "") for delta in collect_deltas(events))
    assert text == (SECRET if mode == PolicyMode.ALLOW else "[REDACTED_AWS_KEY]")
    assert any(f.type == "AWS_KEY" for f in sanitizer.response_findings)
    assert usage in events
    assert sanitizer.usage == usage["usage"]


@pytest.mark.parametrize("legacy", [False, True])
def test_split_legitimate_tool_name_survives_but_arguments_are_inspected(legacy):
    sanitizer = StreamingDlpSanitizer(PolicyMode.REDACT, True)
    events = []
    for name, arguments in [("get_customer_", '{"key":"' + SECRET[:8]),
                            ("billing_information", SECRET[8:] + '"}')]:
        function = {"name": name, "arguments": arguments}
        delta = {"function_call": function} if legacy else {
            "tool_calls": [{"index": 0, "type": "function", "function": function}]
        }
        events += sanitizer.process_chunk(chunk(delta))
    events += sanitizer.process_chunk(chunk({}, finish_reason="tool_calls"))
    functions = [delta["function_call"] if legacy else delta["tool_calls"][0]["function"]
                 for delta in collect_deltas(events)
                 if ("function_call" if legacy else "tool_calls") in delta]
    assert functions == [{"name": "get_customer_billing_information",
                          "arguments": '{"key":"[REDACTED_AWS_KEY]"}'}]


def test_safe_custom_text_choice_metadata_and_logprobs_are_preserved():
    sanitizer = StreamingDlpSanitizer(PolicyMode.REDACT, True)
    logprobs = {"content": [{"token": "Hello", "logprob": -0.1,
                             "bytes": list(b"Hello"), "top_logprobs": []}]}
    first = chunk({"content": "Hello", "custom_text": "safe supplemental "},
                  logprobs=logprobs, custom_score=0.9)
    first["service_tier"] = "default"
    events = sanitizer.process_chunk(first)
    events += sanitizer.process_chunk(chunk({"custom_text": "text"}, finish_reason="stop"))
    deltas = collect_deltas(events)
    assert "".join(d.get("content", "") for d in deltas) == "Hello"
    assert "".join(d.get("custom_text", "") for d in deltas) == "safe supplemental text"
    choices = [c for event in events for c in event["choices"]]
    assert [c["logprobs"] for c in choices if "logprobs" in c] == [logprobs]
    assert [c["custom_score"] for c in choices if "custom_score" in c] == [0.9]
    assert [e["service_tier"] for e in events if "service_tier" in e] == ["default"]
    assert not sanitizer.redacted


@pytest.mark.parametrize("bytes_only", [False, True])
def test_logprob_tokens_and_bytes_cannot_reconstruct_a_secret(bytes_only):
    sanitizer = StreamingDlpSanitizer(PolicyMode.REDACT, True)
    events = []
    for part in [SECRET[:8], SECRET[8:]]:
        # Harmless content, but token metadata itself contains a split secret.
        logprobs = {"content": [{"token": "?" if bytes_only else part,
                                 "bytes": list(part.encode()), "logprob": -0.1,
                                 "top_logprobs": [{"token": "alternative", "logprob": -1}]}]}
        events += sanitizer.process_chunk(chunk({"content": "Hello "}, logprobs=logprobs))
    events += sanitizer.process_chunk(chunk({}, finish_reason="stop"))
    metadata_choices = [c for e in events for c in e["choices"] if "logprobs" in c]
    assert len(metadata_choices) == 2
    assert all(c["logprobs"] is None and c["gatekeep_logprobs_redacted"] for c in metadata_choices)
    assert any(f.type == "AWS_KEY" for f in sanitizer.response_findings)
    assert SECRET[:8] not in json.dumps(events)


def test_multiple_choices_keep_separate_buffers_and_metadata():
    sanitizer = StreamingDlpSanitizer(PolicyMode.REDACT, True)
    events = sanitizer.process_chunk({"choices": [
        {"index": 0, "delta": {"content": SECRET[:8]}},
        {"index": 1, "delta": {"content": "Hello"}, "finish_reason": "stop"},
    ], "service_tier": "default"})
    assert not sanitizer.is_complete
    events += sanitizer.process_chunk(chunk({"content": SECRET[8:]}, finish_reason="stop"))
    assert sanitizer.is_complete
    text = {index: "".join(c["delta"].get("content", "") for e in events
                          for c in e["choices"] if c["index"] == index) for index in (0, 1)}
    assert text == {0: "[REDACTED_AWS_KEY]", 1: "Hello"}
    assert sum("service_tier" in e for e in events) == 1


def test_structured_delta_extension_fails_explicitly_instead_of_disappearing():
    sanitizer = StreamingDlpSanitizer(PolicyMode.REDACT, True)
    with pytest.raises(UpstreamProtocolError, match="Unsupported structured delta extension"):
        sanitizer.process_chunk(chunk({"custom_object": {"value": "hello"}}))


def test_inspection_disabled_preserves_extensions_but_still_detects_provider_errors():
    sanitizer = StreamingDlpSanitizer(PolicyMode.REDACT, False)
    original = chunk({"custom_object": {"value": SECRET}}, finish_reason="stop")
    assert sanitizer.process_chunk(original) == [original]
    assert sanitizer.is_complete
    with pytest.raises(UpstreamProtocolError, match="generation error"):
        sanitizer.process_chunk({"error": {"message": "failed"}})
