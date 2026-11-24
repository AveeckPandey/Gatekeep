"""Server-owned OpenAI-compatible provider registry.

Keys stay in environment variables; callers can only choose configured aliases.
"""

import json
import os
from typing import Any

from dotenv import dotenv_values

from app.config import settings
from app.security.ssrf import validate_upstream_url


def configured_providers() -> dict[str, dict[str, Any]]:
    try:
        registry = json.loads(settings.UPSTREAM_PROVIDERS)
    except json.JSONDecodeError as exc:
        raise ValueError("UPSTREAM_PROVIDERS must be valid JSON") from exc
    if not isinstance(registry, dict):
        raise ValueError("UPSTREAM_PROVIDERS must be a JSON object")
    return registry


def resolve_provider(alias: str, workspace_id: str) -> tuple[str, str]:
    provider = configured_providers().get(alias)
    if not isinstance(provider, dict):
        raise ValueError("Unknown upstream provider")
    allowed = provider.get("allowed_workspaces", [])
    if not isinstance(allowed, list) or not all(isinstance(item, str) for item in allowed):
        raise ValueError("Invalid provider workspace permissions")
    if workspace_id not in allowed and "*" not in allowed:
        raise PermissionError("Provider is not enabled for this workspace")
    base_url = provider.get("base_url")
    key_env = provider.get("api_key_env")
    if not isinstance(base_url, str) or not isinstance(key_env, str) or not key_env.isidentifier():
        raise ValueError("Invalid upstream provider configuration")
    api_key = os.environ.get(key_env) or dotenv_values(".env").get(key_env)
    if not api_key:
        raise ValueError("Upstream provider API key is not configured")
    return validate_upstream_url(base_url), api_key
