import json

import pytest

from app.config import settings
from app.core import providers


def test_provider_registry_is_workspace_scoped(monkeypatch):
    monkeypatch.setattr(settings, "UPSTREAM_PROVIDERS", json.dumps({
        "any-model-service": {
            "base_url": "https://api.example.test/v1",
            "api_key_env": "EXAMPLE_PROVIDER_KEY",
            "allowed_workspaces": ["workspace-1"],
        }
    }))
    monkeypatch.setenv("EXAMPLE_PROVIDER_KEY", "private-test-key")
    monkeypatch.setattr(providers, "validate_upstream_url", lambda url: url)

    assert providers.resolve_provider("any-model-service", "workspace-1") == (
        "https://api.example.test/v1", "private-test-key"
    )
    with pytest.raises(PermissionError):
        providers.resolve_provider("any-model-service", "workspace-2")
    with pytest.raises(ValueError):
        providers.resolve_provider("missing", "workspace-1")
