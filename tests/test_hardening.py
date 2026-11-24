import httpx
import pytest
import respx
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.repositories.in_memory import repo
from app.security.rate_limiter import workspace_rate_limiter


@pytest.fixture(autouse=True)
async def reset_in_memory_db():
    await repo.reset()
    workspace_rate_limiter.reset()


@pytest.mark.asyncio
async def test_policy_hardening_fields():
    """Verify that inspect_responses and rate_limit_rpm can be retrieved and updated."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Register user
        reg_resp = await ac.post("/api/auth/register", json={
            "email": "hardening_user@example.com",
            "password": "SecurePassword123!",
        })
        token = reg_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Create workspace
        ws_resp = await ac.post("/api/workspaces", json={"name": "Hardened Workspace"}, headers=headers)
        ws_id = ws_resp.json()["id"]

        # Default policy should have inspect_responses=True, rate_limit_rpm=60
        pol_resp = await ac.get(f"/api/workspaces/{ws_id}/policy", headers=headers)
        assert pol_resp.status_code == 200
        pol_data = pol_resp.json()
        assert pol_data["inspect_responses"] is True
        assert pol_data["rate_limit_rpm"] == 60

        # Update policy hardening fields
        update_resp = await ac.put(f"/api/workspaces/{ws_id}/policy", json={
            "inspect_responses": False,
            "rate_limit_rpm": 15,
        }, headers=headers)
        assert update_resp.status_code == 200
        updated_data = update_resp.json()
        assert updated_data["inspect_responses"] is False
        assert updated_data["rate_limit_rpm"] == 15


@pytest.mark.asyncio
async def test_workspace_rate_limiter():
    """Verify that requests exceeding workspace RPM limit are rejected with HTTP 429."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Setup tenant with rate_limit_rpm = 2
        reg_resp = await ac.post("/api/auth/register", json={
            "email": "ratelimit_user@example.com",
            "password": "SecurePassword123!",
        })
        token = reg_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        ws_resp = await ac.post("/api/workspaces", json={"name": "Rate Limited Workspace"}, headers=headers)
        ws_id = ws_resp.json()["id"]

        # Set rate limit to 2 RPM and configure upstream key
        await ac.put(f"/api/workspaces/{ws_id}/policy", json={
            "rate_limit_rpm": 2,
            "upstream_api_key": "nvapi-test-key-mock",
        }, headers=headers)

        # Create API key
        key_resp = await ac.post(f"/api/workspaces/{ws_id}/keys", json={"name": "RL Key"}, headers=headers)
        gateway_key = key_resp.json()["api_key"]
        gw_headers = {"Authorization": f"Bearer {gateway_key}"}

        with respx.mock(assert_all_called=False) as respx_mock:
            respx_mock.post("https://integrate.api.nvidia.com/v1/chat/completions").mock(
                return_value=httpx.Response(200, json={
                    "id": "chatcmpl-test",
                    "object": "chat.completion",
                    "created": 123456789,
                    "model": "nvidia/llama-3.1-nemotron-70b-instruct",
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hello!"}}],
                })
            )

            # Request 1: Allowed
            r1 = await ac.post("/v1/chat/completions", json={
                "model": "nvidia/llama-3.1-nemotron-70b-instruct",
                "messages": [{"role": "user", "content": "Req 1"}],
            }, headers=gw_headers)
            assert r1.status_code == 200

            # Request 2: Allowed
            r2 = await ac.post("/v1/chat/completions", json={
                "model": "nvidia/llama-3.1-nemotron-70b-instruct",
                "messages": [{"role": "user", "content": "Req 2"}],
            }, headers=gw_headers)
            assert r2.status_code == 200

            # Request 3: Blocked by Rate Limiter (HTTP 429)
            r3 = await ac.post("/v1/chat/completions", json={
                "model": "nvidia/llama-3.1-nemotron-70b-instruct",
                "messages": [{"role": "user", "content": "Req 3"}],
            }, headers=gw_headers)
            assert r3.status_code == 429
            assert "Rate limit exceeded" in r3.json()["detail"]
            assert "Retry-After" in r3.headers


@pytest.mark.asyncio
async def test_response_dlp_redaction():
    """Verify that when upstream LLM leaks sensitive PII or secrets, GateKeep redacts it before returning."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Setup tenant with inspect_responses=True
        reg_resp = await ac.post("/api/auth/register", json={
            "email": "dlp_user@example.com",
            "password": "SecurePassword123!",
        })
        token = reg_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        ws_resp = await ac.post("/api/workspaces", json={"name": "DLP Workspace"}, headers=headers)
        ws_id = ws_resp.json()["id"]

        await ac.put(f"/api/workspaces/{ws_id}/policy", json={
            "inspect_responses": True,
            "upstream_api_key": "nvapi-test-key-mock",
        }, headers=headers)

        key_resp = await ac.post(f"/api/workspaces/{ws_id}/keys", json={"name": "DLP Key"}, headers=headers)
        gateway_key = key_resp.json()["api_key"]
        gw_headers = {"Authorization": f"Bearer {gateway_key}"}

        # Mock upstream response containing leaked AWS key and customer email
        leaked_response_text = "Here is the internal credential: AKIAIOSFODNN7EXAMPLE and contact admin@corp.internal"
        with respx.mock(assert_all_called=False) as respx_mock:
            respx_mock.post("https://integrate.api.nvidia.com/v1/chat/completions").mock(
                return_value=httpx.Response(200, json={
                    "id": "chatcmpl-dlp",
                    "object": "chat.completion",
                    "created": 123456789,
                    "model": "nvidia/llama-3.1-nemotron-70b-instruct",
                    "choices": [{
                        "index": 0,
                        "message": {"role": "assistant", "content": leaked_response_text},
                    }],
                })
            )

            resp = await ac.post("/v1/chat/completions", json={
                "model": "nvidia/llama-3.1-nemotron-70b-instruct",
                "messages": [{"role": "user", "content": "What is the secret?"}],
            }, headers=gw_headers)

            assert resp.status_code == 200
            data = resp.json()

            # Output content must be sanitized!
            content = data["choices"][0]["message"]["content"]
            assert "AKIAIOSFODNN7EXAMPLE" not in content
            assert "[REDACTED_AWS_KEY]" in content
            assert "admin@corp.internal" not in content
            assert "[REDACTED_EMAIL]" in content

            # aegisgate_meta telemetry must reflect response findings
            meta = data["aegisgate_meta"]
            assert meta["response_findings_count"] >= 2
            assert any(f["category"] == "SECRET" or f["type"] == "AWS_KEY" for f in meta["response_findings"])
            assert any(f["category"] == "PII" or f["type"] == "EMAIL" for f in meta["response_findings"])

            # Audit log must reflect findings
            logs_resp = await ac.get(f"/api/workspaces/{ws_id}/logs", headers=headers)
            assert logs_resp.status_code == 200
            logs = logs_resp.json()
            assert len(logs) == 1
            assert logs[0]["findings_count"] >= 2


@pytest.mark.asyncio
async def test_demo_workspace_mock_response():
    """Verify that demo workspace responds cleanly without needing an external LLM key."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Create user & workspace with demo prefix or default
        reg_resp = await ac.post("/api/auth/register", json={
            "email": "demo_tester@example.com",
            "password": "SecurePassword123!",
        })
        token = reg_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        ws_resp = await ac.post("/api/workspaces", json={"name": "Demo Evaluation"}, headers=headers)
        ws_id = ws_resp.json()["id"]

        # Configure upstream base url to demo mock
        await ac.put(f"/api/workspaces/{ws_id}/policy", json={
            "upstream_base_url": "https://demo.gatekeep.local/v1",
        }, headers=headers)

        key_resp = await ac.post(f"/api/workspaces/{ws_id}/keys", json={"name": "Demo Key"}, headers=headers)
        gateway_key = key_resp.json()["api_key"]
        gw_headers = {"Authorization": f"Bearer {gateway_key}"}

        # Send request without any upstream mock - should be handled by GateKeep demo mock handler
        resp = await ac.post("/v1/chat/completions", json={
            "model": "nvidia/llama-3.1-nemotron-70b-instruct",
            "messages": [{"role": "user", "content": "My contact is test@example.com"}],
        }, headers=gw_headers)

        assert resp.status_code == 200
        data = resp.json()
        assert "choices" in data
        assert "GateKeep Gateway Demo Response" in data["choices"][0]["message"]["content"]
        assert data["aegisgate_meta"]["findings_count"] >= 1
