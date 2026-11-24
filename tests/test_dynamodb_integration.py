import json

import boto3
import pytest
import respx
from httpx import AsyncClient
from moto import mock_aws

from app.db.dynamo import create_gatekeep_table
from app.repositories import set_repository
from app.repositories.dynamo import DynamoDBRepository


@pytest.fixture
def dynamodb_fastapi_env():
    """Sets up DynamoDB table and configures FastAPI to use DynamoDBRepository."""
    with mock_aws():
        client = boto3.client("dynamodb", region_name="us-east-1")
        resource = boto3.resource("dynamodb", region_name="us-east-1")
        table_name = "gatekeep-fastapi-integration"

        create_gatekeep_table(table_name=table_name, client=client)
        repo = DynamoDBRepository(table_name=table_name, dynamo_resource=resource)

        # Set as active repository for FastAPI dependency injection
        set_repository(repo)
        yield repo, resource.Table(table_name)
        set_repository(None)


@pytest.mark.asyncio
@respx.mock
async def test_dynamodb_full_e2e_flow(async_client: AsyncClient, dynamodb_fastapi_env):
    repo, raw_table = dynamodb_fastapi_env

    # Mock Upstream NVIDIA Nemotron LLM
    route = respx.post("https://integrate.api.nvidia.com/v1/chat/completions").mock(
        return_value=respx.MockResponse(
            200,
            json={
                "id": "chatcmpl-dynamo-test",
                "object": "chat.completion",
                "created": 1700000000,
                "model": "nvidia/nemotron-4-340b-instruct",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "Processed via GateKeep + DynamoDB!"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 8, "total_tokens": 18},
            },
        )
    )

    # 1. Register User in DynamoDB
    reg = await async_client.post(
        "/api/auth/register",
        json={"email": "dynamo_user@enterprise.com", "password": "SecurePassword#2026"},
    )
    assert reg.status_code == 201
    auth_data = reg.json()
    token = auth_data["access_token"]
    user_headers = {"Authorization": f"Bearer {token}"}

    # 2. Create Workspace in DynamoDB
    ws_resp = await async_client.post(
        "/api/workspaces",
        headers=user_headers,
        json={"name": "DynamoDB Enterprise Workspace"},
    )
    assert ws_resp.status_code == 201
    ws = ws_resp.json()
    ws_id = ws["id"]

    # 3. Configure Policy with BYOK encrypted upstream key
    upstream_key = "nvapi-live-enterprise-byok-key-xyz"
    pol_resp = await async_client.put(
        f"/api/workspaces/{ws_id}/policy",
        headers=user_headers,
        json={
            "mode": "REDACT",
            "block_injections": True,
            "upstream_base_url": "https://integrate.api.nvidia.com/v1",
            "upstream_api_key": upstream_key,
        },
    )
    assert pol_resp.status_code == 200
    assert pol_resp.json()["mode"] == "REDACT"
    assert pol_resp.json()["has_upstream_api_key"] is True

    # 4. Generate Gateway API Key (stored as SHA-256 in DynamoDB)
    key_resp = await async_client.post(
        f"/api/workspaces/{ws_id}/keys",
        headers=user_headers,
        json={"name": "Production Service Key"},
    )
    assert key_resp.status_code == 201
    key_data = key_resp.json()
    plaintext_key = key_data["api_key"]
    key_id = key_data["id"]

    # 5. Invoke Data Plane Proxy (/v1/chat/completions) with sensitive PII
    proxy_payload = {
        "model": "nvidia/nemotron-4-340b-instruct",
        "messages": [
            {
                "role": "user",
                "content": "Please verify user john@company.com with card 4111 1111 1111 1111 and AWS key AKIAIOSFODNN7EXAMPLE",
            }
        ],
    }

    proxy_resp = await async_client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {plaintext_key}"},
        json=proxy_payload,
    )
    assert proxy_resp.status_code == 200
    resp_json = proxy_resp.json()

    # Verify upstream was called with REDACTED content
    assert route.called
    forwarded_content = json.loads(route.calls.last.request.content)["messages"][0]["content"]
    assert "[REDACTED_EMAIL]" in forwarded_content
    assert "[REDACTED_CREDIT_CARD]" in forwarded_content
    assert "[REDACTED_AWS_KEY]" in forwarded_content

    # Verify telemetry metadata returned
    meta = resp_json["aegisgate_meta"]
    assert meta["action"] == "REDACT"
    assert meta["findings_count"] == 3

    # 6. Retrieve Audit Logs from DynamoDB via Dashboard API
    logs_resp = await async_client.get(f"/api/workspaces/{ws_id}/logs", headers=user_headers)
    assert logs_resp.status_code == 200
    logs = logs_resp.json()
    assert len(logs) == 1
    assert logs[0]["workspace_id"] == ws_id
    assert logs[0]["action"] == "REDACT"
    assert logs[0]["findings_count"] == 3
    assert logs[0]["model"] == "nvidia/nemotron-4-340b-instruct"

    # 7. Instant Revocation test in DynamoDB
    del_key = await async_client.delete(f"/api/workspaces/{ws_id}/keys/{key_id}", headers=user_headers)
    assert del_key.status_code == 200

    # Immediate rejection on revoked key
    revoked_resp = await async_client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {plaintext_key}"},
        json={"model": "nvidia/nemotron-4-340b-instruct", "messages": [{"role": "user", "content": "Hi"}]},
    )
    assert revoked_resp.status_code == 401
    assert "revoked" in revoked_resp.json()["detail"]


@pytest.mark.asyncio
async def test_dynamodb_cross_tenant_bola_idor_integration(async_client: AsyncClient, dynamodb_fastapi_env):
    """
    Proves BOLA/IDOR protection across tenants end-to-end when backed by DynamoDB.
    """
    repo, _ = dynamodb_fastapi_env

    # Register Tenant 1
    t1_reg = await async_client.post(
        "/api/auth/register",
        json={"email": "tenant1@corp.com", "password": "PasswordT1!123"},
    )
    t1_headers = {"Authorization": f"Bearer {t1_reg.json()['access_token']}"}

    # Register Tenant 2
    t2_reg = await async_client.post(
        "/api/auth/register",
        json={"email": "tenant2@attacker.com", "password": "PasswordT2!123"},
    )
    t2_headers = {"Authorization": f"Bearer {t2_reg.json()['access_token']}"}

    # Tenant 1 creates Workspace
    ws1 = (
        await async_client.post(
            "/api/workspaces",
            headers=t1_headers,
            json={"name": "Tenant 1 Confidential Workspace"},
        )
    ).json()
    ws1_id = ws1["id"]

    # Tenant 2 creates Workspace
    ws2 = (
        await async_client.post(
            "/api/workspaces",
            headers=t2_headers,
            json={"name": "Tenant 2 Workspace"},
        )
    ).json()
    assert ws2["id"] is not None

    # Tenant 2 attempts to view Tenant 1's workspace policy in DynamoDB -> 403 Forbidden
    resp = await async_client.get(f"/api/workspaces/{ws1_id}/policy", headers=t2_headers)
    assert resp.status_code == 403

    # Tenant 2 attempts to modify Tenant 1's policy -> 403 Forbidden
    resp = await async_client.put(
        f"/api/workspaces/{ws1_id}/policy",
        headers=t2_headers,
        json={"mode": "ALLOW"},
    )
    assert resp.status_code == 403

    # Tenant 2 attempts to create an API key in Tenant 1's workspace -> 403 Forbidden
    resp = await async_client.post(
        f"/api/workspaces/{ws1_id}/keys",
        headers=t2_headers,
        json={"name": "Attacker Injected Key"},
    )
    assert resp.status_code == 403

    # Tenant 2 attempts to read Tenant 1's audit logs -> 403 Forbidden
    resp = await async_client.get(f"/api/workspaces/{ws1_id}/logs", headers=t2_headers)
    assert resp.status_code == 403
