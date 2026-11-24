import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_bola_idor_workspace_isolation(async_client: AsyncClient):
    # Setup User A
    reg_a = await async_client.post(
        "/api/auth/register",
        json={"email": "usera@corp.com", "password": "passwordA1234"},
    )
    token_a = reg_a.json()["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}

    # Setup User B
    reg_b = await async_client.post(
        "/api/auth/register",
        json={"email": "userb@attacker.com", "password": "passwordB1234"},
    )
    token_b = reg_b.json()["access_token"]
    headers_b = {"Authorization": f"Bearer {token_b}"}

    # User A creates Workspace A
    ws_a = (
        await async_client.post(
            "/api/workspaces",
            headers=headers_a,
            json={"name": "Workspace A Confidential"},
        )
    ).json()
    ws_a_id = ws_a["id"]

    # User A creates a Gateway API Key in Workspace A
    key_a = (
        await async_client.post(
            f"/api/workspaces/{ws_a_id}/keys",
            headers=headers_a,
            json={"name": "Key A"},
        )
    ).json()
    key_a_id = key_a["id"]

    # User B creates Workspace B
    ws_b = (
        await async_client.post(
            "/api/workspaces",
            headers=headers_b,
            json={"name": "Workspace B"},
        )
    ).json()
    ws_b_id = ws_b["id"]

    # BOLA / IDOR Verification: User B attempts unauthorized actions on Workspace A

    # 1. User B tries to view Workspace A details -> 403 Forbidden
    resp = await async_client.get(f"/api/workspaces/{ws_a_id}", headers=headers_b)
    assert resp.status_code == 403

    # 2. User B tries to view Workspace A policy -> 403 Forbidden
    resp = await async_client.get(f"/api/workspaces/{ws_a_id}/policy", headers=headers_b)
    assert resp.status_code == 403

    # 3. User B tries to modify Workspace A policy -> 403 Forbidden
    resp = await async_client.put(
        f"/api/workspaces/{ws_a_id}/policy",
        headers=headers_b,
        json={"mode": "ALLOW", "upstream_base_url": "https://malicious.endpoint.com"},
    )
    assert resp.status_code == 403

    # 4. User B tries to generate an API key in Workspace A -> 403 Forbidden
    resp = await async_client.post(
        f"/api/workspaces/{ws_a_id}/keys",
        headers=headers_b,
        json={"name": "Rogue Key"},
    )
    assert resp.status_code == 403

    # 5. User B tries to list API keys in Workspace A -> 403 Forbidden
    resp = await async_client.get(f"/api/workspaces/{ws_a_id}/keys", headers=headers_b)
    assert resp.status_code == 403

    # 6. User B tries to delete / revoke Key A -> 403 Forbidden
    resp = await async_client.delete(
        f"/api/workspaces/{ws_a_id}/keys/{key_a_id}",
        headers=headers_b,
    )
    assert resp.status_code == 403

    # 7. User B tries to access Workspace A audit logs -> 403 Forbidden
    resp = await async_client.get(f"/api/workspaces/{ws_a_id}/logs", headers=headers_b)
    assert resp.status_code == 403

    # 8. User B workspace list strictly contains only Workspace B
    list_b = await async_client.get("/api/workspaces", headers=headers_b)
    assert list_b.status_code == 200
    b_ids = [w["id"] for w in list_b.json()]
    assert ws_b_id in b_ids
    assert ws_a_id not in b_ids
