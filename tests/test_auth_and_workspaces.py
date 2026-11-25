import pytest
from httpx import AsyncClient

from app.core.security import hash_api_key
from app.repositories.in_memory import repo


@pytest.mark.asyncio
async def test_user_registration_and_login(async_client: AsyncClient):
    # 1. Register new user
    reg_resp = await async_client.post(
        "/api/auth/register",
        json={"email": "alice@example.com", "password": "securepassword123"},
    )
    assert reg_resp.status_code == 201
    data = reg_resp.json()
    assert "access_token" in data
    assert data["user"]["email"] == "alice@example.com"
    token = data["access_token"]

    # 2. Duplicate registration fails
    dup_resp = await async_client.post(
        "/api/auth/register",
        json={"email": "alice@example.com", "password": "securepassword123"},
    )
    assert dup_resp.status_code == 400

    # 3. Successful login
    login_resp = await async_client.post(
        "/api/auth/login",
        json={"email": "alice@example.com", "password": "securepassword123"},
    )
    assert login_resp.status_code == 200
    assert "access_token" in login_resp.json()

    # 4. Failed login with wrong password
    bad_login = await async_client.post(
        "/api/auth/login",
        json={"email": "alice@example.com", "password": "wrongpassword"},
    )
    assert bad_login.status_code == 401

    # 5. Access /api/auth/me with token
    me_resp = await async_client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == "alice@example.com"

    # 6. Access /api/auth/me without token -> 401
    unauth_resp = await async_client.get("/api/auth/me")
    assert unauth_resp.status_code == 401


@pytest.mark.asyncio
async def test_workspace_crud_and_policy(async_client: AsyncClient):
    # Register user
    reg = await async_client.post(
        "/api/auth/register",
        json={"email": "bob@example.com", "password": "password1234"},
    )
    token = reg.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Create workspace
    create_ws = await async_client.post(
        "/api/workspaces",
        headers=headers,
        json={"name": "Bob's Dev Workspace"},
    )
    assert create_ws.status_code == 201
    ws = create_ws.json()
    assert ws["name"] == "Bob's Dev Workspace"
    ws_id = ws["id"]

    # List workspaces
    list_ws = await async_client.get("/api/workspaces", headers=headers)
    assert list_ws.status_code == 200
    assert len(list_ws.json()) == 1
    assert list_ws.json()[0]["id"] == ws_id

    # Get initial default policy
    get_pol = await async_client.get(f"/api/workspaces/{ws_id}/policy", headers=headers)
    assert get_pol.status_code == 200
    pol_data = get_pol.json()
    assert pol_data["mode"] == "REDACT"
    assert pol_data["block_injections"] is True
    assert pol_data["has_upstream_api_key"] is False

    # Update policy with encrypted BYOK key and BLOCK mode
    raw_upstream_key = "nvapi-secret-test-nemotron-key-9999"
    put_pol = await async_client.put(
        f"/api/workspaces/{ws_id}/policy",
        headers=headers,
        json={
            "mode": "BLOCK",
            "block_injections": True,
            "upstream_base_url": "https://integrate.api.nvidia.com/v1",
            "upstream_api_key": raw_upstream_key,
        },
    )
    assert put_pol.status_code == 200
    updated_pol = put_pol.json()
    assert updated_pol["mode"] == "BLOCK"
    assert updated_pol["has_upstream_api_key"] is True
    # Verify raw secret is NOT leaked in response
    assert raw_upstream_key not in put_pol.text

    # Verify at rest in repository the key is encrypted and not plaintext
    stored_policy = await repo.get_policy(ws_id)
    assert stored_policy is not None
    assert stored_policy.encrypted_upstream_api_key is not None
    assert stored_policy.encrypted_upstream_api_key != raw_upstream_key


@pytest.mark.asyncio
async def test_workspace_api_key_lifecycle(async_client: AsyncClient):
    # Register user and workspace
    reg = await async_client.post(
        "/api/auth/register",
        json={"email": "carol@example.com", "password": "password1234"},
    )
    token = reg.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    ws = (
        await async_client.post(
            "/api/workspaces",
            headers=headers,
            json={"name": "Carol Workspace"},
        )
    ).json()
    ws_id = ws["id"]

    # 1. Create Gateway API Key
    key_resp = await async_client.post(
        f"/api/workspaces/{ws_id}/keys",
        headers=headers,
        json={"name": "Carol Live App Key"},
    )
    assert key_resp.status_code == 201
    key_data = key_resp.json()
    key_id = key_data["id"]
    plaintext_key = key_data["api_key"]
    assert plaintext_key.startswith("gw_live_")

    # Verify key hash in repository (storage ONLY as SHA-256 hash)
    expected_hash = hash_api_key(plaintext_key)
    stored_key = await repo.get_api_key_by_id(key_id, ws_id)
    assert stored_key is not None
    assert stored_key.key_hash == expected_hash

    # 2. List keys (plaintext key must NOT appear)
    list_keys = await async_client.get(f"/api/workspaces/{ws_id}/keys", headers=headers)
    assert list_keys.status_code == 200
    keys_list = list_keys.json()
    assert len(keys_list) == 1
    assert keys_list[0]["id"] == key_id
    assert keys_list[0]["is_revoked"] is False
    assert plaintext_key not in list_keys.text

    # 3. Revoke key
    del_resp = await async_client.delete(f"/api/workspaces/{ws_id}/keys/{key_id}", headers=headers)
    assert del_resp.status_code == 200
    assert del_resp.json()["revoked"] is True

    # 4. Verify status is revoked
    list_after_revoke = await async_client.get(f"/api/workspaces/{ws_id}/keys", headers=headers)
    assert list_after_revoke.json()[0]["is_revoked"] is True


@pytest.mark.asyncio
async def test_api_key_creation_rejects_credential_shaped_names(async_client: AsyncClient):
    reg = await async_client.post(
        "/api/auth/register",
        json={"email": "keylabel@example.com", "password": "password1234"},
    )
    token = reg.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    ws = (
        await async_client.post(
            "/api/workspaces",
            headers=headers,
            json={"name": "Key Label WS"},
        )
    ).json()
    ws_id = ws["id"]

    bad_names = [
        "sk-proj-abc123xyz45678901234567890",
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
        "nvapi-1234567890abcdef1234567890",
        "AIzaSyD1234567890abcdef1234567890",
        "gw_live_1234567890abcdef1234567890abcdef",
        "9b7d3f82a1c4e650d8f2b3a4c5e6f7a8",
        "A" * 40,
    ]
    for bad_name in bad_names:
        resp = await async_client.post(
            f"/api/workspaces/{ws_id}/keys",
            headers=headers,
            json={"name": bad_name},
        )
        assert resp.status_code == 422, f"Credential-like name should be rejected: {bad_name}"

    for valid_name in ("Production App Key", "production-backend-service"):
        resp = await async_client.post(
            f"/api/workspaces/{ws_id}/keys",
            headers=headers,
            json={"name": valid_name},
        )
        assert resp.status_code == 201, f"Valid label rejected: {valid_name}"


@pytest.mark.asyncio
async def test_recruiter_demo_session_provisioning(async_client: AsyncClient):
    """Verify frictionless 10-second recruiter demo session generation."""
    resp = await async_client.post("/api/auth/demo")
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["user"]["email"] == "demo@gatekeep.ai"
    assert data["demo_workspace_id"] is not None
    assert data["demo_api_key"].startswith("gw_live_")

    # Verify repeated calls return the same session idempotently
    resp2 = await async_client.post("/api/auth/demo")
    assert resp2.status_code == 200
    assert resp2.json()["demo_workspace_id"] == data["demo_workspace_id"]
    assert resp2.json()["demo_api_key"] != data["demo_api_key"]
