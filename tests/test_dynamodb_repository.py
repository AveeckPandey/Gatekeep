import time
from datetime import datetime, timezone
import boto3
from moto import mock_aws
import pytest

from app.core.security import encrypt_secret, hash_api_key, hash_password
from app.db.dynamo import create_gatekeep_table
from app.models.api_key import ApiKey
from app.models.audit_log import AuditLog
from app.models.policy import Policy, PolicyMode
from app.models.user import User
from app.models.workspace import Workspace
from app.repositories.dynamo import DynamoDBRepository


@pytest.fixture
def dynamodb_env():
    """Sets up a mock DynamoDB environment with the GateKeep Single-Table schema."""
    with mock_aws():
        client = boto3.client("dynamodb", region_name="us-east-1")
        resource = boto3.resource("dynamodb", region_name="us-east-1")
        table_name = "gatekeep-test-table"

        create_gatekeep_table(table_name=table_name, client=client)
        repo = DynamoDBRepository(table_name=table_name, dynamo_resource=resource)
        yield repo, resource.Table(table_name)


@pytest.mark.asyncio
async def test_dynamodb_user_persistence(dynamodb_env):
    repo, raw_table = dynamodb_env

    # 1. Create User
    pw_hash = hash_password("securepassword123")
    user = User(email="testuser@gatekeep.io", hashed_password=pw_hash)
    created = await repo.create_user(user)
    assert created.id == user.id

    # Verify Single-Table Item schema in DynamoDB: PK: USER#<email>, SK: META
    raw_item = raw_table.get_item(Key={"PK": f"USER#{user.email}", "SK": "META"}).get("Item")
    assert raw_item is not None
    assert raw_item["user_id"] == user.id
    assert raw_item["hashed_password"] == pw_hash

    # Verify secondary user id lookup item: PK: USERID#<user_id>, SK: META
    raw_uid_item = raw_table.get_item(Key={"PK": f"USERID#{user.id}", "SK": "META"}).get("Item")
    assert raw_uid_item is not None
    assert raw_uid_item["email"] == user.email

    # 2. Get User by Email & ID
    fetched_email = await repo.get_user_by_email("testuser@gatekeep.io")
    assert fetched_email is not None
    assert fetched_email.id == user.id

    fetched_id = await repo.get_user_by_id(user.id)
    assert fetched_id is not None
    assert fetched_id.email == user.email

    # 3. Duplicate email registration fails via DynamoDB condition check
    with pytest.raises(ValueError, match="already exists"):
        await repo.create_user(User(email="testuser@gatekeep.io", hashed_password="new"))


@pytest.mark.asyncio
async def test_dynamodb_workspace_and_policy_persistence(dynamodb_env):
    repo, raw_table = dynamodb_env

    user_id = "user_12345"
    ws = Workspace(name="Acme Production", owner_id=user_id)
    created_ws = await repo.create_workspace(ws)
    assert created_ws.id == ws.id

    # Verify Single-Table Workspace Item: PK: WORKSPACE#<ws_id>, SK: META
    ws_item = raw_table.get_item(Key={"PK": f"WORKSPACE#{ws.id}", "SK": "META"}).get("Item")
    assert ws_item is not None
    assert ws_item["name"] == "Acme Production"
    assert ws_item["owner_user_id"] == user_id
    assert ws_item["GSI1PK"] == f"USER#{user_id}"
    assert ws_item["GSI1SK"] == f"WORKSPACE#{ws.id}"

    # Verify Default Policy created: PK: WORKSPACE#<ws_id>, SK: POLICY#DEFAULT
    pol_item = raw_table.get_item(Key={"PK": f"WORKSPACE#{ws.id}", "SK": "POLICY#DEFAULT"}).get("Item")
    assert pol_item is not None
    assert pol_item["mode"] == "REDACT"
    assert pol_item["block_injections"] is True

    # Test GSI1 Query for list_workspaces_for_user
    user_workspaces = await repo.list_workspaces_for_user(user_id)
    assert len(user_workspaces) == 1
    assert user_workspaces[0].id == ws.id

    # Update Policy with encrypted BYOK key
    encrypted_key = encrypt_secret("nvapi-secret-key-999")
    policy = Policy(
        workspace_id=ws.id,
        mode=PolicyMode.BLOCK,
        block_injections=True,
        upstream_base_url="https://integrate.api.nvidia.com/v1",
        encrypted_upstream_api_key=encrypted_key,
    )
    await repo.upsert_policy(policy)

    updated_pol = await repo.get_policy(ws.id)
    assert updated_pol.mode == PolicyMode.BLOCK
    assert updated_pol.encrypted_upstream_api_key == encrypted_key


@pytest.mark.asyncio
async def test_dynamodb_api_key_persistence_and_revocation(dynamodb_env):
    repo, raw_table = dynamodb_env

    ws_id = "ws_test_key"
    plaintext_key = "gw_live_abcdef1234567890abcdef1234567890"
    key_hash = hash_api_key(plaintext_key)

    api_key = ApiKey(
        workspace_id=ws_id,
        name="Backend Service Key",
        key_hash=key_hash,
        prefix="gw_live_abcd...",
    )
    created_key = await repo.create_api_key(api_key)

    # 1. Verify Item in PK: APIKEY#<sha256_hash>, SK: META
    hash_item = raw_table.get_item(Key={"PK": f"APIKEY#{key_hash}", "SK": "META"}).get("Item")
    assert hash_item is not None
    assert hash_item["key_id"] == created_key.id
    assert hash_item["workspace_id"] == ws_id
    assert hash_item["status"] == "ACTIVE"
    assert hash_item["is_revoked"] is False

    # 2. Verify Item in PK: WORKSPACE#<ws_id>, SK: APIKEY#<key_id>
    ws_key_item = raw_table.get_item(Key={"PK": f"WORKSPACE#{ws_id}", "SK": f"APIKEY#{created_key.id}"}).get("Item")
    assert ws_key_item is not None
    assert ws_key_item["key_hash"] == key_hash

    # 3. Retrieve Key by Hash (Data Plane Proxy pattern)
    fetched_by_hash = await repo.get_api_key_by_hash(key_hash)
    assert fetched_by_hash is not None
    assert fetched_by_hash.id == created_key.id
    assert fetched_by_hash.is_revoked is False

    # 4. List keys for workspace (Control Plane Dashboard pattern)
    keys_list = await repo.list_api_keys_for_workspace(ws_id)
    assert len(keys_list) == 1
    assert keys_list[0].id == created_key.id

    # 5. Revoke key
    revoked = await repo.revoke_api_key(created_key.id, ws_id)
    assert revoked is True

    # Verify revoked in both items
    hash_item_revoked = raw_table.get_item(Key={"PK": f"APIKEY#{key_hash}", "SK": "META"}).get("Item")
    assert hash_item_revoked["status"] == "REVOKED"
    assert hash_item_revoked["is_revoked"] is True

    fetched_after_revocation = await repo.get_api_key_by_hash(key_hash)
    assert fetched_after_revocation.is_revoked is True


@pytest.mark.asyncio
async def test_dynamodb_audit_logs_with_ttl(dynamodb_env):
    repo, raw_table = dynamodb_env

    ws_id = "ws_test_logs"
    now = datetime.now(timezone.utc)

    log1 = AuditLog(
        workspace_id=ws_id,
        model="nvidia/nemotron-4-340b-instruct",
        action="ALLOW",
        is_blocked=False,
        findings_count=0,
        inspection_ms=0.45,
        upstream_ms=120.5,
        total_ms=120.95,
        created_at=now,
    )
    await repo.create_audit_log(log1)

    # Verify raw item in DynamoDB has PK: WORKSPACE#<ws_id>, SK: LOG#... and 30-day TTL
    resp = raw_table.query(KeyConditionExpression="PK = :pk AND begins_with(SK, :sk)", ExpressionAttributeValues={":pk": f"WORKSPACE#{ws_id}", ":sk": "LOG#"})
    items = resp.get("Items", [])
    assert len(items) == 1
    item = items[0]
    assert item["action"] == "ALLOW"
    assert "ttl" in item

    # Verify TTL is ~30 days in the future
    expected_min_ttl = int(time.time()) + (29 * 86400)
    expected_max_ttl = int(time.time()) + (31 * 86400)
    assert expected_min_ttl <= item["ttl"] <= expected_max_ttl

    # Verify list_audit_logs_for_workspace
    logs = await repo.list_audit_logs_for_workspace(ws_id)
    assert len(logs) == 1
    assert logs[0].id == log1.id
    assert logs[0].inspection_ms == 0.45
    assert logs[0].upstream_ms == 120.5


@pytest.mark.asyncio
async def test_dynamodb_strict_database_tenant_isolation(dynamodb_env):
    """
    Verifies tenant isolation directly at the DynamoDB partition and query level.
    Proves that queries for Workspace A never read or leak any records belonging to Workspace B.
    """
    repo, raw_table = dynamodb_env

    user_a = "user_tenant_a"
    user_b = "user_tenant_b"

    ws_a = await repo.create_workspace(Workspace(name="Tenant A Workspace", owner_id=user_a))
    ws_b = await repo.create_workspace(Workspace(name="Tenant B Workspace", owner_id=user_b))

    # Add API keys to both workspaces
    key_a = await repo.create_api_key(
        ApiKey(
            workspace_id=ws_a.id,
            name="Key Tenant A",
            key_hash=hash_api_key("gw_live_key_a_secret_12345678901234567890"),
            prefix="gw_live_keyA...",
        )
    )
    key_b = await repo.create_api_key(
        ApiKey(
            workspace_id=ws_b.id,
            name="Key Tenant B",
            key_hash=hash_api_key("gw_live_key_b_secret_99999999999999999999"),
            prefix="gw_live_keyB...",
        )
    )

    # Add audit logs to both workspaces
    await repo.create_audit_log(
        AuditLog(
            workspace_id=ws_a.id,
            model="nvidia/nemotron-4-340b-instruct",
            action="ALLOW",
            is_blocked=False,
            total_ms=10.0,
        )
    )
    await repo.create_audit_log(
        AuditLog(
            workspace_id=ws_b.id,
            model="meta/llama-3.1-70b-instruct",
            action="BLOCK",
            is_blocked=True,
            total_ms=5.0,
        )
    )

    # 1. Partition Isolation for Workspace A
    resp_a = raw_table.query(KeyConditionExpression="PK = :pk", ExpressionAttributeValues={":pk": f"WORKSPACE#{ws_a.id}"})
    for item in resp_a.get("Items", []):
        assert item.get("workspace_id") == ws_a.id or item.get("PK") == f"WORKSPACE#{ws_a.id}"
        # Absolutely no data from Workspace B
        assert ws_b.id not in str(item)

    # 2. Partition Isolation for Workspace B
    resp_b = raw_table.query(KeyConditionExpression="PK = :pk", ExpressionAttributeValues={":pk": f"WORKSPACE#{ws_b.id}"})
    for item in resp_b.get("Items", []):
        assert item.get("workspace_id") == ws_b.id or item.get("PK") == f"WORKSPACE#{ws_b.id}"
        assert ws_a.id not in str(item)

    # 3. GSI1 User Isolation
    workspaces_user_a = await repo.list_workspaces_for_user(user_a)
    assert len(workspaces_user_a) == 1
    assert workspaces_user_a[0].id == ws_a.id
    assert workspaces_user_a[0].owner_id == user_a

    workspaces_user_b = await repo.list_workspaces_for_user(user_b)
    assert len(workspaces_user_b) == 1
    assert workspaces_user_b[0].id == ws_b.id
    assert workspaces_user_b[0].owner_id == user_b

    # 4. API Key Listing Isolation
    keys_a = await repo.list_api_keys_for_workspace(ws_a.id)
    assert len(keys_a) == 1
    assert keys_a[0].id == key_a.id
    assert keys_a[0].workspace_id == ws_a.id

    keys_b = await repo.list_api_keys_for_workspace(ws_b.id)
    assert len(keys_b) == 1
    assert keys_b[0].id == key_b.id
    assert keys_b[0].workspace_id == ws_b.id

    # 5. Audit Log Isolation
    logs_a = await repo.list_audit_logs_for_workspace(ws_a.id)
    assert len(logs_a) == 1
    assert logs_a[0].workspace_id == ws_a.id
    assert logs_a[0].model == "nvidia/nemotron-4-340b-instruct"

    logs_b = await repo.list_audit_logs_for_workspace(ws_b.id)
    assert len(logs_b) == 1
    assert logs_b[0].workspace_id == ws_b.id
    assert logs_b[0].model == "meta/llama-3.1-70b-instruct"
