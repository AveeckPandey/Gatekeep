import time
from datetime import datetime, timezone
from typing import Any, List, Optional

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from app.config import settings
from app.db.dynamo import (
    decimals_to_floats,
    floats_to_decimals,
    get_dynamo_resource,
)
from app.models.api_key import ApiKey
from app.models.audit_log import AuditLog
from app.models.policy import Policy, PolicyMode
from app.models.user import User
from app.models.workspace import Workspace
from app.repositories.base import BaseRepository


class DynamoDBRepository(BaseRepository):
    """
    Amazon DynamoDB implementation of BaseRepository using Single-Table Design.
    Designed for zero-cost operation on AWS Free Tier and DynamoDB Local / Moto.
    """

    def __init__(
        self,
        table_name: str = settings.DYNAMODB_TABLE_NAME,
        dynamo_resource: Optional[Any] = None,
    ):
        self.table_name = table_name
        self._dynamo_resource = dynamo_resource or get_dynamo_resource()
        self._table = self._dynamo_resource.Table(self.table_name)

    @property
    def table(self):
        return self._table

    # User operations
    async def create_user(self, user: User) -> User:
        user_item = {
            "PK": f"USER#{user.email}",
            "SK": "META",
            "user_id": user.id,
            "email": user.email,
            "hashed_password": user.hashed_password,
            "created_at": user.created_at.isoformat(),
        }

        user_id_lookup_item = {
            "PK": f"USERID#{user.id}",
            "SK": "META",
            "user_id": user.id,
            "email": user.email,
            "hashed_password": user.hashed_password,
            "created_at": user.created_at.isoformat(),
        }

        try:
            # Conditional write ensures no duplicate user with the same email
            self.table.put_item(
                Item=user_item,
                ConditionExpression="attribute_not_exists(PK)",
            )
            self.table.put_item(Item=user_id_lookup_item)
            return user
        except ClientError as e:
            if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise ValueError("User with this email already exists")
            raise

    async def get_user_by_email(self, email: str) -> Optional[User]:
        resp = self.table.get_item(Key={"PK": f"USER#{email}", "SK": "META"})
        item = resp.get("Item")
        if not item:
            return None
        return User(
            id=item["user_id"],
            email=item["email"],
            hashed_password=item["hashed_password"],
            created_at=datetime.fromisoformat(item["created_at"]),
        )

    async def get_user_by_id(self, user_id: str) -> Optional[User]:
        resp = self.table.get_item(Key={"PK": f"USERID#{user_id}", "SK": "META"})
        item = resp.get("Item")
        if not item:
            return None
        return User(
            id=item["user_id"],
            email=item["email"],
            hashed_password=item["hashed_password"],
            created_at=datetime.fromisoformat(item["created_at"]),
        )

    # Workspace operations
    async def create_workspace(self, workspace: Workspace) -> Workspace:
        ws_item = {
            "PK": f"WORKSPACE#{workspace.id}",
            "SK": "META",
            "GSI1PK": f"USER#{workspace.owner_id}",
            "GSI1SK": f"WORKSPACE#{workspace.id}",
            "workspace_id": workspace.id,
            "owner_user_id": workspace.owner_id,
            "name": workspace.name,
            "created_at": workspace.created_at.isoformat(),
            "updated_at": workspace.updated_at.isoformat(),
        }
        self.table.put_item(Item=ws_item)

        # Create default workspace policy
        default_policy = Policy(workspace_id=workspace.id)
        await self.upsert_policy(default_policy)
        return workspace

    async def get_workspace(self, workspace_id: str) -> Optional[Workspace]:
        resp = self.table.get_item(Key={"PK": f"WORKSPACE#{workspace_id}", "SK": "META"})
        item = resp.get("Item")
        if not item:
            return None
        return Workspace(
            id=item["workspace_id"],
            name=item["name"],
            owner_id=item["owner_user_id"],
            created_at=datetime.fromisoformat(item["created_at"]),
            updated_at=datetime.fromisoformat(item["updated_at"]),
        )

    async def list_workspaces_for_user(self, owner_id: str) -> List[Workspace]:
        # Query GSI1 by user
        resp = self.table.query(
            IndexName="GSI1",
            KeyConditionExpression=Key("GSI1PK").eq(f"USER#{owner_id}")
            & Key("GSI1SK").begins_with("WORKSPACE#"),
        )
        items = resp.get("Items", [])
        return [
            Workspace(
                id=item["workspace_id"],
                name=item["name"],
                owner_id=item["owner_user_id"],
                created_at=datetime.fromisoformat(item["created_at"]),
                updated_at=datetime.fromisoformat(item["updated_at"]),
            )
            for item in items
        ]

    async def delete_workspace(self, workspace_id: str) -> bool:
        # Query all items in WORKSPACE#<ws_id> partition
        resp = self.table.query(KeyConditionExpression=Key("PK").eq(f"WORKSPACE#{workspace_id}"))
        items = resp.get("Items", [])
        if not items:
            return False

        with self.table.batch_writer() as batch:
            for it in items:
                batch.delete_item(Key={"PK": it["PK"], "SK": it["SK"]})
                # If item is an API key, also delete the APIKEY#<hash> partition item
                if it["SK"].startswith("APIKEY#") and "key_hash" in it:
                    batch.delete_item(Key={"PK": f"APIKEY#{it['key_hash']}", "SK": "META"})

        return True

    # Policy operations
    async def get_policy(self, workspace_id: str) -> Optional[Policy]:
        resp = self.table.get_item(Key={"PK": f"WORKSPACE#{workspace_id}", "SK": "POLICY#DEFAULT"})
        item = resp.get("Item")
        if not item:
            # Check if workspace exists
            ws = await self.get_workspace(workspace_id)
            if ws:
                new_policy = Policy(workspace_id=workspace_id)
                await self.upsert_policy(new_policy)
                return new_policy
            return None

        return Policy(
            workspace_id=item["workspace_id"],
            mode=PolicyMode(item["mode"]),
            block_injections=item.get("block_injections", True),
            inspect_responses=item.get("inspect_responses", True),
            rate_limit_rpm=int(item.get("rate_limit_rpm", 60)),
            upstream_base_url=item["upstream_base_url"],
            encrypted_upstream_api_key=item.get("encrypted_upstream_api_key"),
            updated_at=datetime.fromisoformat(item["updated_at"]),
        )

    async def upsert_policy(self, policy: Policy) -> Policy:
        policy.updated_at = datetime.now(timezone.utc)
        item = {
            "PK": f"WORKSPACE#{policy.workspace_id}",
            "SK": "POLICY#DEFAULT",
            "workspace_id": policy.workspace_id,
            "mode": policy.mode.value,
            "block_injections": policy.block_injections,
            "inspect_responses": policy.inspect_responses,
            "rate_limit_rpm": policy.rate_limit_rpm,
            "upstream_base_url": policy.upstream_base_url,
            "encrypted_upstream_api_key": policy.encrypted_upstream_api_key,
            "updated_at": policy.updated_at.isoformat(),
        }
        self.table.put_item(Item=item)
        return policy

    # API Key operations
    async def create_api_key(self, api_key: ApiKey) -> ApiKey:
        status_str = "REVOKED" if api_key.is_revoked else "ACTIVE"

        # Item 1: Direct SHA-256 hash lookup (Ultra fast proxy data-plane auth)
        hash_item = {
            "PK": f"APIKEY#{api_key.key_hash}",
            "SK": "META",
            "key_id": api_key.id,
            "workspace_id": api_key.workspace_id,
            "status": status_str,
            "is_revoked": api_key.is_revoked,
            "prefix": api_key.prefix,
            "name": api_key.name,
            "created_at": api_key.created_at.isoformat(),
            "last_used_at": api_key.last_used_at.isoformat() if api_key.last_used_at else None,
        }

        # Item 2: Workspace API keys collection (Control plane dashboard listing)
        ws_key_item = {
            "PK": f"WORKSPACE#{api_key.workspace_id}",
            "SK": f"APIKEY#{api_key.id}",
            "key_id": api_key.id,
            "key_hash": api_key.key_hash,
            "workspace_id": api_key.workspace_id,
            "status": status_str,
            "is_revoked": api_key.is_revoked,
            "prefix": api_key.prefix,
            "name": api_key.name,
            "created_at": api_key.created_at.isoformat(),
            "last_used_at": api_key.last_used_at.isoformat() if api_key.last_used_at else None,
        }

        self.table.put_item(Item=hash_item)
        self.table.put_item(Item=ws_key_item)
        return api_key

    async def get_api_key_by_hash(self, key_hash: str) -> Optional[ApiKey]:
        resp = self.table.get_item(Key={"PK": f"APIKEY#{key_hash}", "SK": "META"})
        item = resp.get("Item")
        if not item:
            return None

        return ApiKey(
            id=item["key_id"],
            workspace_id=item["workspace_id"],
            name=item.get("name", "Gateway Key"),
            key_hash=key_hash,
            prefix=item.get("prefix", "gw_live_..."),
            is_revoked=item.get("is_revoked", item.get("status") == "REVOKED"),
            created_at=datetime.fromisoformat(item["created_at"]),
            last_used_at=(
                datetime.fromisoformat(item["last_used_at"]) if item.get("last_used_at") else None
            ),
        )

    async def get_api_key_by_id(self, key_id: str, workspace_id: str) -> Optional[ApiKey]:
        resp = self.table.get_item(Key={"PK": f"WORKSPACE#{workspace_id}", "SK": f"APIKEY#{key_id}"})
        item = resp.get("Item")
        if not item:
            return None

        return ApiKey(
            id=item["key_id"],
            workspace_id=item["workspace_id"],
            name=item.get("name", "Gateway Key"),
            key_hash=item.get("key_hash", ""),
            prefix=item.get("prefix", "gw_live_..."),
            is_revoked=item.get("is_revoked", item.get("status") == "REVOKED"),
            created_at=datetime.fromisoformat(item["created_at"]),
            last_used_at=(
                datetime.fromisoformat(item["last_used_at"]) if item.get("last_used_at") else None
            ),
        )

    async def list_api_keys_for_workspace(self, workspace_id: str) -> List[ApiKey]:
        resp = self.table.query(
            KeyConditionExpression=Key("PK").eq(f"WORKSPACE#{workspace_id}")
            & Key("SK").begins_with("APIKEY#")
        )
        items = resp.get("Items", [])
        return [
            ApiKey(
                id=item["key_id"],
                workspace_id=item["workspace_id"],
                name=item.get("name", "Gateway Key"),
                key_hash=item.get("key_hash", ""),
                prefix=item.get("prefix", "gw_live_..."),
                is_revoked=item.get("is_revoked", item.get("status") == "REVOKED"),
                created_at=datetime.fromisoformat(item["created_at"]),
                last_used_at=(
                    datetime.fromisoformat(item["last_used_at"]) if item.get("last_used_at") else None
                ),
            )
            for item in items
        ]

    async def revoke_api_key(self, key_id: str, workspace_id: str) -> bool:
        # Look up key item to retrieve hash
        ws_key_resp = self.table.get_item(Key={"PK": f"WORKSPACE#{workspace_id}", "SK": f"APIKEY#{key_id}"})
        item = ws_key_resp.get("Item")
        if not item:
            return False

        key_hash = item.get("key_hash")

        # Update in WORKSPACE# partition
        self.table.update_item(
            Key={"PK": f"WORKSPACE#{workspace_id}", "SK": f"APIKEY#{key_id}"},
            UpdateExpression="SET is_revoked = :r, #s = :s",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":r": True, ":s": "REVOKED"},
        )

        # Update in APIKEY# partition
        if key_hash:
            self.table.update_item(
                Key={"PK": f"APIKEY#{key_hash}", "SK": "META"},
                UpdateExpression="SET is_revoked = :r, #s = :s",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":r": True, ":s": "REVOKED"},
            )

        return True

    async def update_api_key_last_used(
        self,
        key_id: str,
        workspace_id: Optional[str] = None,
        key_hash: Optional[str] = None,
    ) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        if workspace_id:
            try:
                self.table.update_item(
                    Key={"PK": f"WORKSPACE#{workspace_id}", "SK": f"APIKEY#{key_id}"},
                    UpdateExpression="SET last_used_at = :now",
                    ExpressionAttributeValues={":now": now_iso},
                )
            except Exception:
                pass
        if key_hash:
            try:
                self.table.update_item(
                    Key={"PK": f"APIKEY#{key_hash}", "SK": "META"},
                    UpdateExpression="SET last_used_at = :now",
                    ExpressionAttributeValues={":now": now_iso},
                )
            except Exception:
                pass

    # Audit Log operations
    async def create_audit_log(self, log: AuditLog) -> AuditLog:
        timestamp_str = log.created_at.strftime("%Y%m%dT%H%M%S%f")
        ttl_seconds = int(time.time()) + (30 * 86400)  # 30 days retention TTL

        # Cap findings count and details to prevent exceeding DynamoDB 400KB limit
        bounded_findings = []
        for f in (log.findings or [])[:50]:
            if isinstance(f, dict):
                f_copy = dict(f)
                if "safe_preview" in f_copy and isinstance(f_copy["safe_preview"], str):
                    f_copy["safe_preview"] = f_copy["safe_preview"][:100]
                if "details" in f_copy and isinstance(f_copy["details"], str):
                    f_copy["details"] = f_copy["details"][:200]
                bounded_findings.append(f_copy)
            else:
                bounded_findings.append(f)

        raw_item = {
            "PK": f"WORKSPACE#{log.workspace_id}",
            "SK": f"LOG#{timestamp_str}#{log.id}",
            "workspace_id": log.workspace_id,
            "log_id": log.id,
            "key_id": log.key_id,
            "model": log.model,
            "action": log.action,
            "is_blocked": log.is_blocked,
            "block_reason": log.block_reason[:500] if log.block_reason else None,
            "findings_count": log.findings_count,
            "findings": bounded_findings,
            "inspection_ms": log.inspection_ms,
            "upstream_ms": log.upstream_ms,
            "total_ms": log.total_ms,
            "prompt_tokens": log.prompt_tokens,
            "completion_tokens": log.completion_tokens,
            "created_at": log.created_at.isoformat(),
            "ttl": ttl_seconds,
        }

        # Convert floats to Decimals for DynamoDB
        dynamo_item = floats_to_decimals(raw_item)
        self.table.put_item(Item=dynamo_item)
        return log

    async def list_audit_logs_for_workspace(self, workspace_id: str, limit: int = 100) -> List[AuditLog]:
        resp = self.table.query(
            KeyConditionExpression=Key("PK").eq(f"WORKSPACE#{workspace_id}") & Key("SK").begins_with("LOG#"),
            ScanIndexForward=False,  # Reverse chronological (newest first)
            Limit=limit,
        )
        items = resp.get("Items", [])
        results: List[AuditLog] = []

        for it in items:
            clean_it = decimals_to_floats(it)
            results.append(
                AuditLog(
                    id=clean_it["log_id"],
                    workspace_id=clean_it["workspace_id"],
                    key_id=clean_it.get("key_id"),
                    model=clean_it["model"],
                    action=clean_it["action"],
                    is_blocked=clean_it.get("is_blocked", False),
                    block_reason=clean_it.get("block_reason"),
                    findings_count=clean_it.get("findings_count", 0),
                    findings=clean_it.get("findings", []),
                    inspection_ms=clean_it.get("inspection_ms", 0.0),
                    upstream_ms=clean_it.get("upstream_ms"),
                    total_ms=clean_it.get("total_ms", 0.0),
                    prompt_tokens=clean_it.get("prompt_tokens"),
                    completion_tokens=clean_it.get("completion_tokens"),
                    created_at=datetime.fromisoformat(clean_it["created_at"]),
                )
            )

        return results
