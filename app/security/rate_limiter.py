import threading
import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from app.config import settings


class SlidingWindowRateLimiter:
    """
    Sliding window per-workspace rate limiter.
    Enforces requests-per-minute (RPM) limit per tenant workspace.
    When DynamoDB is configured and available (production / multi-worker EC2),
    it uses atomic DynamoDB counters with TTL to enforce rate limits across
    all Uvicorn workers and EC2 instances.
    In testing or offline mode, it falls back to thread-safe local memory.
    """

    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds
        self._requests: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def _check_dynamodb(self, workspace_id: str, limit_rpm: int) -> Optional[Tuple[bool, int]]:
        """Attempts atomic rate limit check via DynamoDB single table counter."""
        if settings.REPOSITORY_BACKEND != "dynamodb":
            return None

        try:
            from app.db.dynamo import get_dynamodb_resource

            resource = get_dynamodb_resource()
            table = resource.Table(settings.DYNAMODB_TABLE_NAME)

            now = time.time()
            minute_bucket = int(now // self.window_seconds)
            ttl = int(now) + (self.window_seconds * 3)

            resp = table.update_item(
                Key={"PK": f"RATELIMIT#{workspace_id}#{minute_bucket}", "SK": "META"},
                UpdateExpression="ADD request_count :one SET #ttl = :ttl",
                ExpressionAttributeNames={"#ttl": "ttl"},
                ExpressionAttributeValues={":one": 1, ":ttl": ttl},
                ReturnValues="UPDATED_NEW",
            )
            count = int(resp.get("Attributes", {}).get("request_count", 1))
            if count > limit_rpm:
                retry_after = max(1, self.window_seconds - int(now % self.window_seconds))
                return False, retry_after
            return True, 0
        except Exception:
            # If DynamoDB is unreachable or not yet initialized, fall back to in-memory
            return None

    def check_and_record(self, workspace_id: str, limit_rpm: int) -> Tuple[bool, int]:
        """
        Check if request is allowed for workspace_id under limit_rpm.
        If allowed, records request and returns (True, 0).
        If rate limited, returns (False, retry_after_seconds).
        """
        # 1. Try distributed DynamoDB rate limiting
        db_res = self._check_dynamodb(workspace_id, limit_rpm)
        if db_res is not None:
            return db_res

        # 2. Local in-memory sliding window
        now = time.time()
        window_start = now - self.window_seconds

        with self._lock:
            timestamps = self._requests[workspace_id]
            valid_timestamps = [t for t in timestamps if t > window_start]
            self._requests[workspace_id] = valid_timestamps

            if len(valid_timestamps) >= limit_rpm:
                oldest_timestamp = valid_timestamps[0]
                retry_after = max(1, int(oldest_timestamp + self.window_seconds - now + 0.99))
                return False, retry_after

            valid_timestamps.append(now)
            return True, 0

    def reset(self, workspace_id: str = None) -> None:
        """Reset rate limiter state (useful for tests)."""
        with self._lock:
            if workspace_id:
                self._requests.pop(workspace_id, None)
            else:
                self._requests.clear()


# Global singleton rate limiter instance
workspace_rate_limiter = SlidingWindowRateLimiter()
