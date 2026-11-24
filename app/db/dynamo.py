import os
import time
from decimal import Decimal
from typing import Any, Dict, Optional
import boto3
from botocore.exceptions import ClientError

from app.config import settings


def floats_to_decimals(obj: Any) -> Any:
    """Recursively converts Python floats to Decimal for DynamoDB serialization."""
    if isinstance(obj, float):
        return Decimal(str(round(obj, 4)))
    elif isinstance(obj, dict):
        return {k: floats_to_decimals(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [floats_to_decimals(v) for v in obj]
    return obj


def decimals_to_floats(obj: Any) -> Any:
    """Recursively converts DynamoDB Decimals back to Python floats."""
    if isinstance(obj, Decimal):
        # Convert to int if whole number, otherwise float
        return int(obj) if obj % 1 == 0 else float(obj)
    elif isinstance(obj, dict):
        return {k: decimals_to_floats(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [decimals_to_floats(v) for v in obj]
    return obj


def get_dynamo_client():
    """Initializes and returns boto3 DynamoDB client with configured settings."""
    kwargs: Dict[str, Any] = {"region_name": settings.AWS_REGION}
    if settings.DYNAMODB_ENDPOINT_URL:
        kwargs["endpoint_url"] = settings.DYNAMODB_ENDPOINT_URL
    if settings.AWS_ACCESS_KEY_ID and settings.AWS_SECRET_ACCESS_KEY:
        kwargs["aws_access_key_id"] = settings.AWS_ACCESS_KEY_ID
        kwargs["aws_secret_access_key"] = settings.AWS_SECRET_ACCESS_KEY
    return boto3.client("dynamodb", **kwargs)


def get_dynamo_resource():
    """Initializes and returns boto3 DynamoDB resource with configured settings."""
    kwargs: Dict[str, Any] = {"region_name": settings.AWS_REGION}
    if settings.DYNAMODB_ENDPOINT_URL:
        kwargs["endpoint_url"] = settings.DYNAMODB_ENDPOINT_URL
    if settings.AWS_ACCESS_KEY_ID and settings.AWS_SECRET_ACCESS_KEY:
        kwargs["aws_access_key_id"] = settings.AWS_ACCESS_KEY_ID
        kwargs["aws_secret_access_key"] = settings.AWS_SECRET_ACCESS_KEY
    return boto3.resource("dynamodb", **kwargs)


def create_gatekeep_table(
    table_name: str = settings.DYNAMODB_TABLE_NAME,
    client: Optional[Any] = None,
) -> Any:
    """
    Creates the GateKeep Single-Table DynamoDB schema.
    Configured for on-demand billing (Pay-Per-Request) and 30-day TTL.
    """
    if client is None:
        client = get_dynamo_client()

    # Check if table already exists
    try:
        existing = client.describe_table(TableName=table_name)
        return existing["Table"]
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

    # Table Schema Definition
    table_definition = {
        "TableName": table_name,
        "KeySchema": [
            {"AttributeName": "PK", "KeyType": "HASH"},
            {"AttributeName": "SK", "KeyType": "RANGE"},
        ],
        "AttributeDefinitions": [
            {"AttributeName": "PK", "AttributeType": "S"},
            {"AttributeName": "SK", "AttributeType": "S"},
            {"AttributeName": "GSI1PK", "AttributeType": "S"},
            {"AttributeName": "GSI1SK", "AttributeType": "S"},
        ],
        "GlobalSecondaryIndexes": [
            {
                "IndexName": "GSI1",
                "KeySchema": [
                    {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        "BillingMode": "PAY_PER_REQUEST",
    }

    resp = client.create_table(**table_definition)

    # Enable TTL on the 'ttl' attribute
    try:
        client.update_time_to_live(
            TableName=table_name,
            TimeToLiveSpecification={
                "Enabled": True,
                "AttributeName": "ttl",
            },
        )
    except Exception:
        pass  # In some mock environments update_time_to_live might be a no-op

    return resp
