#!/usr/bin/env python3
"""
GateKeep DynamoDB Table Provisioning Script
Creates single-table schema with on-demand (Pay-Per-Request) billing and 30-day TTL.
Supports running against AWS Cloud or DynamoDB Local (http://localhost:8000).
"""

import argparse
import sys
import boto3
from botocore.exceptions import ClientError


def init_dynamodb_table(
    table_name: str = "gatekeep-main",
    region: str = "us-east-1",
    endpoint_url: str = None,
):
    print(f"Connecting to DynamoDB [Region: {region}, Endpoint: {endpoint_url or 'AWS Default'}]...")
    kwargs = {"region_name": region}
    if endpoint_url:
        kwargs["endpoint_url"] = endpoint_url
        # If running locally without AWS credentials, provide dummy credentials
        kwargs.setdefault("aws_access_key_id", "local")
        kwargs.setdefault("aws_secret_access_key", "local")

    client = boto3.client("dynamodb", **kwargs)

    # Check if table already exists
    try:
        desc = client.describe_table(TableName=table_name)
        status = desc["Table"]["TableStatus"]
        print(f"Table '{table_name}' already exists (Status: {status}).")
        return desc["Table"]
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            print(f"Error checking table '{table_name}': {e}", file=sys.stderr)
            raise

    print(f"Creating Single-Table schema for '{table_name}' with On-Demand billing...")

    table_schema = {
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

    resp = client.create_table(**table_schema)
    print(f"Table creation requested. ARN: {resp['TableDescription']['TableArn']}")

    # Wait for table to be active if on AWS
    if not endpoint_url:
        print("Waiting for table to become ACTIVE...")
        waiter = client.get_waiter("table_exists")
        waiter.wait(TableName=table_name)
        print("Table is now ACTIVE.")

    # Enable TTL
    print("Configuring 30-day TTL on attribute 'ttl'...")
    try:
        client.update_time_to_live(
            TableName=table_name,
            TimeToLiveSpecification={
                "Enabled": True,
                "AttributeName": "ttl",
            },
        )
        print("TTL enabled successfully.")
    except Exception as ttl_err:
        print(f"TTL configuration notice: {ttl_err}")

    print(f"SUCCESS: GateKeep Single-Table '{table_name}' ready.")
    return resp


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Provision GateKeep DynamoDB Single-Table Schema")
    parser.add_argument("--table-name", default="gatekeep-main", help="DynamoDB Table Name")
    parser.add_argument("--region", default="us-east-1", help="AWS Region")
    parser.add_argument("--endpoint-url", default=None, help="Custom endpoint URL (e.g. http://localhost:8000)")

    args = parser.parse_args()
    try:
        init_dynamodb_table(
            table_name=args.table_name,
            region=args.region,
            endpoint_url=args.endpoint_url,
        )
    except Exception as exc:
        print(f"Failed to provision table: {exc}", file=sys.stderr)
        sys.exit(1)
