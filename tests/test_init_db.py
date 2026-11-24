import boto3
from moto import mock_aws
import pytest

from scripts.init_db import init_dynamodb_table


def test_init_dynamodb_script():
    with mock_aws():
        table_name = "gatekeep-provision-test"
        region = "us-east-1"

        # 1. Provision new table
        res = init_dynamodb_table(table_name=table_name, region=region)
        assert res is not None

        # Verify table exists in DynamoDB
        client = boto3.client("dynamodb", region_name=region)
        desc = client.describe_table(TableName=table_name)["Table"]
        assert desc["TableName"] == table_name
        assert desc["BillingModeSummary"]["BillingMode"] == "PAY_PER_REQUEST"

        # Verify key schema
        key_names = {k["AttributeName"]: k["KeyType"] for k in desc["KeySchema"]}
        assert key_names == {"PK": "HASH", "SK": "RANGE"}

        # Verify GSI1
        gsis = desc.get("GlobalSecondaryIndexes", [])
        assert len(gsis) == 1
        assert gsis[0]["IndexName"] == "GSI1"

        # Verify TTL
        ttl_desc = client.describe_time_to_live(TableName=table_name)["TimeToLiveDescription"]
        assert ttl_desc["TimeToLiveStatus"] == "ENABLED"
        assert ttl_desc["AttributeName"] == "ttl"

        # 2. Idempotent re-run on existing table
        res_existing = init_dynamodb_table(table_name=table_name, region=region)
        assert res_existing["TableName"] == table_name
