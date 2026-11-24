#!/usr/bin/env python3
"""
GateKeep AWS Lambda & Free Tier Deployment Script
Packages FastAPI + Mangum backend, creates least-privilege IAM role,
provisions/updates AWS Lambda function, and enables Function URL with CORS.
"""

import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile

import boto3
from botocore.exceptions import ClientError
from cryptography.fernet import Fernet


FUNCTION_NAME = "gatekeep-api"
ROLE_NAME = "gatekeep-lambda-role"
TABLE_NAME = "gatekeep-main"


def get_account_id(region: str) -> str:
    sts = boto3.client("sts", region_name=region)
    return sts.get_caller_identity()["Account"]


def ensure_iam_role(account_id: str, region: str) -> str:
    """Creates least-privilege IAM role for GateKeep Lambda function."""
    iam = boto3.client("iam", region_name=region)
    table_arn = f"arn:aws:dynamodb:{region}:{account_id}:table/{TABLE_NAME}"
    index_arn = f"{table_arn}/index/*"

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }

    try:
        resp = iam.get_role(RoleName=ROLE_NAME)
        role_arn = resp["Role"]["Arn"]
        print(f"IAM Role '{ROLE_NAME}' already exists: {role_arn}")
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            print(f"Creating least-privilege IAM role '{ROLE_NAME}'...")
            resp = iam.create_role(
                RoleName=ROLE_NAME,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Description="Least-privilege execution role for GateKeep LLM Security Gateway Lambda",
            )
            role_arn = resp["Role"]["Arn"]
            print(f"Created role: {role_arn}")
            time.sleep(8)  # Wait for IAM role propagation
        else:
            raise

    # Attach least-privilege policy strictly scoped to gatekeep-main
    least_privilege_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DynamoDBSingleTableAccess",
                "Effect": "Allow",
                "Action": [
                    "dynamodb:GetItem",
                    "dynamodb:PutItem",
                    "dynamodb:UpdateItem",
                    "dynamodb:DeleteItem",
                    "dynamodb:Query",
                    "dynamodb:DescribeTable",
                ],
                "Resource": [table_arn, index_arn],
            },
            {
                "Sid": "CloudWatchLogsAccess",
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                "Resource": "arn:aws:logs:*:*:*",
            },
        ],
    }

    iam.put_role_policy(
        RoleName=ROLE_NAME,
        PolicyName="GateKeepDynamoDBLeastPrivilegePolicy",
        PolicyDocument=json.dumps(least_privilege_policy),
    )
    print("Attached least-privilege DynamoDB policy.")
    return role_arn


def build_deployment_package(include_deps: bool = False) -> str:
    """Builds zip package containing application code (and optional Linux binary dependencies)."""
    workspace_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    build_dir = tempfile.mkdtemp(prefix="gatekeep_pkg_")
    zip_path = os.path.join(tempfile.gettempdir(), f"gatekeep_{int(time.time())}.zip")

    print(f"Building deployment package in {build_dir}...")

    if include_deps:
        print("Installing Linux x86_64 production dependencies into package...")
        subprocess.check_call([
            sys.executable,
            "-m",
            "pip",
            "install",
            "mangum",
            "fastapi",
            "httpx",
            "pydantic",
            "pydantic-settings",
            "bcrypt",
            "pyjwt",
            "cryptography",
            "email-validator",
            "--platform",
            "manylinux2014_x86_64",
            "--target",
            build_dir,
            "--implementation",
            "cp",
            "--python-version",
            "3.12",
            "--only-binary=:all:",
        ])

    # Copy app and handler
    shutil.copytree(os.path.join(workspace_dir, "app"), os.path.join(build_dir, "app"), dirs_exist_ok=True)
    shutil.copy(os.path.join(workspace_dir, "handler.py"), os.path.join(build_dir, "handler.py"))

    # Create zip archive
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(build_dir):
            for file in files:
                if file.endswith((".pyc", ".pyo")) or "__pycache__" in root:
                    continue
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, build_dir)
                zipf.write(file_path, arcname)

    shutil.rmtree(build_dir, ignore_errors=True)
    size_mb = os.path.getsize(zip_path) / (1024 * 1024)
    print(f"Packaged {zip_path} ({size_mb:.2f} MB).")
    return zip_path


def deploy_lambda(
    region: str = "us-east-1",
    frontend_origin: str = "*",
    include_deps: bool = False,
):
    account_id = get_account_id(region)
    print(f"Target AWS Account: {account_id} [Region: {region}]")

    role_arn = ensure_iam_role(account_id, region)
    zip_path = build_deployment_package(include_deps=include_deps)

    lambda_client = boto3.client("lambda", region_name=region)

    jwt_secret = os.getenv("JWT_SECRET_KEY")
    if not jwt_secret:
        jwt_secret = secrets.token_urlsafe(32)
        print("[DEPLOY NOTICE] Generated new cryptographically secure JWT_SECRET_KEY.")

    enc_key = os.getenv("GATEKEEP_ENCRYPTION_KEY")
    if not enc_key:
        enc_key = Fernet.generate_key().decode()
        print("[DEPLOY NOTICE] Generated new cryptographically secure GATEKEEP_ENCRYPTION_KEY.")

    env_vars = {
        "ENV": "production",
        "REPOSITORY_BACKEND": "dynamodb",
        "DYNAMODB_TABLE_NAME": TABLE_NAME,
        "JWT_SECRET_KEY": jwt_secret,
        "GATEKEEP_ENCRYPTION_KEY": enc_key,
    }

    with open(zip_path, "rb") as f:
        zip_bytes = f.read()

    try:
        # Check if function exists
        lambda_client.get_function(FunctionName=FUNCTION_NAME)
        print(f"Updating existing Lambda function '{FUNCTION_NAME}' code...")
        lambda_client.update_function_code(
            FunctionName=FUNCTION_NAME,
            ZipFile=zip_bytes,
        )
        print("Updating function configuration...")
        time.sleep(3)
        lambda_client.update_function_configuration(
            FunctionName=FUNCTION_NAME,
            Runtime="python3.12",
            Role=role_arn,
            Handler="handler.handler",
            Timeout=30,
            MemorySize=512,
            Environment={"Variables": env_vars},
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            print(f"Creating new Lambda function '{FUNCTION_NAME}'...")
            # Wait for IAM role replication
            retries = 5
            while retries > 0:
                try:
                    lambda_client.create_function(
                        FunctionName=FUNCTION_NAME,
                        Runtime="python3.12",
                        Role=role_arn,
                        Handler="handler.handler",
                        Code={"ZipFile": zip_bytes},
                        Description="GateKeep LLM Security Gateway & Prompt Injection Firewall",
                        Timeout=30,
                        MemorySize=512,
                        Environment={"Variables": env_vars},
                    )
                    break
                except ClientError as ce:
                    if "The role defined for the function cannot be assumed" in str(ce):
                        print("Waiting for IAM role propagation...")
                        time.sleep(5)
                        retries -= 1
                    else:
                        raise
        else:
            raise

    # Clean up local zip
    if os.path.exists(zip_path):
        os.remove(zip_path)

    # Configure Lambda Function URL
    print("Configuring Lambda Function URL (Free Tier $0/month)...")
    cors_config = {
        "AllowOrigins": [frontend_origin] if frontend_origin != "*" else ["*"],
        "AllowMethods": ["*"],
        "AllowHeaders": ["*"],
        "AllowCredentials": True if frontend_origin != "*" else False,
        "MaxAge": 86400,
    }

    try:
        url_resp = lambda_client.get_function_url_config(FunctionName=FUNCTION_NAME)
        function_url = url_resp["FunctionUrl"]
        print(f"Updating Function URL CORS...")
        lambda_client.update_function_url_config(
            FunctionName=FUNCTION_NAME,
            AuthType="NONE",
            Cors=cors_config,
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            url_resp = lambda_client.create_function_url_config(
                FunctionName=FUNCTION_NAME,
                AuthType="NONE",
                Cors=cors_config,
            )
            function_url = url_resp["FunctionUrl"]
        else:
            raise

    # Allow public invoke on Function URL
    try:
        lambda_client.add_permission(
            FunctionName=FUNCTION_NAME,
            StatementId="FunctionURLAllowPublicAccess",
            Action="lambda:InvokeFunctionUrl",
            Principal="*",
            FunctionUrlAuthType="NONE",
        )
        print("Added public invocation permission to Function URL.")
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceConflictException":
            print(f"Permission notice: {e}")

    print("\n" + "=" * 70)
    print(" GateKeep AWS Lambda Deployment Complete!")
    print("=" * 70)
    print(f" Lambda Function Name: {FUNCTION_NAME}")
    print(f" Live Function URL:    {function_url}")
    print(f" DynamoDB Table:       {TABLE_NAME} (On-Demand, 30-day TTL)")
    print(f" Cost Estimate:        $0.00 / month (AWS Free Tier)")
    print(f"\n Next Step for Vercel Frontend Deployment:")
    print(f" Set environment variable in Vercel:")
    print(f" NEXT_PUBLIC_API_URL={function_url.rstrip('/')}")
    print("=" * 70 + "\n")
    return function_url


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deploy GateKeep to AWS Lambda Free Tier")
    parser.add_argument("--region", default="us-east-1", help="AWS Region")
    parser.add_argument("--frontend-origin", default="*", help="Frontend origin for CORS")
    parser.add_argument("--include-deps", action="store_true", help="Include Linux x86_64 dependencies in package")
    parser.add_argument("--auto-confirm", action="store_true", help="Skip confirmation prompt")
    args = parser.parse_args()

    deploy_lambda(
        region=args.region,
        frontend_origin=args.frontend_origin,
        include_deps=args.include_deps,
    )
