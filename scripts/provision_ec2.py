#!/usr/bin/env python3
"""
GateKeep AWS EC2 Provisioning & IAM Profile Setup Script
Provisions:
1. Least-privilege IAM Role & Instance Profile for EC2 (Zero keys on disk).
2. Hardened Security Group (80, 443 open; port 8000 blocked; SSH restricted).
3. Optional launch of Ubuntu Free Tier t2.micro/t3.micro instance with IMDSv2.
"""

import argparse
import json
import urllib.request

import boto3
from botocore.exceptions import ClientError

ROLE_NAME = "aegisgate-ec2-role"
INSTANCE_PROFILE_NAME = "aegisgate-ec2-profile"
SECURITY_GROUP_NAME = "aegisgate-ec2-sg"
TABLE_NAME = "gatekeep-main"


def get_current_public_ip() -> str:
    """Detect current caller IP for locking down SSH access."""
    try:
        with urllib.request.urlopen("https://checkip.amazonaws.com", timeout=5) as response:
            return response.read().decode("utf-8").strip()
    except Exception:
        return "0.0.0.0"


def setup_iam_instance_profile(region: str = "us-east-1") -> str:
    """Creates the IAM Role and Instance Profile for EC2 with least-privilege DynamoDB access."""
    sts = boto3.client("sts", region_name=region)
    account_id = sts.get_caller_identity()["Account"]
    iam = boto3.client("iam", region_name=region)

    table_arn = f"arn:aws:dynamodb:{region}:{account_id}:table/{TABLE_NAME}"
    index_arn = f"{table_arn}/index/*"
    config_parameter_arn = f"arn:aws:ssm:{region}:{account_id}:parameter/gatekeep/production/env"

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }

    print(f"Configuring IAM Role '{ROLE_NAME}'...")
    try:
        iam.get_role(RoleName=ROLE_NAME)
        print(f"Role '{ROLE_NAME}' already exists.")
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            iam.create_role(
                RoleName=ROLE_NAME,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Description="Least-privilege role for GateKeep EC2 instance accessing DynamoDB",
            )
            print(f"Created IAM role '{ROLE_NAME}'.")
        else:
            raise

    # Least privilege policy for DynamoDB + AWS SSM Session Manager
    policy_doc = {
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
                "Sid": "ReadGateKeepEnvironment",
                "Effect": "Allow",
                "Action": ["ssm:GetParameter"],
                "Resource": config_parameter_arn,
            },
            {
                "Sid": "AWSSSMManagedInstanceAccess",
                "Effect": "Allow",
                "Action": [
                    "ssm:UpdateInstanceInformation",
                    "ssmmessages:CreateControlChannel",
                    "ssmmessages:CreateDataChannel",
                    "ssmmessages:OpenControlChannel",
                    "ssmmessages:OpenDataChannel",
                ],
                "Resource": "*",
            },
        ],
    }

    iam.put_role_policy(
        RoleName=ROLE_NAME,
        PolicyName="GateKeepEC2DynamoDBPolicy",
        PolicyDocument=json.dumps(policy_doc),
    )
    print("Attached least-privilege DynamoDB & SSM policy to role.")
    iam.attach_role_policy(
        RoleName=ROLE_NAME,
        PolicyArn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
    )

    # Create Instance Profile
    print(f"Configuring IAM Instance Profile '{INSTANCE_PROFILE_NAME}'...")
    try:
        iam.get_instance_profile(InstanceProfileName=INSTANCE_PROFILE_NAME)
        print(f"Instance profile '{INSTANCE_PROFILE_NAME}' already exists.")
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            iam.create_instance_profile(InstanceProfileName=INSTANCE_PROFILE_NAME)
            print(f"Created instance profile '{INSTANCE_PROFILE_NAME}'.")
        else:
            raise

    # Add role to instance profile if not already attached
    try:
        iam.add_role_to_instance_profile(
            InstanceProfileName=INSTANCE_PROFILE_NAME,
            RoleName=ROLE_NAME,
        )
        print(f"Added role '{ROLE_NAME}' to instance profile.")
    except ClientError as e:
        if e.response["Error"]["Code"] != "LimitExceeded":
            # Role already in instance profile or duplicate
            pass

    return INSTANCE_PROFILE_NAME


def setup_security_group(vpc_id: str = None, region: str = "us-east-1", admin_ip: str = None) -> str:
    """Configures hardened EC2 Security Group: Ports 80/443 open; port 8000 strictly blocked."""
    ec2 = boto3.client("ec2", region_name=region)

    if not vpc_id:
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "is-default", "Values": ["true"]}])
        if vpcs["Vpcs"]:
            vpc_id = vpcs["Vpcs"][0]["VpcId"]
        else:
            raise RuntimeError("No default VPC found. Please supply --vpc-id.")

    print(f"Configuring Security Group in VPC: {vpc_id}...")

    # Check if security group exists
    sg_id = None
    try:
        sgs = ec2.describe_security_groups(
            Filters=[
                {"Name": "group-name", "Values": [SECURITY_GROUP_NAME]},
                {"Name": "vpc-id", "Values": [vpc_id]},
            ]
        )
        if sgs["SecurityGroups"]:
            sg_id = sgs["SecurityGroups"][0]["GroupId"]
            print(f"Security Group '{SECURITY_GROUP_NAME}' already exists: {sg_id}")
            return sg_id
    except ClientError:
        pass

    resp = ec2.create_security_group(
        GroupName=SECURITY_GROUP_NAME,
        Description="Hardened Security Group for GateKeep EC2 (Nginx 80/443, port 8000 blocked)",
        VpcId=vpc_id,
    )
    sg_id = resp["GroupId"]
    print(f"Created Security Group: {sg_id}")

    # Determine admin IP for SSH
    ssh_ip = admin_ip if admin_ip else get_current_public_ip()
    ssh_cidr = f"{ssh_ip}/32" if "/" not in ssh_ip else ssh_ip

    ip_permissions = [
        # HTTP 80 from everywhere (for Let's Encrypt Certbot & redirect)
        {
            "IpProtocol": "tcp",
            "FromPort": 80,
            "ToPort": 80,
            "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "HTTP for Nginx & Certbot"}],
        },
        # HTTPS 443 from everywhere (for TLS API & Proxy traffic)
        {
            "IpProtocol": "tcp",
            "FromPort": 443,
            "ToPort": 443,
            "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "HTTPS for GateKeep API"}],
        },
        # SSH 22 locked strictly to admin IP
        {
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": ssh_cidr, "Description": f"Admin SSH restricted to {ssh_cidr}"}],
        },
    ]

    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=ip_permissions,
    )
    print(f"Ingress rules authorized: HTTP 80 & HTTPS 443 public, SSH 22 locked to {ssh_cidr}. Port 8000 BLOCKED.")
    return sg_id


def get_latest_ubuntu_ami(region: str = "us-east-1") -> str:
    """Finds latest Ubuntu 24.04 or 22.04 LTS AMI ID for amd64."""
    ec2 = boto3.client("ec2", region_name=region)
    resp = ec2.describe_images(
        Filters=[
            {"Name": "name", "Values": ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*", "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]},
            {"Name": "owner-id", "Values": ["099720109477"]},  # Canonical official owner ID
            {"Name": "state", "Values": ["available"]},
        ],
    )
    images = sorted(resp["Images"], key=lambda x: x["CreationDate"], reverse=True)
    if not images:
        raise RuntimeError("Could not find standard Ubuntu AMI.")
    ami_id = images[0]["ImageId"]
    ami_name = images[0]["Name"]
    print(f"Selected Ubuntu AMI: {ami_id} ({ami_name})")
    return ami_id


def ensure_dynamodb_table(region: str = "us-east-1"):
    """Ensures DynamoDB table exists with TTL enabled for audit logs."""
    try:
        from scripts.init_db import init_dynamodb_table
        init_dynamodb_table(table_name=TABLE_NAME, region=region)
    except Exception as e:
        print(f"Notice: DynamoDB table setup check: {e}")


def launch_hardened_ec2(
    instance_type: str = "t3.micro",
    region: str = "us-east-1",
    key_name: str = None,
    admin_ip: str = None,
    launch_instance: bool = False,
):
    """Provisions infrastructure and optionally launches hardened EC2 instance."""
    print("=" * 70)
    print(" Provisioning GateKeep Hardened AWS EC2 Infrastructure")
    print("=" * 70)

    # 0. Ensure DynamoDB table is initialized
    ensure_dynamodb_table(region=region)

    # 1. IAM Instance Profile
    profile_name = setup_iam_instance_profile(region=region)

    # 2. Hardened Security Group
    sg_id = setup_security_group(region=region, admin_ip=admin_ip)

    # 3. AMI
    ami_id = get_latest_ubuntu_ami(region=region)

    # 4. Optional Instance Launch
    if launch_instance:
        print(f"\nLaunching hardened EC2 instance ({instance_type})...")
        ec2 = boto3.client("ec2", region_name=region)
        instance_params = {
            "ImageId": ami_id,
            "InstanceType": instance_type,
            "MinCount": 1,
            "MaxCount": 1,
            "SecurityGroupIds": [sg_id],
            "IamInstanceProfile": {"Name": profile_name},
            "MetadataOptions": {
                "HttpTokens": "required",
                "HttpPutResponseHopLimit": 1,
                "HttpEndpoint": "enabled",
            },
            "TagSpecifications": [
                {
                    "ResourceType": "instance",
                    "Tags": [{"Key": "Name", "Value": "gatekeep-gateway-prod"}],
                }
            ],
        }
        if key_name:
            instance_params["KeyName"] = key_name
        resp = ec2.run_instances(**instance_params)
        inst_id = resp["Instances"][0]["InstanceId"]
        print(f"Successfully launched EC2 instance '{inst_id}' with IAM profile and IMDSv2!")

    print("\n" + "=" * 70)
    print(" GateKeep EC2 Infrastructure Ready!")
    print("=" * 70)
    print(f" IAM Instance Profile: {profile_name}")
    print(f" Security Group ID:    {sg_id}")
    print(f" Recommended AMI:      {ami_id}")
    print(f" Instance Type:        {instance_type} (Ubuntu 24.04 LTS)")
    print("\n Instructions to Launch / Attach to Existing Instance:")
    print(" 1. When launching your EC2 instance:")
    print(f"    - Attach Security Group:  {sg_id}")
    print(f"    - Attach IAM Profile:     {profile_name}")
    print("    - Enable IMDSv2:          HttpTokens=required (Metadata version 2)")
    print(" 2. Once connected via SSH or AWS SSM Session Manager:")
    print("    git clone https://github.com/AveeckPandey/Gatekeep.git /tmp/gatekeep")
    print("    cd /tmp/gatekeep && sudo bash deploy/setup_ec2.sh")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Provision GateKeep EC2 Infrastructure")
    parser.add_argument("--region", default="us-east-1", help="AWS Region")
    parser.add_argument("--instance-type", default="t3.micro", help="EC2 Instance Type (t2.micro/t3.micro)")
    parser.add_argument("--key-name", default=None, help="EC2 SSH Key Pair Name for launch")
    parser.add_argument("--admin-ip", default=None, help="Admin IP for locking SSH port 22")
    parser.add_argument("--launch", action="store_true", help="Launch a new EC2 instance with the configured profile")
    args = parser.parse_args()

    launch_hardened_ec2(
        instance_type=args.instance_type,
        region=args.region,
        key_name=args.key_name,
        admin_ip=args.admin_ip,
        launch_instance=args.launch,
    )
