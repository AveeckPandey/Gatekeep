#!/usr/bin/env bash
# EC2 user-data bootstrap. Set AWS_REGION before invoking, or use the instance Region.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl unzip git ca-certificates

if ! command -v aws >/dev/null 2>&1; then
    curl --fail --silent --show-error https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o /tmp/awscliv2.zip
    unzip -q /tmp/awscliv2.zip -d /tmp
    /tmp/aws/install
fi

: "${AWS_REGION:?AWS_REGION must be set in EC2 user data}"
install -d -m 750 /etc/aegisgate
aws ssm get-parameter \
    --region "${AWS_REGION}" \
    --name /gatekeep/production/env \
    --with-decryption \
    --query Parameter.Value \
    --output text > /etc/aegisgate/aegisgate.env
chmod 600 /etc/aegisgate/aegisgate.env

git clone --depth 1 https://github.com/AveeckPandey/Gatekeep.git /tmp/gatekeep
bash /tmp/gatekeep/deploy/setup_ec2.sh
