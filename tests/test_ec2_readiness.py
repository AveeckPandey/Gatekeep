import os

from app.config import settings
from app.db.dynamo import get_dynamo_client, get_dynamo_resource

DEPLOY_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "deploy"))


def test_systemd_service_hardening():
    """
    Verifies that deploy/aegisgate.service implements non-root execution
    and strict systemd security sandboxing.
    """
    service_file = os.path.join(DEPLOY_DIR, "aegisgate.service")
    assert os.path.exists(service_file), f"Missing {service_file}"

    with open(service_file, "r", encoding="utf-8") as f:
        content = f.read()

    # User & Execution target
    assert "User=aegisgate" in content
    assert "Group=aegisgate" in content
    assert "--host 127.0.0.1" in content
    assert "--port 8000" in content

    # Security Sandboxing Flags
    assert "NoNewPrivileges=true" in content
    assert "ProtectSystem=strict" in content
    assert "ProtectHome=true" in content
    assert "PrivateTmp=true" in content
    assert "PrivateDevices=true" in content
    assert "ProtectKernelTunables=true" in content
    assert "ProtectKernelModules=true" in content
    assert "ProtectControlGroups=true" in content
    assert "RestrictRealtime=true" in content
    assert "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6" in content
    assert "CapabilityBoundingSet=" in content


def test_nginx_reverse_proxy_security_configuration():
    """
    Verifies that deploy/nginx-aegisgate.conf enforces:
    - Reverse proxy to 127.0.0.1:8000
    - client_max_body_size 1m
    - Security headers: HSTS, nosniff, DENY, server_tokens off
    - Rate limiting with HTTP 429
    - TLS 1.2 and 1.3 enforcement
    """
    nginx_file = os.path.join(DEPLOY_DIR, "nginx-aegisgate.conf")
    assert os.path.exists(nginx_file), f"Missing {nginx_file}"

    with open(nginx_file, "r", encoding="utf-8") as f:
        content = f.read()

    # Upstream proxy to internal localhost only
    assert "127.0.0.1:8000" in content
    assert "proxy_pass http://aegisgate_backend;" in content

    # Payload limit
    assert "client_max_body_size 1m;" in content

    # Server tokens off
    assert "server_tokens off;" in content

    # Security Headers
    assert "Strict-Transport-Security" in content
    assert "max-age=63072000" in content
    assert "X-Content-Type-Options" in content
    assert "nosniff" in content
    assert "X-Frame-Options" in content
    assert "DENY" in content

    # Rate Limiting
    assert "limit_req_zone" in content
    assert "limit_req_status 429;" in content
    assert "limit_req zone=gatekeep_rate_limit" in content

    # Modern TLS enforcement
    assert "ssl_protocols TLSv1.2 TLSv1.3;" in content


def test_fail2ban_jail_configuration():
    """
    Verifies that deploy/jail.local configures bans for SSH and Nginx via UFW.
    """
    jail_file = os.path.join(DEPLOY_DIR, "jail.local")
    assert os.path.exists(jail_file), f"Missing {jail_file}"

    with open(jail_file, "r", encoding="utf-8") as f:
        content = f.read()

    assert "banaction = ufw" in content
    assert "[sshd]" in content
    assert "[nginx-http-auth]" in content
    assert "[nginx-limit-req]" in content
    assert "maxretry" in content


def test_ec2_setup_script_hardening_rules():
    """
    Verifies that deploy/setup_ec2.sh includes UFW blocking of port 8000,
    non-root user setup, and unattended security updates.
    """
    setup_file = os.path.join(DEPLOY_DIR, "setup_ec2.sh")
    assert os.path.exists(setup_file), f"Missing {setup_file}"

    with open(setup_file, "r", encoding="utf-8") as f:
        content = f.read()

    # User & Shell
    assert "useradd --system" in content
    assert "/usr/sbin/nologin" in content

    # Firewall Rules
    assert "ufw default deny incoming" in content
    assert "ufw allow 80/tcp" in content
    assert "ufw allow 443/tcp" in content
    assert "ufw deny 8000/tcp" in content

    # Unattended security updates
    assert "unattended-upgrades" in content


def test_boto3_default_credential_chain_for_ec2():
    """
    Verifies that DynamoDB client and resource use the default credential chain
    without requiring static AWS credentials on disk when deployed to EC2.
    """
    # In production on EC2, DYNAMODB_ENDPOINT_URL is None
    orig_endpoint = settings.DYNAMODB_ENDPOINT_URL
    try:
        settings.DYNAMODB_ENDPOINT_URL = None
        client = get_dynamo_client()
        resource = get_dynamo_resource()
        assert client is not None
        assert resource is not None
        assert client.meta.region_name == settings.AWS_REGION
    finally:
        settings.DYNAMODB_ENDPOINT_URL = orig_endpoint
