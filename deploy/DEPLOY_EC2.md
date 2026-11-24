# Hardened AWS EC2 Deployment Runbook — GateKeep ($0/month Free Tier)

This runbook guides you through deploying GateKeep on an **AWS EC2 Free Tier instance** (Ubuntu 24.04 / 22.04 LTS on `t2.micro` or `t3.micro`) with enterprise-grade host and network hardening.

---

## 1. Architecture Highlights
- **Reverse Proxy:** Nginx terminating TLS 1.2/1.3 on port 443, proxying to `127.0.0.1:8000`.
- **Backend Service:** Uvicorn running FastAPI strictly on `127.0.0.1:8000` under a dedicated non-root Linux user (`aegisgate`).
- **Zero AWS Access Keys on Disk:** AWS credentials for DynamoDB are supplied dynamically via an **IAM Instance Profile** (`aegisgate-ec2-profile`) over IMDSv2.
- **Defense in Depth:** UFW host firewall, Fail2Ban brute-force defense, systemd sandboxing (`ProtectSystem=strict`, `NoNewPrivileges=true`), HSTS, and Nginx rate limiting.

---

## 2. Automated One-Command Host Setup

Once your EC2 instance is launched and connected:

```bash
# 1. Clone repository
git clone https://github.com/gatekeep/gatekeep.git /tmp/gatekeep
cd /tmp/gatekeep

# 2. Run automated hardening script as root
sudo bash deploy/setup_ec2.sh
```

---

## 3. Manual Step-by-Step Deployment Guide

### Step 3.1: Provision AWS IAM Role & Security Group (From Local Machine)
Run the automated script to provision the IAM Instance Profile and Security Group:
```bash
python scripts/provision_ec2.py --region us-east-1
```
Or manually via AWS CLI:
```bash
# 1. Create IAM Role with trust policy for EC2
aws iam create-role \
  --role-name aegisgate-ec2-role \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

# 2. Attach least-privilege DynamoDB policy
aws iam put-role-policy \
  --role-name aegisgate-ec2-role \
  --policy-name GateKeepDynamoDBPolicy \
  --policy-document file://deploy/iam-policy.json

# 3. Create Instance Profile & attach role
aws iam create-instance-profile --instance-profile-name aegisgate-ec2-profile
aws iam add-role-to-instance-profile --instance-profile-name aegisgate-ec2-profile --role-name aegisgate-ec2-role

# 4. Create Security Group
aws ec2 create-security-group \
  --group-name aegisgate-ec2-sg \
  --description "Hardened SG for GateKeep: 80/443 public, 8000 blocked, SSH restricted" \
  --vpc-id <YOUR_VPC_ID>

# Allow HTTP (80) & HTTPS (443)
aws ec2 authorize-security-group-ingress --group-id <SG_ID> --protocol tcp --port 80 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id <SG_ID> --protocol tcp --port 443 --cidr 0.0.0.0/0

# Lock SSH (22) strictly to your /32 IP
MY_IP=$(curl -s https://checkip.amazonaws.com)
aws ec2 authorize-security-group-ingress --group-id <SG_ID> --protocol tcp --port 22 --cidr "${MY_IP}/32"
```

> [!IMPORTANT]
> Port 8000 is intentionally **NOT** authorized in the Security Group. Uvicorn binds strictly to `127.0.0.1:8000` behind Nginx.

---

### Step 3.2: Launch the EC2 Instance
- **Instance Type:** `t3.micro` (or `t2.micro`) — 750 hours/month Free Tier.
- **AMI:** Ubuntu Server 24.04 LTS (e.g. `ami-0a951420c495183dc`).
- **Security Group:** `aegisgate-ec2-sg`
- **IAM Instance Profile:** `aegisgate-ec2-profile`
- **Metadata Version:** Require IMDSv2 (`HttpTokens=required`).

---

### Step 3.3: Configure Host User & Directory
On the EC2 instance:
```bash
# Create dedicated non-root user
sudo useradd --system --no-create-home --shell /usr/sbin/nologin aegisgate

# Setup application directories
sudo mkdir -p /opt/aegisgate /etc/aegisgate
sudo chown -R aegisgate:aegisgate /opt/aegisgate
sudo chmod -R 750 /opt/aegisgate
```

---

### Step 3.4: Configure Environment & Secrets
Create `/etc/aegisgate/aegisgate.env`:
```bash
sudo cp deploy/aegisgate.env.example /etc/aegisgate/aegisgate.env
sudo chown root:aegisgate /etc/aegisgate/aegisgate.env
sudo chmod 640 /etc/aegisgate/aegisgate.env
```
Generate secure random keys:
```bash
JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
FERNET_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
sudo sed -i "s/replace-with-a-cryptographically-secure-random-32-byte-secret/${JWT_SECRET}/" /etc/aegisgate/aegisgate.env
sudo sed -i "s|replace-with-a-fernet-url-safe-base64-key-here=|${FERNET_KEY}|" /etc/aegisgate/aegisgate.env
```

---

### Step 3.4.1: Initialize DynamoDB Table with TTL
Ensure the DynamoDB table is initialized on the AWS Free Tier with TTL enabled for automatic 30-day log expiration:
```bash
python3 scripts/init_db.py
```
*(Note: If using `sudo bash deploy/setup_ec2.sh`, this step is executed automatically.)*

---

### Step 3.5: Install & Start Systemd Service
```bash
sudo cp deploy/aegisgate.service /etc/systemd/system/aegisgate.service
sudo systemctl daemon-reload
sudo systemctl enable --now aegisgate.service

# Verify service status
sudo systemctl status aegisgate.service
```

---

### Step 3.6: Configure Hardened Nginx Reverse Proxy
```bash
sudo apt-get install -y nginx ssl-cert
sudo make-ssl-cert generate-default-snakeoil || true

sudo cp deploy/nginx-aegisgate.conf /etc/nginx/sites-available/aegisgate.conf
sudo rm -f /etc/nginx/sites-enabled/default
sudo ln -sf /etc/nginx/sites-available/aegisgate.conf /etc/nginx/sites-enabled/

sudo nginx -t
sudo systemctl restart nginx
```

---

### Step 3.7: Configure UFW Host Firewall
```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp comment 'SSH'
sudo ufw allow 80/tcp comment 'HTTP / Certbot'
sudo ufw allow 443/tcp comment 'HTTPS GateKeep'
sudo ufw deny 8000/tcp comment 'Block direct Uvicorn port'
sudo ufw --force enable
```

---

### Step 3.8: Configure Fail2Ban
```bash
sudo apt-get install -y fail2ban
sudo cp deploy/jail.local /etc/fail2ban/jail.local
sudo systemctl enable --now fail2ban
sudo systemctl restart fail2ban
```

---

### Step 3.9: Hardened SSH Configuration
Edit `/etc/ssh/sshd_config`:
```bash
sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
sudo systemctl reload ssh || sudo systemctl reload sshd
```

---

### Step 3.10: Obtain Let's Encrypt TLS Certificate (Certbot)
Point your DNS `A` record (e.g. `api.yourdomain.com`) to your EC2 Elastic/Public IP, then run:
```bash
sudo certbot --nginx -d api.yourdomain.com
```
Certbot automatically provisions auto-renewing TLS certificates and binds them to Nginx.

---

## 4. Verification & Health Checks

```bash
# 1. Local Uvicorn check (internal loopback only)
curl -i http://127.0.0.1:8000/health

# 2. Public HTTPS Nginx proxy check
curl -i https://api.yourdomain.com/health

# 3. Check security headers
curl -I https://api.yourdomain.com/health | grep -E "Strict-Transport|X-Content|X-Frame|server"

# 4. Test Demo Authentication
curl -X POST https://api.yourdomain.com/api/auth/demo
```

---

## 5. Connecting Next.js Frontend (Vercel)
In your Vercel Dashboard project settings:
- Set environment variable:
  ```
  NEXT_PUBLIC_API_URL=https://api.yourdomain.com
  ```
- Deploy the frontend. All control plane operations and playground requests will securely route through your hardened EC2 Nginx proxy!
