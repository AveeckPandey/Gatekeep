#!/usr/bin/env bash
# ==============================================================================
# GateKeep — Production EC2 Server Hardening & Automated Provisioning Script
# Target OS: Ubuntu 22.04 / 24.04 LTS (AWS EC2 t2.micro / t3.micro Free Tier)
# Must be executed as root (sudo bash deploy/setup_ec2.sh)
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE} GateKeep — EC2 Production Hardening & Provisioning Script           ${NC}"
echo -e "${BLUE}======================================================================${NC}"

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[ERROR] This script must be run as root. Use: sudo bash deploy/setup_ec2.sh${NC}"
   exit 1
fi

APP_DIR="/opt/aegisgate"
CONFIG_DIR="/etc/aegisgate"
USER_NAME="aegisgate"

# ------------------------------------------------------------------------------
# 1. System Updates & OS Hardening Packages
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[1/8] Updating package index and installing security packages...${NC}"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"

apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    nginx \
    ufw \
    fail2ban \
    certbot \
    python3-certbot-nginx \
    unattended-upgrades \
    ssl-cert \
    curl \
    git

# Enable unattended security updates
echo -e "${GREEN}Enabling automatic unattended security updates...${NC}"
echo 'APT::Periodic::Update-Package-Lists "1";' > /etc/apt/apt.conf.d/20auto-upgrades
echo 'APT::Periodic::Unattended-Upgrade "1";' >> /etc/apt/apt.conf.d/20auto-upgrades
systemctl restart unattended-upgrades

# ------------------------------------------------------------------------------
# 2. Dedicated Non-Root System User Creation
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[2/8] Creating dedicated non-root service user '${USER_NAME}'...${NC}"
if ! id -u "${USER_NAME}" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "${USER_NAME}"
    echo -e "${GREEN}Created system user '${USER_NAME}' without login shell.${NC}"
else
    echo -e "${GREEN}System user '${USER_NAME}' already exists.${NC}"
fi

# ------------------------------------------------------------------------------
# 3. Application Directory & Python Virtual Environment Setup
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[3/8] Setting up application in ${APP_DIR}...${NC}"
mkdir -p "${APP_DIR}"

# Copy application files if running from repository
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "${SCRIPT_DIR}")"

if [ -d "${REPO_DIR}/app" ]; then
    cp -r "${REPO_DIR}/app" "${APP_DIR}/"
    cp -r "${REPO_DIR}/scripts" "${APP_DIR}/"
    cp "${REPO_DIR}/requirements.txt" "${APP_DIR}/"
    if [ -f "${REPO_DIR}/handler.py" ]; then
        cp "${REPO_DIR}/handler.py" "${APP_DIR}/"
    fi
fi

# Create virtualenv and install dependencies
if [ ! -d "${APP_DIR}/venv" ]; then
    echo -e "${GREEN}Creating Python virtual environment...${NC}"
    python3 -m venv "${APP_DIR}/venv"
fi

"${APP_DIR}/venv/bin/pip" install --upgrade pip setuptools wheel
"${APP_DIR}/venv/bin/pip" install -r "${APP_DIR}/requirements.txt"
"${APP_DIR}/venv/bin/pip" install uvicorn

# Restrict permissions
chown -R "${USER_NAME}:${USER_NAME}" "${APP_DIR}"
chmod -R 750 "${APP_DIR}"

# ------------------------------------------------------------------------------
# 4. Environment Configuration Setup
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[4/8] Configuring secure environment in ${CONFIG_DIR}...${NC}"
mkdir -p "${CONFIG_DIR}"

if [ ! -f "${CONFIG_DIR}/aegisgate.env" ]; then
    echo -e "${RED}[ERROR] ${CONFIG_DIR}/aegisgate.env is required before service setup.${NC}"
    exit 1
fi

# Strict file permissions on secrets
chown root:"${USER_NAME}" "${CONFIG_DIR}/aegisgate.env"
chmod 640 "${CONFIG_DIR}/aegisgate.env"

# ------------------------------------------------------------------------------
# 5. Systemd Service Installation & Hardening
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[5/8] Installing hardened systemd service (aegisgate.service)...${NC}"
cp "${SCRIPT_DIR}/aegisgate.service" /etc/systemd/system/aegisgate.service

systemctl daemon-reload
systemctl enable aegisgate.service
systemctl restart aegisgate.service

# Verify service is running
sleep 2
if systemctl is-active --quiet aegisgate.service; then
    echo -e "${GREEN}SUCCESS: aegisgate.service is active and running on 127.0.0.1:8000!${NC}"
else
    echo -e "${RED}[ERROR] aegisgate.service failed to start. Journal logs:${NC}"
    journalctl -u aegisgate.service -n 25 --no-pager
    exit 1
fi

# ------------------------------------------------------------------------------
# 5.5. Initialize DynamoDB Table
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[5.5/8] Verifying and initializing DynamoDB table schema...${NC}"
runuser -u "${USER_NAME}" -- "${APP_DIR}/venv/bin/python" "${APP_DIR}/scripts/init_db.py"

# ------------------------------------------------------------------------------
# 6. Hardened Nginx Reverse Proxy Setup
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[6/8] Configuring Nginx reverse proxy with TLS & security headers...${NC}"

# Ensure default snakeoil SSL certificates exist
make-ssl-cert generate-default-snakeoil || true

cp "${SCRIPT_DIR}/nginx-aegisgate.conf" /etc/nginx/sites-available/aegisgate.conf
rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/aegisgate.conf /etc/nginx/sites-enabled/aegisgate.conf

nginx -t
systemctl restart nginx
echo -e "${GREEN}Nginx configured and reloaded.${NC}"

# ------------------------------------------------------------------------------
# 7. Host Firewall (UFW) Configuration
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[7/8] Configuring UFW host firewall...${NC}"
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# Allow SSH, HTTP, and HTTPS only
ufw allow 22/tcp comment 'SSH'
ufw allow 80/tcp comment 'Nginx HTTP / ACME Challenge'
ufw allow 443/tcp comment 'Nginx HTTPS'

# Explicitly block direct external access to internal port 8000
ufw deny 8000/tcp comment 'Block direct Uvicorn port'

ufw --force enable
echo -e "${GREEN}UFW firewall active. Ports 80 and 443 allowed; port 8000 strictly blocked.${NC}"

# ------------------------------------------------------------------------------
# 8. Fail2Ban Brute-Force & Flood Protection Setup
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[8/8] Configuring Fail2Ban brute-force defense...${NC}"
cp "${SCRIPT_DIR}/jail.local" /etc/fail2ban/jail.local

systemctl enable fail2ban
systemctl restart fail2ban
echo -e "${GREEN}Fail2Ban active for SSH and Nginx rate limiting.${NC}"

# ------------------------------------------------------------------------------
# SSH Daemon Hardening Reminder
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}======================================================================${NC}"
echo -e "${GREEN} GateKeep Hardened EC2 Deployment Complete!                         ${NC}"
echo -e "${BLUE}======================================================================${NC}"
echo -e " Backend Service:     active (127.0.0.1:8000 via Uvicorn)"
echo -e " Reverse Proxy:       active (Port 80/443 via Nginx)"
echo -e " Host Firewall:       UFW enabled (deny 8000, allow 80/443/22)"
echo -e " Brute-Force Defense: Fail2Ban enabled"
echo -e " Credential Security: EC2 IAM Instance Profile (Zero static keys on disk)"
echo -e ""
echo -e "${YELLOW}Next Steps to Complete Production Setup:${NC}"
echo -e " 1. Attach IAM Instance Profile 'aegisgate-ec2-profile' to this EC2 instance."
echo -e " 2. (Optional) Point your DNS domain to this EC2 IP and run:"
echo -e "    sudo certbot --nginx -d api.yourdomain.com"
echo -e " 3. Verify SSH hardening in /etc/ssh/sshd_config:"
echo -e "    PermitRootLogin no"
echo -e "    PasswordAuthentication no"
echo -e "    sudo systemctl reload ssh"
echo -e "${BLUE}======================================================================${NC}\n"
