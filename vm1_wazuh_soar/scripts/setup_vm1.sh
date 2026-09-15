#!/bin/bash
# setup_vm1.sh - Idempotent setup script for VM1 (Wazuh Manager + n8n SOAR)
# Run as root on Ubuntu 22.04 LTS

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root"
   exit 1
fi

# Load environment variables
if [[ -f .env ]]; then
    export $(grep -v '^#' .env | xargs)
    log_info "Loaded environment from .env"
else
    log_warn ".env file not found, using defaults. Copy .env.example to .env and configure."
fi

# Set defaults if not provided
VM2_IP="${VM2_IP:-10.0.2.4}"
WAZUH_PASSWORD="${WAZUH_PASSWORD:-StrongPassword123!}"
N8N_ENCRYPTION_KEY="${N8N_ENCRYPTION_KEY:-$(openssl rand -hex 16)}"
WEBHOOK_URL="${WEBHOOK_URL:-http://$(hostname -I | awk '{print $1}'):5678/}"

log_info "Starting VM1 setup: Wazuh Manager + n8n SOAR"
log_info "VM2 IP (Splunk): ${VM2_IP}"

# Update system
log_info "Updating system packages..."
apt-get update && apt-get upgrade -y

# Install dependencies
log_info "Installing dependencies..."
apt-get install -y \
    curl \
    wget \
    gnupg2 \
    software-properties-common \
    apt-transport-https \
    ca-certificates \
    lsb-release \
    unzip \
    jq \
    net-tools \
    iproute2 \
    systemd \
    openssl

# Install Docker
log_info "Installing Docker..."
if ! command -v docker &> /dev/null; then
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable docker
    systemctl start docker
    log_info "Docker installed successfully"
else
    log_info "Docker already installed"
fi

# Install Docker Compose (standalone)
log_info "Installing Docker Compose..."
if ! command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | jq -r .tag_name)
    curl -L "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    log_info "Docker Compose installed"
else
    log_info "Docker Compose already installed"
fi

# Create .env file for docker-compose
log_info "Creating .env file for docker-compose..."
cat > .env <<EOF
WAZUH_PASSWORD=${WAZUH_PASSWORD}
WEBHOOK_URL=${WEBHOOK_URL}
N8N_ENCRYPTION_KEY=${N8N_ENCRYPTION_KEY}
VM2_IP=${VM2_IP}
EOF

# Update ossec.conf with actual VM2 IP
log_info "Updating ossec.conf with VM2 IP..."
sed -i "s|\${VM2_IP}|${VM2_IP}|g" configs/ossec.conf

# Create necessary directories
log_info "Creating data directories..."
mkdir -p /var/ossec/data /var/ossec/logs /var/ossec/etc /var/ossec/queue /var/ossec/var
mkdir -p /home/node/.n8n

# Set permissions
chmod 750 /var/ossec/data /var/ossec/logs /var/ossec/etc /var/ossec/queue /var/ossec/var

# Start Wazuh and n8n stack
log_info "Starting Wazuh Manager and n8n stack..."
docker-compose up -d

# Wait for services to be healthy
log_info "Waiting for services to start..."
sleep 30

# Check Wazuh Manager health
log_info "Checking Wazuh Manager health..."
for i in {1..10}; do
    if curl -k -s -u "wazuh:${WAZUH_PASSWORD}" https://localhost:55000/healthcheck 2>/dev/null | grep -q "ok"; then
        log_info "Wazuh Manager is healthy"
        break
    fi
    log_info "Waiting for Wazuh Manager... (attempt $i/10)"
    sleep 10
done

# Check n8n health
log_info "Checking n8n health..."
for i in {1..10}; do
    if curl -s http://localhost:5678/healthz 2>/dev/null | grep -q "ok"; then
        log_info "n8n is healthy"
        break
    fi
    log_info "Waiting for n8n... (attempt $i/10)"
    sleep 10
done

# Enable ossec-syslogd for syslog forwarding
log_info "Enabling ossec-syslogd..."
docker exec wazuh-manager /var/ossec/bin/ossec-control enable syslogd 2>/dev/null || true
docker exec wazuh-manager systemctl restart wazuh-manager 2>/dev/null || docker restart wazuh-manager

# Import n8n workflow
log_info "Importing n8n workflow..."
sleep 10
WORKFLOW_FILE="workflows/soc_soar_workflow.json"
if [[ -f "$WORKFLOW_FILE" ]]; then
    # Wait for n8n API to be ready
    for i in {1..10}; do
        if curl -s -X POST http://localhost:5678/rest/workflows \
            -H "Content-Type: application/json" \
            -d @"${WORKFLOW_FILE}" 2>/dev/null | grep -q "id"; then
            log_info "n8n workflow imported successfully"
            break
        fi
        log_info "Waiting for n8n API... (attempt $i/10)"
        sleep 5
    done
else
    log_warn "Workflow file not found at ${WORKFLOW_FILE}"
fi

# Configure firewall
log_info "Configuring UFW firewall..."
ufw --force enable
ufw allow 22/tcp comment 'SSH'
ufw allow 1514/udp comment 'Wazuh Agent'
ufw allow 1515/tcp comment 'Wazuh Auth'
ufw allow 55000/tcp comment 'Wazuh API'
ufw allow 5601/tcp comment 'Wazuh Dashboard'
ufw allow 5678/tcp comment 'n8n Webhook'
ufw allow 514/udp comment 'Syslog to VM2'
ufw allow 514/tcp comment 'Syslog to VM2'
ufw reload

# Display summary
log_info "=========================================="
log_info "VM1 Setup Complete!"
log_info "=========================================="
log_info "Wazuh Dashboard: https://$(hostname -I | awk '{print $1}'):5601"
log_info "  Username: wazuh"
log_info "  Password: ${WAZUH_PASSWORD}"
log_info ""
log_info "n8n SOAR: http://$(hostname -I | awk '{print $1}'):5678"
log_info "  Webhook endpoint: http://$(hostname -I | awk '{print $1}'):5678/webhook/soc-alert"
log_info ""
log_info "Wazuh API: https://$(hostname -I | awk '{print $1}'):55000"
log_info ""
log_info "Syslog forwarding to VM2 (${VM2_IP}:514) for alerts level >= 12"
log_info ""
log_info "Next steps:"
log_info "1. Configure n8n credentials: VirusTotal API key and Slack Webhook URL"
log_info "2. Activate the 'SOC SOAR - Wazuh Alert Enrichment' workflow in n8n"
log_info "3. Deploy Wazuh agents on target endpoints pointing to this manager"
log_info "=========================================="