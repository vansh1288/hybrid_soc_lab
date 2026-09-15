#!/bin/bash
# setup_vm2.sh - Installation script for VM2 (Splunk Enterprise + Suricata NIDS)
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

# Configuration variables
SPLUNK_VERSION="9.2.1"
SPLUNK_BUILD="78803f08aabb"
SPLUNK_FILENAME="splunk-${SPLUNK_VERSION}-${SPLUNK_BUILD}-linux-amd64.deb"
SPLUNK_URL="https://download.splunk.com/products/splunk/releases/${SPLUNK_VERSION}/linux/${SPLUNK_FILENAME}"
SPLUNK_HOME="/opt/splunk"
SPLUNK_USER="splunk"
SPLUNK_PASSWORD="${SPLUNK_PASSWORD:-Changeme123!}"
SURICATA_INTERFACE="${SURICATA_INTERFACE:-eth0}"

log_info "Starting VM2 setup: Splunk Enterprise + Suricata NIDS"
log_info "Splunk Version: ${SPLUNK_VERSION}"
log_info "Suricata Interface: ${SURICATA_INTERFACE}"

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
    ethtool \
    pciutils \
    linux-headers-$(uname -r) \
    build-essential \
    pkg-config \
    libyaml-dev \
    libpcap-dev \
    libnet1-dev \
    libcap-ng-dev \
    libmagic-dev \
    libjansson-dev \
    libnss3-dev \
    libgeoip-dev \
    liblz4-dev \
    libzstd-dev \
    rustc \
    cargo

# Install Suricata from OISF repository (latest stable)
log_info "Installing Suricata..."
add-apt-repository -y ppa:oisf/suricata-stable
apt-get update
apt-get install -y suricata

# Verify Suricata installation
suricata_version=$(suricata --build-info | head -1)
log_info "Suricata installed: ${suricata_version}"

# Configure Suricata
log_info "Configuring Suricata..."

# Detect network interface if not specified
if [[ "${SURICATA_INTERFACE}" == "auto" ]]; then
    SURICATA_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    log_info "Auto-detected interface: ${SURICATA_INTERFACE}"
fi

# Update suricata.yaml with correct interface
sed -i "s/interface: eth0/interface: ${SURICATA_INTERFACE}/g" configs/suricata.yaml

# Copy Suricata configs
mkdir -p /etc/suricata/rules
cp configs/suricata.yaml /etc/suricata/suricata.yaml
cp configs/local.rules /etc/suricata/rules/local.rules

# Download Emerging Threats rules
log_info "Downloading Emerging Threats rules..."
suricata-update enable-source et/open
suricata-update update-sources
suricata-update

# Create Suricata log directory
mkdir -p /var/log/suricata
chown -R suricata:suricata /var/log/suricata

# Enable and start Suricata
log_info "Enabling Suricata service..."
systemctl enable suricata

# Create systemd override for custom config
mkdir -p /etc/systemd/system/suricata.service.d
cat > /etc/systemd/system/suricata.service.d/override.conf <<EOF
[Service]
ExecStartPre=/usr/bin/suricata -T -c /etc/suricata/suricata.yaml -v
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml --pidfile /run/suricata.pid -D
Restart=on-failure
RestartSec=5
EOF

systemctl daemon-reload

# Test Suricata configuration
log_info "Testing Suricata configuration..."
if suricata -T -c /etc/suricata/suricata.yaml -v; then
    log_info "Suricata configuration test passed"
else
    log_error "Suricata configuration test failed"
    exit 1
fi

systemctl start suricata
sleep 5
systemctl status suricata --no-pager

# Install Splunk Enterprise
log_info "Installing Splunk Enterprise..."
cd /tmp

if [[ ! -f "${SPLUNK_FILENAME}" ]]; then
    log_info "Downloading Splunk Enterprise..."
    wget -q -O "${SPLUNK_FILENAME}" "${SPLUNK_URL}" || {
        log_error "Failed to download Splunk. Please download manually from splunk.com"
        log_error "URL: ${SPLUNK_URL}"
        log_error "Place ${SPLUNK_FILENAME} in /tmp and re-run script"
        exit 1
    }
fi

log_info "Installing Splunk package..."
dpkg -i "${SPLUNK_FILENAME}"

# Create splunk user if not exists
if ! id "${SPLUNK_USER}" &>/dev/null; then
    useradd -m -s /bin/bash "${SPLUNK_USER}"
fi

# Set Splunk password and accept license
log_info "Configuring Splunk..."
"${SPLUNK_HOME}/bin/splunk" start --accept-license --answer-yes --no-prompt --seed-passwd "${SPLUNK_PASSWORD}"

# Enable Splunk at boot
"${SPLUNK_HOME}/bin/splunk" enable boot-start -user "${SPLUNK_USER}" --accept-license

# Configure Splunk inputs and props
log_info "Configuring Splunk inputs and props..."
mkdir -p "${SPLUNK_HOME}/etc/apps/search/local"
cp configs/inputs.conf "${SPLUNK_HOME}/etc/apps/search/local/inputs.conf"
cp configs/props.conf "${SPLUNK_HOME}/etc/apps/search/local/props.conf"

# Set permissions
chown -R "${SPLUNK_USER}:${SPLUNK_USER}" "${SPLUNK_HOME}"

# Restart Splunk to apply configs
log_info "Restarting Splunk..."
sudo -u "${SPLUNK_USER}" "${SPLUNK_HOME}/bin/splunk" restart

# Wait for Splunk to start
log_info "Waiting for Splunk to start..."
for i in {1..30}; do
    if sudo -u "${SPLUNK_USER}" "${SPLUNK_HOME}/bin/splunk" status | grep -q "splunkd is running"; then
        log_info "Splunk is running"
        break
    fi
    sleep 5
done

# Configure Splunk for remote syslog reception
log_info "Configuring Splunk network inputs..."
sudo -u "${SPLUNK_USER}" "${SPLUNK_HOME}/bin/splunk" add udp 514 -sourcetype wazuh_json -index main -auth "admin:${SPLUNK_PASSWORD}" 2>/dev/null || true
sudo -u "${SPLUNK_USER}" "${SPLUNK_HOME}/bin/splunk" add tcp 514 -sourcetype wazuh_json -index main -auth "admin:${SPLUNK_PASSWORD}" 2>/dev/null || true

# Create Splunk saved searches for alerting
log_info "Creating Splunk saved searches..."
mkdir -p "${SPLUNK_HOME}/etc/apps/search/local"
cat > "${SPLUNK_HOME}/etc/apps/search/local/savedsearches.conf" <<'SEARCHES'
[Wazuh Critical Alerts - LSASS Access]
search = index=main sourcetype=wazuh_json rule.level>=12 (win.eventdata.targetimage="*lsass.exe" OR win.eventdata.grantedaccess IN ("0x1010","0x1f0fff","0x001fffff"))
dispatch.earliest_time = -5m
dispatch.latest_time = now
alert.track = 1
alert.severity = 1
cron_schedule = */5 * * * *
action.webhook = 1
action.webhook.param.url = http://<N8N_WEBHOOK_URL>/webhook/soc-alert
action.webhook.param.payload_format = json
alert.suppress = 1
alert.suppress.period = 300

[Wazuh High Alerts - LOLBin Execution]
search = index=main sourcetype=wazuh_json rule.level>=10 (rule.groups="sysmon" AND win.eventdata.image IN ("*powershell.exe","*certutil.exe","*mshta.exe","*regsvr32.exe","*rundll32.exe","*wmic.exe","*cmstp.exe","*installutil.exe"))
dispatch.earliest_time = -5m
dispatch.latest_time = now
alert.track = 1
alert.severity = 2
cron_schedule = */5 * * * *
action.webhook = 1
action.webhook.param.url = http://<N8N_WEBHOOK_URL>/webhook/soc-alert
action.webhook.param.payload_format = json
alert.suppress = 1
alert.suppress.period = 300

[Suricata Critical Alerts - Metasploit C2]
search = index=main sourcetype=suricata_eve event_type=alert alert.signature_id IN (2000001,2000002,2000003,2000004,2000010,2000011,2000012,2000030,2000031)
dispatch.earliest_time = -5m
dispatch.latest_time = now
alert.track = 1
alert.severity = 1
cron_schedule = */5 * * * *
action.webhook = 1
action.webhook.param.url = http://<N8N_WEBHOOK_URL>/webhook/soc-alert
action.webhook.param.payload_format = json
alert.suppress = 1
alert.suppress.period = 300

[Suricata High Alerts - Lateral Movement]
search = index=main sourcetype=suricata_eve event_type=alert alert.signature_id IN (2000200,2000201,2000202)
dispatch.earliest_time = -5m
dispatch.latest_time = now
alert.track = 1
alert.severity = 2
cron_schedule = */5 * * * *
action.webhook = 1
action.webhook.param.url = http://<N8N_WEBHOOK_URL>/webhook/soc-alert
action.webhook.param.payload_format = json
alert.suppress = 1
alert.suppress.period = 300
SEARCHES

chown -R "${SPLUNK_USER}:${SPLUNK_USER}" "${SPLUNK_HOME}/etc/apps/search/local/savedsearches.conf"

# Configure firewall
log_info "Configuring UFW firewall..."
ufw --force enable
ufw allow 22/tcp comment 'SSH'
ufw allow 514/udp comment 'Syslog from Wazuh'
ufw allow 514/tcp comment 'Syslog from Wazuh'
ufw allow 8000/tcp comment 'Splunk Web'
ufw allow 8089/tcp comment 'Splunk Management'
ufw allow 9997/tcp comment 'Splunk Forwarder'
ufw reload

# Display summary
log_info "=========================================="
log_info "VM2 Setup Complete!"
log_info "=========================================="
log_info "Splunk Web UI: http://$(hostname -I | awk '{print $1}'):8000"
log_info "  Username: admin"
log_info "  Password: ${SPLUNK_PASSWORD}"
log_info ""
log_info "Splunk Management: https://$(hostname -I | awk '{print $1}'):8089"
log_info ""
log_info "Suricata NIDS: Running on interface ${SURICATA_INTERFACE}"
log_info "  Logs: /var/log/suricata/eve.json"
log_info "  Stats: /var/log/suricata/stats.log"
log_info ""
log_info "Syslog listening on UDP/TCP 514 for Wazuh alerts"
log_info ""
log_info "Next steps:"
log_info "1. Update savedsearches.conf with actual n8n webhook URL"
log_info "2. Configure Splunk indexes and data retention"
log_info "3. Set up Splunk alerts to trigger n8n webhooks"
log_info "4. Verify Suricata is capturing traffic: tail -f /var/log/suricata/eve.json"
log_info "5. Test with: suricata -c /etc/suricata/suricata.yaml -i ${SURICATA_INTERFACE} --init-errors-fatal"
log_info "=========================================="