#!/bin/bash
# Configuration validation script for Hybrid SOC Lab
# Run from repository root

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

ERRORS=0
WARNINGS=0

check_file() {
    local file=$1
    local desc=$2
    if [[ -f "$file" ]]; then
        log_info "✓ $desc exists: $file"
    else
        log_error "✗ $desc missing: $file"
        ((ERRORS++))
    fi
}

check_yaml_syntax() {
    local file=$1
    local desc=$2
    if command -v python3 &> /dev/null; then
        if python3 -c "import yaml; yaml.safe_load(open('$file'))" 2>/dev/null; then
            log_info "✓ $desc YAML syntax valid"
        else
            log_error "✗ $desc YAML syntax invalid"
            ((ERRORS++))
        fi
    else
        log_warn "? $desc YAML syntax check skipped (python3 not available)"
        ((WARNINGS++))
    fi
}

check_xml_syntax() {
    local file=$1
    local desc=$2
    if command -v xmllint &> /dev/null; then
        if xmllint --noout "$file" 2>/dev/null; then
            log_info "✓ $desc XML syntax valid"
        else
            log_error "✗ $desc XML syntax invalid"
            ((ERRORS++))
        fi
    else
        log_warn "? $desc XML syntax check skipped (xmllint not available)"
        ((WARNINGS++))
    fi
}

check_json_syntax() {
    local file=$1
    local desc=$2
    if command -v python3 &> /dev/null; then
        if python3 -c "import json; json.load(open('$file'))" 2>/dev/null; then
            log_info "✓ $desc JSON syntax valid"
        else
            log_error "✗ $desc JSON syntax invalid"
            ((ERRORS++))
        fi
    else
        log_warn "? $desc JSON syntax check skipped (python3 not available)"
        ((WARNINGS++))
    fi
}

echo "=== Hybrid SOC Lab Configuration Validation ==="
echo

# Check required files
log_info "Checking required files..."
check_file "vm1_wazuh_soar/docker-compose.yml" "Docker Compose"
check_file "vm1_wazuh_soar/configs/ossec.conf.template" "Wazuh Manager config template"
check_file "vm1_wazuh_soar/configs/local_rules.xml" "Wazuh custom rules"
check_file "vm1_wazuh_soar/workflows/soc_soar_workflow.json" "n8n SOAR workflow"
check_file "vm1_wazuh_soar/.env.example" "Environment example"
check_file "vm1_wazuh_soar/scripts/setup_vm1.sh" "VM1 setup script"

check_file "vm2_splunk_nids/configs/suricata.yaml" "Suricata config"
check_file "vm2_splunk_nids/configs/local.rules" "Suricata custom rules"
check_file "vm2_splunk_nids/configs/inputs.conf" "Splunk inputs.conf"
check_file "vm2_splunk_nids/configs/props.conf" "Splunk props.conf"
check_file "vm2_splunk_nids/scripts/setup_vm2.sh" "VM2 setup script"

check_file "windows_target/ossec.conf" "Windows Wazuh Agent config"
check_file "windows_target/sysmonconfig.xml" "Sysmon config"
check_file "windows_target/scripts/setup_target.ps1" "Windows setup script"

check_file "attacks/metasploit_c2.rc" "Metasploit resource script"
check_file "attacks/attack_simulation.md" "Attack simulation guide"

check_file "README.md" "Documentation"

echo
log_info "Checking syntax..."

# Docker Compose
if command -v docker &> /dev/null && docker compose &> /dev/null; then
    if (cd vm1_wazuh_soar && docker compose config -q 2>/dev/null); then
        log_info "✓ docker-compose.yml syntax valid"
    else
        log_error "✗ docker-compose.yml syntax invalid"
        ((ERRORS++))
    fi
else
    log_warn "? Docker Compose validation skipped (docker not available)"
    ((WARNINGS++))
fi

# YAML configs
check_yaml_syntax "vm2_splunk_nids/configs/suricata.yaml" "Suricata"

# XML configs
check_xml_syntax "vm1_wazuh_soar/configs/ossec.conf.template" "Wazuh Manager template"
check_xml_syntax "vm1_wazuh_soar/configs/local_rules.xml" "Wazuh custom rules"
check_xml_syntax "windows_target/ossec.conf" "Windows Wazuh Agent"
check_xml_syntax "windows_target/sysmonconfig.xml" "Sysmon"

# JSON configs
check_json_syntax "vm1_wazuh_soar/workflows/soc_soar_workflow.json" "n8n workflow"

echo
log_info "Checking for hardcoded secrets..."
if grep -r "StrongPassword123\|Changeme123" --exclude-dir=.git --exclude="*.md" . 2>/dev/null; then
    log_error "✗ Hardcoded passwords found in non-documentation files"
    ((ERRORS++))
else
    log_info "✓ No hardcoded passwords in config files"
fi

if grep -r "VIRUSTOTAL_API_KEY=\|SLACK_WEBHOOK_URL=" --exclude-dir=.git --exclude="*.md" --exclude="*.example" . 2>/dev/null | grep -v "your-.*-here"; then
    log_warn "? Possible real API keys in config files"
    ((WARNINGS++))
else
    log_info "✓ No real API keys detected"
fi

echo
log_info "Checking Wazuh config mount paths..."
if grep -q '/var/ossec/etc/ossec.conf' vm1_wazuh_soar/docker-compose.yml; then
    log_info "✓ Wazuh config mount path correct"
else
    log_error "✗ Wazuh config mount path incorrect"
    ((ERRORS++))
fi

if grep -q '/var/ossec/etc/rules/local_rules.xml' vm1_wazuh_soar/docker-compose.yml; then
    log_info "✓ Wazuh rules mount path correct"
else
    log_error "✗ Wazuh rules mount path incorrect"
    ((ERRORS++))
fi

echo
log_info "Checking Windows Sysmon eventchannel config..."
if grep -q 'Microsoft-Windows-Sysmon/Operational' windows_target/ossec.conf && grep -q 'log_format>eventchannel' windows_target/ossec.conf; then
    log_info "✓ Windows Sysmon eventchannel config correct"
else
    log_error "✗ Windows Sysmon eventchannel config incorrect"
    ((ERRORS++))
fi

echo
log_info "Checking for removed av-scanner references..."
if grep -r "av-scanner" --exclude-dir=.git --exclude="*.md" . 2>/dev/null; then
    log_error "✗ av-scanner references still present"
    ((ERRORS++))
else
    log_info "✓ No av-scanner references found"
fi

echo
log_info "Checking n8n workflow structure..."
if command -v python3 &> /dev/null; then
    python3 << 'EOF'
import json
with open('vm1_wazuh_soar/workflows/soc_soar_workflow.json') as f:
    wf = json.load(f)

nodes = {n['id']: n for n in wf['nodes']}
connections = wf.get('connections', {})

# Check required nodes
required = ['Webhook', 'Parse Alert', 'Has Hash?', 'VirusTotal Lookup', 
            'Format VT Results', 'No Hash - Skip VT', 'Merge Results',
            'Build Slack Payload', 'Post to Slack', 'Webhook Response']
for req in required:
    found = any(n['name'] == req for n in wf['nodes'])
    if found:
        print(f"✓ Node '{req}' present")
    else:
        print(f"✗ Node '{req}' missing")
        exit(1)

# Check conditional branching
has_hash = nodes.get('3')
if has_hash and has_hash['type'] == 'n8n-nodes-base.if':
    print("✓ Conditional branching (IF node) present")
else:
    print("✗ Conditional branching missing")
    exit(1)

# Check merge node
merge = nodes.get('7')
if merge and merge['type'] == 'n8n-nodes-base.merge':
    print("✓ Merge node present")
else:
    print("✗ Merge node missing")
    exit(1)

# Check continueOnFail on external calls
vt_node = nodes.get('4')
slack_node = nodes.get('9')
if vt_node and vt_node['parameters'].get('continueOnFail') == True:
    print("✓ VirusTotal continueOnFail enabled")
else:
    print("✗ VirusTotal continueOnFail missing")
    exit(1)

if slack_node and slack_node['parameters'].get('continueOnFail') == True:
    print("✓ Slack continueOnFail enabled")
else:
    print("✗ Slack continueOnFail missing")
    exit(1)

print("✓ n8n workflow structure valid")
EOF
    if [[ $? -eq 0 ]]; then
        log_info "✓ n8n workflow validation passed"
    else
        log_error "✗ n8n workflow validation failed"
        ((ERRORS++))
    fi
else
    log_warn "? n8n workflow validation skipped (python3 not available)"
    ((WARNINGS++))
fi

echo
echo "=== Validation Summary ==="
if [[ $ERRORS -eq 0 && $WARNINGS -eq 0 ]]; then
    log_info "All checks passed! ✓"
    exit 0
elif [[ $ERRORS -eq 0 ]]; then
    log_warn "Validation passed with $WARNINGS warning(s)"
    exit 0
else
    log_error "$ERRORS error(s), $WARNINGS warning(s) - Fix errors before deployment"
    exit 1
fi