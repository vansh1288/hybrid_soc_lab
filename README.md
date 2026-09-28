# Hybrid SOC Lab

A hybrid Security Operations Center (SOC) lab demonstrating detection and response pipeline:
Windows telemetry → Wazuh SIEM → Splunk → n8n SOAR → Slack.

**Status**: Configuration complete. **NOT VERIFIED** end-to-end — requires runtime deployment and testing.

> **Note:** This is an on-premises hybrid SOC lab. No cloud infrastructure is required or included.

## Architecture

```text
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  ATTACKER       │     │  WINDOWS TARGET  │     │  VM1 (Tier 1)   │
│  (Metasploit)   │────▶│  Sysmon +        │────▶│  Wazuh Manager  │
│                 │     │  Wazuh Agent     │     │  Wazuh Indexer  │
└─────────────────┘     └──────────────────┘     │  Wazuh Dashboard│
                                                  │  n8n SOAR       │
                                                  └────────┬────────┘
                                                           │ JSON Syslog (514)
                                                           ▼
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  NETWORK        │     │  VM2 (Tier 2)    │     │  NOTIFICATION   │
│  TRAFFIC        │────▶│  Suricata NIDS   │────▶│  n8n →          │
│                 │     │  Splunk          │     │  VirusTotal     │
└─────────────────┘     └──────────────────┘     │  Slack          │
                                                  └─────────────────┘
```

### Component Overview

| Component | Role | Port(s) |
|-----------|------|---------|
| **Wazuh Manager** | Central log collection, decoding, rule evaluation | 1514/udp (agents), 1515/tcp (auth), 55000/tcp (API) |
| **Wazuh Indexer** | OpenSearch-based alert storage & search | 9200/tcp (REST), 9300/tcp (transport) |
| **Wazuh Dashboard** | Web UI for alert visualization | 5601/tcp |
| **n8n SOAR** | Alert enrichment & automation workflows | 5678/tcp |
| **Suricata** | Network IDS - eve.json output (passive tap) | N/A |
| **Splunk** | Unified search, correlation, alerting | 8000/tcp (web), 8089/tcp (mgmt), 514/udp/tcp (syslog) |
| **Windows Target** | Sysmon telemetry + Wazuh Agent | Outbound 1514/udp |

## Prerequisites

- **VM1 (Ubuntu 22.04)**: 4+ vCPU, 8+ GB RAM, 50+ GB disk - Wazuh stack + n8n
- **VM2 (Ubuntu 22.04)**: 4+ vCPU, 16+ GB RAM, 100+ GB disk - Splunk + Suricata
- **Windows Target (Server 2022)**: 2+ vCPU, 4+ GB RAM - Sysmon + Wazuh Agent
- **Attacker Machine**: Kali Linux or similar with Metasploit Framework
- **Network**: All VMs on same VLAN / able to communicate on required ports
- **External**: VirusTotal API key, Slack webhook URL (for SOAR enrichment)

## Quick Start

### 1. Prepare VM1 (Wazuh + n8n)

```bash
# On VM1
git clone https://github.com/vansh1288/hybrid_soc_lab.git
cd hybrid_soc_lab/vm1_wazuh_soar

# Copy and configure environment
cp .env.example .env
# Edit .env with your values:
# INDEXER_PASSWORD=<strong-password>
# API_PASSWORD=<strong-password>
# DASHBOARD_PASSWORD=<strong-password>
# VM2_IP=<vm2-private-ip>
# N8N_ENCRYPTION_KEY=<32-char-random-string>
# N8N_WEBHOOK_URL=http://<vm1-public-ip>:5678/webhook/soc-alert

# Run setup (as root)
chmod +x scripts/setup_vm1.sh
sudo ./scripts/setup_vm1.sh
```

### 2. Prepare VM2 (Splunk + Suricata)

```bash
# On VM2
git clone https://github.com/vansh1288/hybrid_soc_lab.git
cd hybrid_soc_lab/vm2_splunk_nids

# Export required environment variables
export SPLUNK_PASSWORD="<strong-password>"
export SURICATA_INTERFACE="eth0"  # or your monitoring interface
export N8N_WEBHOOK_URL="http://<vm1-ip>:5678/webhook/soc-alert"

# Run setup (as root)
chmod +x scripts/setup_vm2.sh
sudo ./scripts/setup_vm2.sh
```

### 3. Prepare Windows Target

```powershell
# On Windows Target (PowerShell as Administrator)
git clone https://github.com/vansh1288/hybrid_soc_lab.git
cd hybrid_soc_lab\windows_target

# Run setup
.\scripts\setup_target.ps1 -WazuhManagerIP <VM1_IP> -ForceReinstall
```

### 4. Verify Pipeline (NOT VERIFIED - requires deployment)

1. **Wazuh Dashboard**: https://VM1_IP:5601 (user: `admin`, pass: `$DASHBOARD_PASSWORD`)
2. **n8n**: http://VM1_IP:5678 - Import/activate workflow, configure credentials
3. **Splunk**: http://VM2_IP:8000 (user: `admin`, pass: `$SPLUNK_PASSWORD`)
4. **Suricata**: `tail -f /var/log/suricata/eve.json` on VM2

### 5. Run Attack Simulation

```bash
# On Attacker machine - FIRST configure variables in metasploit_c2.rc or via msfconsole:
msfconsole -r attacks/metasploit_c2.rc
# Then in msfconsole:
# setg RHOSTS <TARGET_IP>
# setg LHOST <ATTACKER_IP>
# setg RC4PASSWORD <secure-random-password>

# Or run specific scenarios from attacks/attack_simulation.md
```

## Detection Validation Matrix

**ALL ENTRIES ARE NOT VERIFIED** — Requires runtime test in deployed environment.

| Attack Scenario | Sysmon Event | Wazuh Rule | MITRE ATT&CK | Splunk | n8n | Slack |
|----------------|--------------|------------|--------------|--------|-----|-------|
| PowerShell Encoded Command | EID 1 | 100001 | T1059.001, T1027 | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED |
| Certutil Download/Decode | EID 1 | 100002 | T1105, T1140 | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED |
| MSHTA Remote Execution | EID 1 | 100003 | T1218.005 | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED |
| Regsvr32 COM Scriptlet | EID 1 | 100004 | T1218.010 | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED |
| Rundll32 DLL Execution | EID 1 | 100005 | T1218.011 | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED |
| WMIC Process Creation | EID 1 | 100006 | T1047, T1490 | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED |
| Suspicious Outbound Ports | EID 3 | 100010 | T1071.001 | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED |
| LOLBin Network Connection | EID 3 | 100011 | T1059.x | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED |
| CreateRemoteThread → LSASS | EID 8 | 100020 | T1003.001, T1055 | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED |
| Process Access → LSASS | EID 10 | 100030/31 | T1003.001 | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED |
| Temp Executable Creation | EID 11 | 100040 | T1059, T1105 | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED |
| Startup Folder Persistence | EID 11 | 100041 | T1547.001 | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED |
| Registry Run Key | EID 13 | 100050 | T1547.001 | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED |
| Service ImagePath Mod | EID 13 | 100051 | T1543.003 | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED |
| IFEO Debugger | EID 13 | 100052 | T1546.012 | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED |
| WDigest Enable | EID 13 | 100053 | T1003.001 | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED |
| WMI Event Subscription | EID 13 | 100060 | T1546.003 | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED |
| ADS Creation | EID 15 | 100070 | T1564.004 | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED |
| Brute Force Logon | Sec 4625 | 100100 | T1110.x | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED |
| Lateral Movement Logon | Sec 4624 | 100101 | T1021.004 | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED |
| Metasploit Reverse TCP | NIDS | 2000001 | T1071.001 | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED |
| Meterpreter Stage 2 | NIDS | 2000002 | T1071.001 | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED |
| Meterpreter HTTP C2 | NIDS | 2000010 | T1071.001 | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED |
| PsExec SMB | NIDS | 2000201 | T1021.002 | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED |
| WMI Remote Exec | NIDS | 2000202 | T1021.003 | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED |

> **NOT VERIFIED** — All detections require runtime test in deployed environment. No component has been validated end-to-end.

## Key Configuration Files

```
vm1_wazuh_soar/
├── docker-compose.yml            # Wazuh stack + n8n
├── generate-indexer-certs.yml    # Certificate generation (one-time)
├── configs/
│   ├── ossec.conf.template       # Wazuh Manager config (templated)
│   ├── ossec.conf                # Generated config (gitignored)
│   └── local_rules.xml           # Custom detection rules
├── workflows/
│   └── soc_soar_workflow.json    # n8n SOAR workflow
└── scripts/
    └── setup_vm1.sh              # VM1 automated setup

vm2_splunk_nids/
├── configs/
│   ├── suricata.yaml             # Suricata NIDS config
│   ├── local.rules               # Custom Suricata rules
│   ├── inputs.conf               # Splunk data inputs
│   └── props.conf                # Splunk parsing rules
└── scripts/
    └── setup_vm2.sh              # VM2 automated setup

windows_target/
├── ossec.conf                    # Wazuh Agent config (Windows)
├── sysmonconfig.xml              # Sysmon configuration
└── scripts/
    └── setup_target.ps1          # Windows automated setup

attacks/
├── metasploit_c2.rc              # Metasploit resource script (parameterized)
└── attack_simulation.md          # Step-by-step attack scenarios

scripts/
└── validate_configs.sh           # Configuration validation script
```

## Configuration Details

### Wazuh Manager (vm1_wazuh_soar/configs/ossec.conf.template)
- JSON output enabled for Splunk forwarding
- Syslog forwarding to VM2:514 (UDP, **level 10+**)
- Agent authentication on port 1515
- Custom rules loaded from local_rules.xml
- Allowed agent networks: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
- TLS certificates mounted from wazuh_indexer_certs volume

### Wazuh Credentials (Separate for Each Component)
- **Indexer**: admin / INDEXER_PASSWORD
- **Manager API**: wazuh-wui / API_PASSWORD
- **Dashboard**: admin / DASHBOARD_PASSWORD

### Windows Wazuh Agent (windows_target/ossec.conf)
- Sysmon Operational channel via eventchannel API
- Security, System, Application, PowerShell, WMI, RDP, Defender, Firewall logs
- Syscheck monitoring for system directories & registry
- Rootcheck with Windows audit policies
- Windows Defender exclusions configured via setup script

### Sysmon (windows_target/sysmonconfig.xml)
- Schema version 4.81 (compatible with Sysmon 14+)
- Comprehensive event filtering: Process Create (1), Network (3), CreateRemoteThread (8), Process Access (10), File Create (11), Registry (12-14), ADS (15), DNS (22), WMI (18), etc.
- SHA256 + IMPHASH for all executables

### Suricata (vm2_splunk_nids/configs/suricata.yaml)
- Passive IDS mode (af-packet tap, copy-mode: tap)
- eve.json output with alert, http, dns, tls, files, flow, stats
- Emerging Threats rules + custom local.rules
- Windows host policy for stream reassembly
- stream.inline: no (passive only)

### Splunk (vm2_splunk_nids/configs/props.conf)
- wazuh_json: INDEXED_EXTRACTIONS=json, field aliases for all Wazuh fields
- suricata_eve: INDEXED_EXTRACTIONS=json, field aliases for Suricata EVE fields
- xmlwineventlog: XML parsing for direct Windows logs (optional)

### n8n SOAR Workflow (vm1_wazuh_soar/workflows/soc_soar_workflow.json)
1. **Webhook** - Receives alerts from Splunk saved searches
2. **Parse Alert** - Normalizes Wazuh/Splunk JSON structure
3. **Has Hash?** - Conditional branch: checks for SHA256
4. **VirusTotal Lookup** - Enriches file hash (only if hash exists)
5. **Format VT Results** / **No Hash - Skip VT** - Parallel paths
6. **Merge Results** - Joins both branches (append mode)
7. **Build Slack Payload** - Formats Block Kit message
8. **Post to Slack** - Sends to configured webhook (continueOnFail)
9. **Webhook Response** - Acknowledges Splunk

## Troubleshooting

### Wazuh Manager Won't Start
```bash
docker logs wazuh-manager
# Check config syntax:
docker exec wazuh-manager /var/ossec/bin/wazuh-logtest -c /var/ossec/etc/ossec.conf
```

### Agents Not Connecting
```bash
# On Windows target
Get-Service WazuhSvc
C:\"Program Files (x86)"\ossec-agent\ossec-agent.exe -t

# On Manager
docker exec wazuh-manager /var/ossec/bin/agent_control -l
```

### Syslog Not Reaching Splunk
```bash
# Test from VM1
echo '{"test":"message"}' | nc -u -w1 VM2_IP 514

# Check Splunk
index=main sourcetype=wazuh_json | head 5
```

### Suricata Not Capturing Traffic
```bash
suricata -T -c /etc/suricata/suricata.yaml -v  # Config test
systemctl status suricata
# Verify interface: ip link show
```

### n8n Workflow Not Triggering
- Verify workflow is **Active** in n8n UI
- Check credentials: VirusTotal API (Header Auth), Slack Webhook (Header Auth)
- Test webhook: `curl -X POST http://VM1_IP:5678/webhook/soc-alert -H "Content-Type: application/json" -d '{"rule":{"id":"100001","level":10,"description":"Test"}}'`

## Configuration Validation

Run the validation script to check syntax and structure:

```bash
chmod +x scripts/validate_configs.sh
./scripts/validate_configs.sh
```

## Security Considerations

- **No hardcoded secrets** - All passwords/keys via `.env` or n8n credentials
- **Network restrictions** - Wazuh agent auth limited to RFC1918 ranges
- **Minimal exposure** - Only required ports opened in UFW
- **TLS** - Wazuh components communicate over TLS internally (certificates generated at deploy)
- **Lab environment** - Default passwords MUST be changed before any non-isolated deployment

## Limitations

- Single-node Wazuh Indexer (no HA)
- SQLite n8n database (not for production scale)
- Splunk Free/Enterprise trial license limitations
- Suricata in passive mode only (no inline blocking)
- Windows audit policies require manual tuning for production
- No cloud/Azure log integration (on-prem only)
- **NOT VERIFIED** end-to-end — no component has been tested in a live deployment

## License

MIT License - See LICENSE file for details.

## Contributing

1. Fork the repository
2. Create feature branch
3. Validate changes with `docker compose config`, `suricata -T`, Wazuh config test
4. Submit PR with description of changes and validation steps

---

**Built for**: Cybersecurity portfolio demonstration, SOC training, detection engineering practice
**Status**: Configuration complete. **NOT VERIFIED** end-to-end — requires runtime deployment and testing.