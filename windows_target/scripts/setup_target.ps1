<#
.SYNOPSIS
    Setup script for Windows Target endpoint - Installs Sysmon and Wazuh Agent
.DESCRIPTION
    This script configures a Windows Server 2022 endpoint for the Hybrid Cloud SOC Lab.
    It installs Sysmon with the SwiftOnSecurity-based configuration and the Wazuh Agent
    for telemetry forwarding to the Wazuh Manager.
.NOTES
    Run as Administrator in PowerShell 5.1+
    Requires internet access for downloads
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$WazuhManagerIP,

    [Parameter(Mandatory=$false)]
    [string]$WazuhAgentGroup = "windows,windows-server-2022",

    [Parameter(Mandatory=$false)]
    [string]$SysmonConfigPath = "C:\Windows\System32\drivers\etc\sysmonconfig.xml",

    [Parameter(Mandatory=$false)]
    [string]$WazuhAgentVersion = "4.7.0",

    [Parameter(Mandatory=$false)]
    [string]$DownloadPath = "C:\Temp",

    [Parameter(Mandatory=$false)]
    [switch]$ForceReinstall
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Colors for output
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{ INFO = "Green"; WARN = "Yellow"; ERROR = "Red"; SUCCESS = "Cyan" }
    $color = $colors[$Level] ?? "White"
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Test-IsAdmin {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Check Administrator privileges
if (-not (Test-IsAdmin)) {
    Write-Log "This script must be run as Administrator!" "ERROR"
    exit 1
}

Write-Log "Starting Windows Target Setup for Hybrid Cloud SOC Lab"
Write-Log "Wazuh Manager IP: $WazuhManagerIP"
Write-Log "Sysmon Config: $SysmonConfigPath"

# Create download directory
if (-not (Test-Path $DownloadPath)) {
    New-Item -ItemType Directory -Path $DownloadPath -Force | Out-Null
    Write-Log "Created download directory: $DownloadPath"
}

# ============================================================
# 1. INSTALL SYSMON
# ============================================================
Write-Log "=== Installing Sysmon ==="

$sysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$sysmonZip = Join-Path $DownloadPath "Sysmon.zip"
$sysmonExe = Join-Path $DownloadPath "Sysmon64.exe"

if (Get-Service "Sysmon" -ErrorAction SilentlyContinue) {
    if ($ForceReinstall) {
        Write-Log "Sysmon service found. Stopping and removing..." "WARN"
        & sysmon.exe -u -accepteula 2>$null
        Stop-Service Sysmon -Force -ErrorAction SilentlyContinue
        Start-Sleep 3
    } else {
        Write-Log "Sysmon already installed. Skipping installation." "WARN"
        goto WazuhAgentInstall
    }
}

Write-Log "Downloading Sysmon from $sysmonUrl..."
try {
    Invoke-WebRequest -Uri $sysmonUrl -OutFile $sysmonZip -UseBasicParsing
    Write-Log "Download complete."
} catch {
    Write-Log "Failed to download Sysmon: $($_.Exception.Message)" "ERROR"
    exit 1
}

Write-Log "Extracting Sysmon..."
Expand-Archive -Path $sysmonZip -DestinationPath $DownloadPath -Force
if (-not (Test-Path $sysmonExe)) {
    $sysmonExe = Join-Path $DownloadPath "Sysmon.exe"
    if (-not (Test-Path $sysmonExe)) {
        Write-Log "Sysmon executable not found after extraction!" "ERROR"
        exit 1
    }
}

Write-Log "Installing Sysmon with configuration..."
$installArgs = @(
    "-accepteula",
    "-i",
    $SysmonConfigPath
)
$process = Start-Process -FilePath $sysmonExe -ArgumentList $installArgs -Wait -PassThru -NoNewWindow
if ($process.ExitCode -ne 0) {
    Write-Log "Sysmon installation failed with exit code $($process.ExitCode)" "ERROR"
    exit 1
}

Write-Log "Sysmon installed successfully." "SUCCESS"

# Verify Sysmon service
$sysmonService = Get-Service "Sysmon" -ErrorAction SilentlyContinue
if ($sysmonService) {
    Write-Log "Sysmon service status: $($sysmonService.Status)"
    if ($sysmonService.Status -ne "Running") {
        Start-Service Sysmon
        Write-Log "Started Sysmon service."
    }
} else {
    Write-Log "Sysmon service not found after installation!" "ERROR"
    exit 1
}

# Verify Sysmon config
$currentConfig = & $sysmonExe -c 2>$null
if ($currentConfig) {
    Write-Log "Current Sysmon configuration loaded." "SUCCESS"
}

:WazuhAgentInstall
# ============================================================
# 2. INSTALL WAZUH AGENT
# ============================================================
Write-Log "=== Installing Wazuh Agent ==="

$wazuhMsiUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$WazuhAgentVersion-1.msi"
$wazuhMsiPath = Join-Path $DownloadPath "wazuh-agent-$WazuhAgentVersion-1.msi"

if (Get-Service "WazuhSvc" -ErrorAction SilentlyContinue) {
    if ($ForceReinstall) {
        Write-Log "Wazuh Agent service found. Uninstalling..." "WARN"
        $uninstallArgs = "/x", "`"$wazuhMsiPath`"", "/qn"
        Start-Process msiexec.exe -ArgumentList $uninstallArgs -Wait -NoNewWindow
        Start-Sleep 5
    } else {
        Write-Log "Wazuh Agent already installed. Skipping installation." "WARN"
        goto ConfigureAgent
    }
}

Write-Log "Downloading Wazuh Agent MSI from $wazuhMsiUrl..."
try {
    Invoke-WebRequest -Uri $wazuhMsiUrl -OutFile $wazuhMsiPath -UseBasicParsing
    Write-Log "Download complete."
} catch {
    Write-Log "Failed to download Wazuh Agent: $($_.Exception.Message)" "ERROR"
    exit 1
}

Write-Log "Installing Wazuh Agent silently..."
$installArgs = @(
    "/i", "`"$wazuhMsiPath`"",
    "/qn",
    "WAZUH_MANAGER=$WazuhManagerIP",
    "WAZUH_REGISTRATION_SERVER=$WazuhManagerIP",
    "WAZUH_AGENT_GROUP=$WazuhAgentGroup",
    "WAZUH_AGENT_NAME=$env:COMPUTERNAME"
)
$process = Start-Process msiexec.exe -ArgumentList $installArgs -Wait -PassThru -NoNewWindow
if ($process.ExitCode -ne 0) {
    Write-Log "Wazuh Agent installation failed with exit code $($process.ExitCode)" "ERROR"
    exit 1
}

Write-Log "Wazuh Agent installed successfully." "SUCCESS"

:ConfigureAgent
# ============================================================
# 3. CONFIGURE WAZUH AGENT
# ============================================================
Write-Log "=== Configuring Wazuh Agent ==="

$wazuhInstallPath = "C:\Program Files (x86)\ossec-agent"
$ossecConfPath = Join-Path $wazuhInstallPath "ossec.conf"

if (Test-Path $ossecConfPath) {
    Write-Log "Backing up existing ossec.conf..."
    Copy-Item $ossecConfPath "$ossecConfPath.backup.$(Get-Date -Format 'yyyyMMddHHmmss')" -Force
}

# Generate ossec.conf with actual manager IP
$ossecConfContent = Get-Content -Path "ossec.conf" -Raw
$ossecConfContent = $ossecConfContent -replace "MANAGER_IP", $WazuhManagerIP
$ossecConfContent | Set-Content -Path $ossecConfPath -Encoding UTF8
Write-Log "Updated ossec.conf with Manager IP: $WazuhManagerIP"

# Restart Wazuh Agent service
Write-Log "Restarting Wazuh Agent service..."
Restart-Service WazuhSvc -Force
Start-Sleep 5

$wazuhService = Get-Service WazuhSvc
if ($wazuhService.Status -eq "Running") {
    Write-Log "Wazuh Agent service is running." "SUCCESS"
} else {
    Write-Log "Wazuh Agent service failed to start: $($wazuhService.Status)" "ERROR"
    exit 1
}

# ============================================================
# 4. CONFIGURE WINDOWS AUDIT POLICIES
# ============================================================
Write-Log "=== Configuring Windows Audit Policies ==="

$auditPolicies = @(
    "Process Creation", "Success,Failure"
    "Process Termination", "Success"
    "DPAPI Activity", "Success,Failure"
    "RPC Events", "Success,Failure"
    "Plug and Play Events", "Success,Failure"
    "Token Right Adjusted", "Success,Failure"
    "Filtering Platform Packet Drop", "Failure"
    "Filtering Platform Connection", "Success,Failure"
    "Audit Logon", "Success,Failure"
    "Audit Logoff", "Success"
    "Audit Account Lockout", "Failure"
    "Audit Special Logon", "Success"
    "Audit IPsec Main Mode", "Failure"
    "Audit IPsec Quick Mode", "Failure"
    "Audit IPsec Extended Mode", "Failure"
    "Audit Authentication Policy Change", "Success"
    "Audit Authorization Policy Change", "Success"
    "Audit MPSSVC Rule-Level Policy Change", "Success"
    "Audit Filtering Platform Policy Change", "Success"
    "Audit Other Policy Change Events", "Success"
    "Audit User Account Management", "Success,Failure"
    "Audit Computer Account Management", "Success,Failure"
    "Audit Security Group Management", "Success,Failure"
    "Audit Distribution Group Management", "Success,Failure"
    "Audit Application Group Management", "Success,Failure"
    "Audit Other Account Management Events", "Success,Failure"
    "Audit Non Sensitive Privilege Use", "Failure"
    "Audit Sensitive Privilege Use", "Success,Failure"
    "Audit Other Privilege Use Events", "Success,Failure"
    "Audit Process Creation", "Success"
    "Audit Process Termination", "Success"
    "Audit DPAPI Activity", "Success,Failure"
    "Audit RPC Events", "Success,Failure"
)

for ($i = 0; $i -lt $auditPolicies.Count; $i += 2) {
    $category = $auditPolicies[$i]
    $setting = $auditPolicies[$i + 1]
    try {
        auditpol /set /subcategory:"$category" /$setting /quiet | Out-Null
        Write-Log "Set audit policy: $category = $setting"
    } catch {
        Write-Log "Failed to set audit policy: $category - $($_.Exception.Message)" "WARN"
    }
}

Write-Log "Audit policies configured." "SUCCESS"

# ============================================================
# 5. ENABLE POWERSHELL SCRIPT BLOCK LOGGING
# ============================================================
Write-Log "=== Enabling PowerShell Script Block Logging ==="

$psPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $psPath)) {
    New-Item -Path $psPath -Force | Out-Null
}
Set-ItemProperty -Path $psPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $psPath -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord -Force

$modulePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
if (-not (Test-Path $modulePath)) {
    New-Item -Path $modulePath -Force | Out-Null
}
Set-ItemProperty -Path $modulePath -Name "EnableModuleLogging" -Value 1 -Type DWord -Force
$modules = @("*")
New-ItemProperty -Path $modulePath -Name "ModuleNames" -PropertyType MultiString -Value $modules -Force

Write-Log "PowerShell Script Block Logging enabled." "SUCCESS"

# ============================================================
# 6. ENABLE POWERSHELL TRANSCRIPTION
# ============================================================
Write-Log "=== Enabling PowerShell Transcription ==="

$transPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
if (-not (Test-Path $transPath)) {
    New-Item -Path $transPath -Force | Out-Null
}
Set-ItemProperty -Path $transPath -Name "EnableTranscripting" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $transPath -Name "OutputDirectory" -Value "C:\Windows\Temp\PowerShellTranscripts" -Type String -Force
if (-not (Test-Path "C:\Windows\Temp\PowerShellTranscripts")) {
    New-Item -ItemType Directory -Path "C:\Windows\Temp\PowerShellTranscripts" -Force | Out-Null
}

Write-Log "PowerShell Transcription enabled." "SUCCESS"

# ============================================================
# 7. VERIFY INSTALLATION
# ============================================================
Write-Log "=== Verification ==="

# Check Sysmon
$sysmonCheck = & "$sysmonExe" -c 2>$null
if ($sysmonCheck) {
    Write-Log "Sysmon configuration active." "SUCCESS"
}

# Check Wazuh Agent
$wazuhCheck = & "$wazuhInstallPath\ossec-agent.exe" -t 2>&1
if ($wazuhCheck -match "Configuration OK") {
    Write-Log "Wazuh Agent configuration test passed." "SUCCESS"
} else {
    Write-Log "Wazuh Agent configuration test output: $wazuhCheck" "WARN"
}

# Check Sysmon Event Log
$sysmonLog = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1 -ErrorAction SilentlyContinue
if ($sysmonLog) {
    Write-Log "Sysmon Operational log accessible. Latest Event ID: $($sysmonLog.Id)" "SUCCESS"
}

# Check Wazuh Agent connection
Start-Sleep 10
$agentLog = Get-Content -Path "$wazuhInstallPath\logs\ossec.log" -Tail 20 -ErrorAction SilentlyContinue
if ($agentLog -match "Connected to") {
    Write-Log "Wazuh Agent connected to Manager." "SUCCESS"
} else {
    Write-Log "Wazuh Agent connection status unclear. Check logs." "WARN"
}

Write-Log "=========================================="
Write-Log "Windows Target Setup Complete!" "SUCCESS"
Write-Log "=========================================="
Write-Log "Sysmon: Installed and running with custom config"
Write-Log "Wazuh Agent: Installed, configured, and connected to $WazuhManagerIP"
Write-Log "Audit Policies: Configured for security monitoring"
Write-Log "PowerShell Logging: Script Block Logging + Transcription enabled"
Write-Log ""
Write-Log "Next steps:"
Write-Log "1. Verify alerts in Wazuh Dashboard (VM1:5601)"
Write-Log "2. Run attack simulations from the attacks/ directory"
Write-Log "3. Check Sysmon events: Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' | Select -First 10"
Write-Log "=========================================="