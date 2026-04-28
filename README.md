```powershell
<#
.SYNOPSIS
    This PowerShell script ensures that the WN11-CC-000090 vulnerability is remediated.
    Enables "Configure registry policy processing" and sets it to:
    "Process even if the Group Policy objects have not changed."
    Safe to run multiple times (idempotent), with logging.

.NOTES
    Author          : Kamerin Crawford
    GitHub          : https://github.com/CyberKamerin
    Date Created    : 04/10/2026
    Last Modified   : 04/10/2026
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000090

.DESCRIPTION
    Enforces:
        Computer Configuration >> Administrative Templates >> System >> Group Policy >>
        "Configure registry policy processing" = Enabled
        Option: "Process even if the Group Policy objects have not changed" = Checked

    Registry:
        HKLM\Software\Policies\Microsoft\Windows\System\NoGPOListChanges = 0

    Log file:
        C:\Logs\PolicyHardening.log

    STIG check:
        HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}
        Name  : NoGPOListChanges
        Type  : REG_DWORD
        Value : 0

.TESTED ON
    Date(s) Tested  : 04/10/2026
    Tested By       : Kamerin Crawford
    Systems Tested  : Microsoft Windows 11
    PowerShell Ver. : 5.1.26100.6899

.USAGE
    PS C:\> .\WN11-CC-000090_Remediation_Script.ps1
#>

# ---------------------------
# Configuration
# ---------------------------
$LogDirectory = "C:\Logs"
$LogFile      = Join-Path $LogDirectory "PolicyHardening.log"

$StigGuidPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
$ValueName    = "NoGPOListChanges"
$DesiredValue = 0

# ---------------------------
# Logging Setup
# ---------------------------
if (!(Test-Path $LogDirectory)) {
    New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
}

function Write-Log {
    param (
        [string]$Message,
        [ConsoleColor]$Color = "White"
    )

    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $entry = "$ts - $Message"

    Write-Host $entry -ForegroundColor $Color
    Add-Content -Path $LogFile -Value $entry
}

# ---------------------------
# Admin Check
# ---------------------------
if (-not (
    [Security.Principal.WindowsPrincipal]
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {

    Write-Log "ERROR: Script must be run as Administrator." Red
    Exit 1
}

Write-Log "Starting STIG enforcement: WN11-CC-000090..."

# ---------------------------
# Ensure Registry Path Exists
# ---------------------------
if (!(Test-Path $StigGuidPath)) {
    Write-Log "Creating registry path: $StigGuidPath"

    New-Item -Path $StigGuidPath -Force | Out-Null
    Write-Log "Registry key created successfully." Green
}
else {
    Write-Log "Registry path already exists." Cyan
}

# ---------------------------
# Read Current Value
# ---------------------------
try {
    $current = (Get-ItemProperty -Path $StigGuidPath -Name $ValueName -ErrorAction Stop).$ValueName
}
catch {
    $current = $null
}

Write-Log "Current value: $ValueName = $current" Cyan

# ---------------------------
# Apply Remediation
# ---------------------------
if ($current -ne $DesiredValue) {

    Write-Log "Setting $ValueName to $DesiredValue..."

    New-ItemProperty -Path $StigGuidPath -Name $ValueName -Value $DesiredValue -PropertyType DWord -Force | Out-Null
    Write-Log "SUCCESS: Value applied." Green

}
else {
    Write-Log "No change required (already compliant)." Cyan
}

# ---------------------------
# Verification
# ---------------------------
$verify = (Get-ItemProperty -Path $StigGuidPath -Name $ValueName).$ValueName

if ($verify -eq $DesiredValue) {
    Write-Log "Verification passed: $verify" Green
} else {
    Write-Log "Verification FAILED: $verify" Red
    Exit 1
}

# ---------------------------
# Group Policy Refresh
# ---------------------------
Write-Log "Refreshing Group Policy..."
gpupdate /force | Out-Null
Write-Log "Group Policy refresh complete." Green
Write-Log "Completed STIG enforcement: WN11-CC-000090" Green
