<#
.SYNOPSIS
    Secure Boot Readiness Checker for Microsoft Secure Boot 2023 readiness assessment.

.DESCRIPTION
    Audits Secure Boot configuration, Microsoft KEK/DB 2023 certificates,
    OEM Secure Boot keys, BitLocker status, firmware mode, and optional
    TPM-WMI Secure Boot events.

    Supports console reporting, JSON export, CSV export, HTML reporting,
    and automation scenarios through exit codes.

.EXAMPLE
    .\SecureBootReadinessChecker.ps1

    Runs a standard readiness assessment.

.EXAMPLE
    .\SecureBootReadinessChecker.ps1 -Detailed

    Displays additional Secure Boot certificate information.

.EXAMPLE
    .\SecureBootReadinessChecker.ps1 -Detailed -CheckEvents

    Includes Secure Boot related TPM-WMI event analysis.

.EXAMPLE
    .\SecureBootReadinessChecker.ps1 -ExportHtml -OpenReport

    Generates and opens an HTML report.

.EXAMPLE
    .\SecureBootReadinessChecker.ps1 -ExportJson -ExportCsv

    Exports audit results to JSON and CSV.

.EXAMPLE
    .\SecureBootReadinessChecker.ps1 -Quiet

    Returns a compact output suitable for automation tools
    such as Microsoft Intune or Configuration Manager.

.NOTES
    This tool is audit-only and does not modify Secure Boot,
    firmware, BitLocker, or operating system settings.

.VERSION
    2.0

.AUTHOR
    Lijane Consulting

.LINK
    https://lijaneconsulting.com
#>

[CmdletBinding()]
param(
    [switch]$Detailed,
    [switch]$CheckEvents,
    [switch]$ExportJson,
    [switch]$ExportCsv,
    [switch]$ExportHtml,
    [switch]$OpenReport,
    [switch]$Quiet,
    [string]$OutputPath = $PSScriptRoot
)

#region Functions

function Get-AsciiString {
    param([byte[]]$Bytes)

    try {
        return [System.Text.Encoding]::ASCII.GetString($Bytes)
    }
    catch {
        return ""
    }
}

function Find-CertificateName {
    param(
        [string]$Content,
        [string[]]$Patterns
    )

    foreach ($Pattern in $Patterns) {
        if ($Content -match [regex]::Escape($Pattern)) {
            return $Pattern
        }
    }

    return $null
}

function Find-AllCertificateNames {
    param(
        [string]$Content,
        [string[]]$Patterns
    )

    $Found = @()

    foreach ($Pattern in $Patterns) {
        if ($Content -match [regex]::Escape($Pattern)) {
            $Found += $Pattern
        }
    }

    return $Found
}

function Get-AvailableUpdatesValue {
    $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
    $Name = "AvailableUpdates"

    try {
        $Value = Get-ItemPropertyValue -Path $RegPath -Name $Name -ErrorAction Stop
        return ('0x{0:X}' -f $Value)
    }
    catch {
        return "Not configured"
    }
}

function Get-BitLockerStatus {
    try {
        $SystemDrive = $env:SystemDrive
        $Volume = Get-BitLockerVolume -MountPoint $SystemDrive -ErrorAction Stop

        return [PSCustomObject]@{
            ProtectionStatus = $Volume.ProtectionStatus.ToString()
            VolumeStatus     = $Volume.VolumeStatus.ToString()
            EncryptionMethod = $Volume.EncryptionMethod.ToString()
        }
    }
    catch {
        return [PSCustomObject]@{
            ProtectionStatus = "Unknown"
            VolumeStatus     = "Unknown"
            EncryptionMethod = "Unknown"
        }
    }
}

function Get-ReadinessRecommendation {
    param(
        [bool]$IsUEFI,
        [bool]$SecureBootEnabled,
        [bool]$HasKEK2023,
        [bool]$HasDB2023,
        [bool]$HasDBX
    )

    if (-not $IsUEFI) {
        return "Legacy BIOS or unsupported platform. Exclude this device from Secure Boot 2023 remediation scope."
    }

    if (-not $SecureBootEnabled) {
        return "Secure Boot is disabled. Review BIOS/UEFI configuration before deploying Secure Boot 2023 updates."
    }

    if (-not $HasKEK2023) {
        return "Microsoft KEK 2023 is missing. Deploy Secure Boot 2023 update enablement."
    }

    if (-not $HasDB2023) {
        return "Microsoft DB 2023 is missing. Device may require additional Secure Boot update steps."
    }

    if (-not $HasDBX) {
        return "DBX appears empty or unreadable. Validate firmware and Secure Boot variable access."
    }

    return "No action required. Device is ready for Secure Boot 2026 requirements."
}

function Get-StatusFromScore {
    param(
        [bool]$IsUEFI,
        [int]$Score
    )

    if (-not $IsUEFI) {
        return "UNSUPPORTED"
    }

    if ($Score -ge 90) {
        return "READY"
    }

    if ($Score -ge 60) {
        return "READY WITH WARNING"
    }

    return "ACTION REQUIRED"
}

function Get-ExitCode {
    param([string]$Status)

    switch ($Status) {
        "READY" { return 0 }
        "READY WITH WARNING" { return 1 }
        "ACTION REQUIRED" { return 2 }
        "UNSUPPORTED" { return 3 }
        default { return 9 }
    }
}

function Ensure-OutputPath {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Convert-ArrayToDisplayString {
    param([string[]]$Values)

    if (-not $Values -or $Values.Count -eq 0) {
        return "Not detected"
    }

    return ($Values -join " | ")
}

function Write-ConsoleReport {
    param(
        [object]$Result,
        [switch]$Detailed,
        [switch]$CheckEvents
    )

    Write-Host ""
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host " Secure Boot Readiness Checker v2.0" -ForegroundColor Cyan
    Write-Host " Lijane Consulting" -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "Computer Name : $($Result.ComputerName)"
    Write-Host "Manufacturer  : $($Result.Manufacturer)"
    Write-Host "Model         : $($Result.Model)"
    Write-Host "BIOS Version  : $($Result.BIOSVersion)"
    Write-Host "BIOS Date     : $($Result.BIOSDate)"
    Write-Host "OS Version    : $($Result.OSVersion)"
    Write-Host "OS Build      : $($Result.OSBuild)"
    Write-Host ""

    Write-Host "Firmware Mode : $($Result.FirmwareMode)"
    Write-Host "Secure Boot   : $($Result.SecureBootEnabled)"
    Write-Host "KEK 2023      : $($Result.KEK2023Present)"
    Write-Host "DB 2023       : $($Result.DB2023Present)"
    Write-Host "DBX Present   : $($Result.DBXPresent)"
    Write-Host ""

    Write-Host "AvailableUpdates : $($Result.AvailableUpdates)"
    Write-Host "BitLocker         : $($Result.BitLockerProtectionStatus)"
    Write-Host ""

    Write-Host "Status        : $($Result.Status)"
    Write-Host "Score         : $($Result.Score) / 100"
    Write-Host ""

    Write-Host "Recommendation:"
    Write-Host "$($Result.Recommendation)"
    Write-Host ""

    if ($Detailed) {
        Write-Host "Detailed Information"
        Write-Host "--------------------"
        Write-Host "OEM Platform Key : $($Result.OEMPlatformKey)"
        Write-Host "OEM KEK          : $($Result.OEMKeyExchangeKey)"
        Write-Host "Detected KEK     : $($Result.AllDetectedKEK)"
        Write-Host "Detected DB      : $($Result.AllDetectedDB)"
        Write-Host "DBX Bytes Count  : $($Result.DBXBytesCount)"
        Write-Host "Last Error       : $($Result.LastError)"
        Write-Host ""
    }

    if ($CheckEvents) {
        Write-Host "Secure Boot Events"
        Write-Host "------------------"
        Write-Host "Last Event ID   : $($Result.LastSecureBootEventId)"
        Write-Host "Last Event Date : $($Result.LastSecureBootEventDate)"
        Write-Host "Event Status    : $($Result.SecureBootEventStatus)"
        Write-Host ""
    }

    Write-Host "=================================================="
}

function Export-JsonReport {
    param($Result, [string]$OutputPath)

    Ensure-OutputPath -Path $OutputPath

    $Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $JsonFile = Join-Path $OutputPath "SecureBootReadiness_$($Result.ComputerName)_$Timestamp.json"

    $Result | ConvertTo-Json -Depth 6 | Out-File -FilePath $JsonFile -Encoding UTF8

    return $JsonFile
}

function Export-CsvReport {
    param($Result, [string]$OutputPath)

    Ensure-OutputPath -Path $OutputPath

    $Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $CsvFile = Join-Path $OutputPath "SecureBootReadiness_$($Result.ComputerName)_$Timestamp.csv"

    $Result | Export-Csv -Path $CsvFile -NoTypeInformation -Encoding UTF8

    return $CsvFile
}

function Export-HtmlReport {
    param($Result, [string]$OutputPath)

    Ensure-OutputPath -Path $OutputPath

    $Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $HtmlFile = Join-Path $OutputPath "SecureBootReadiness_$($Result.ComputerName)_$Timestamp.html"

    $StatusClass = switch ($Result.Status) {
        "READY" { "ready" }
        "READY WITH WARNING" { "warning" }
        "ACTION REQUIRED" { "action" }
        "UNSUPPORTED" { "unsupported" }
        default { "unknown" }
    }

    $HtmlContent = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Secure Boot Readiness Report</title>
<style>
body { font-family: Segoe UI, Arial; background:#f4f6f8; color:#1f2937; margin:0; }
.header { background:#0f172a; color:white; padding:26px 40px; }
.header h1 { margin:0; font-size:26px; }
.header p { margin:6px 0 0 0; color:#cbd5e1; }
.container { padding:30px 40px; max-width:1100px; }
.card { background:white; border-radius:12px; padding:22px; margin-bottom:20px; box-shadow:0 2px 8px rgba(0,0,0,0.08); }
.status { font-size:28px; font-weight:700; padding:14px 18px; border-radius:8px; display:inline-block; }
.ready { background:#dcfce7; color:#166534; }
.warning { background:#fef9c3; color:#854d0e; }
.action { background:#fee2e2; color:#991b1b; }
.unsupported { background:#e5e7eb; color:#374151; }
.unknown { background:#e0e7ff; color:#3730a3; }
.score { font-size:44px; font-weight:700; margin-top:12px; }
.grid { display:grid; grid-template-columns: 280px 1fr; row-gap:10px; }
.label { font-weight:600; color:#475569; }
.footer { color:#64748b; font-size:12px; margin-top:30px; }
</style>
</head>
<body>

<div class="header">
  <h1>Secure Boot Readiness Checker</h1>
  <p>Lijane Consulting - Digital Workplace & Endpoint Security</p>
</div>

<div class="container">

  <div class="card">
    <div class="status $StatusClass">$($Result.Status)</div>
    <div class="score">$($Result.Score) / 100</div>
    <p>$($Result.Recommendation)</p>
  </div>

  <div class="card">
    <h2>Device Information</h2>
    <div class="grid">
      <div class="label">Computer Name</div><div>$($Result.ComputerName)</div>
      <div class="label">Manufacturer</div><div>$($Result.Manufacturer)</div>
      <div class="label">Model</div><div>$($Result.Model)</div>
      <div class="label">BIOS Version</div><div>$($Result.BIOSVersion)</div>
      <div class="label">BIOS Date</div><div>$($Result.BIOSDate)</div>
      <div class="label">OS Version</div><div>$($Result.OSVersion)</div>
      <div class="label">OS Build</div><div>$($Result.OSBuild)</div>
    </div>
  </div>

  <div class="card">
    <h2>Secure Boot Checks</h2>
    <div class="grid">
      <div class="label">Firmware Mode</div><div>$($Result.FirmwareMode)</div>
      <div class="label">Secure Boot Enabled</div><div>$($Result.SecureBootEnabled)</div>
      <div class="label">KEK 2023 Present</div><div>$($Result.KEK2023Present)</div>
      <div class="label">DB 2023 Present</div><div>$($Result.DB2023Present)</div>
      <div class="label">DBX Present</div><div>$($Result.DBXPresent)</div>
      <div class="label">AvailableUpdates</div><div>$($Result.AvailableUpdates)</div>
      <div class="label">BitLocker</div><div>$($Result.BitLockerProtectionStatus)</div>
    </div>
  </div>

  <div class="card">
    <h2>Certificates</h2>
    <div class="grid">
      <div class="label">OEM Platform Key</div><div>$($Result.OEMPlatformKey)</div>
      <div class="label">OEM KEK</div><div>$($Result.OEMKeyExchangeKey)</div>
      <div class="label">Detected KEK Entries</div><div>$($Result.AllDetectedKEK)</div>
      <div class="label">Detected DB Entries</div><div>$($Result.AllDetectedDB)</div>
      <div class="label">DBX Bytes Count</div><div>$($Result.DBXBytesCount)</div>
      <div class="label">Last Error</div><div>$($Result.LastError)</div>
    </div>
  </div>

  <div class="card">
    <h2>Secure Boot Events</h2>
    <div class="grid">
      <div class="label">Check Events</div><div>$($Result.CheckEvents)</div>
      <div class="label">Last Event ID</div><div>$($Result.LastSecureBootEventId)</div>
      <div class="label">Last Event Date</div><div>$($Result.LastSecureBootEventDate)</div>
      <div class="label">Event Status</div><div>$($Result.SecureBootEventStatus)</div>
    </div>
  </div>

  <div class="footer">
    Report generated on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") by Lijane Consulting.
  </div>

</div>
</body>
</html>
"@

    $HtmlContent | Out-File -FilePath $HtmlFile -Encoding UTF8
    return $HtmlFile
}

#endregion

#region Data Collection

$ComputerSystem = Get-CimInstance Win32_ComputerSystem
$BIOS = Get-CimInstance Win32_BIOS
$OS = Get-CimInstance Win32_OperatingSystem

$Manufacturer = $ComputerSystem.Manufacturer
$Model = $ComputerSystem.Model
$BIOSVersion = $BIOS.SMBIOSBIOSVersion
$BIOSDate = $BIOS.ReleaseDate
$OSVersion = $OS.Version
$OSBuild = $OS.BuildNumber

#endregion

#region Secure Boot Checks

$IsUEFI = $false
$FirmwareMode = "Legacy BIOS or unsupported"
$SecureBootEnabled = $false
$UnsupportedReason = $null

try {
    $SecureBootEnabled = Confirm-SecureBootUEFI -ErrorAction Stop
    $IsUEFI = $true
    $FirmwareMode = "UEFI"
}
catch {
    $UnsupportedReason = $_.Exception.Message
}

$HasKEK2023 = $false
$HasDB2023 = $false
$HasDBX = $false

$DetectedKEK2023 = $null
$DetectedDB2023 = $null
$OEMPlatformKey = "Not detected"
$OEMKeyExchangeKey = "Not detected"

$AllDetectedKEK = @()
$AllDetectedDB = @()

$KEKAscii = ""
$DBAscii = ""
$PKAscii = ""
$DBXBytesCount = 0

$KEKPatterns = @(
    "Microsoft Corporation KEK CA 2011",
    "Microsoft Corporation KEK 2K CA 2023",
    "Dell Inc. Key Exchange Key",
    "Lenovo UEFI Secure Boot 2012 KEK",
    "HP UEFI Secure Boot 2013 KEK key"
)

$DBPatterns = @(
    "Microsoft Windows UEFI CA 2023",
    "Windows UEFI CA 2023",
    "Microsoft UEFI CA 2023",
    "Microsoft Windows Production PCA 2011",
    "Microsoft Corporation UEFI CA 2011"
)

$PKPatterns = @(
    "Dell Inc. Platform Key",
    "Lenovo Ltd.",
    "HP UEFI Secure Boot 2013 KEK key",
    "Hewlett-Packard"
)

$OEMKEKPatterns = @(
    "Dell Inc. Key Exchange Key",
    "Lenovo UEFI Secure Boot 2012 KEK",
    "HP UEFI Secure Boot 2013 KEK key"
)

if ($IsUEFI) {
    try {
        $PK = Get-SecureBootUEFI PK -ErrorAction Stop
        $KEK = Get-SecureBootUEFI KEK -ErrorAction Stop
        $DB = Get-SecureBootUEFI db -ErrorAction Stop
        $DBX = Get-SecureBootUEFI dbx -ErrorAction Stop

        $PKAscii = Get-AsciiString -Bytes $PK.Bytes
        $KEKAscii = Get-AsciiString -Bytes $KEK.Bytes
        $DBAscii = Get-AsciiString -Bytes $DB.Bytes
        $DBXBytesCount = $DBX.Bytes.Count

        $DetectedKEK2023 = Find-CertificateName -Content $KEKAscii -Patterns @("Microsoft Corporation KEK 2K CA 2023")
        $DetectedDB2023 = Find-CertificateName -Content $DBAscii -Patterns @(
            "Microsoft Windows UEFI CA 2023",
            "Windows UEFI CA 2023",
            "Microsoft UEFI CA 2023"
        )

        $OEMPlatformKey = Find-CertificateName -Content $PKAscii -Patterns $PKPatterns
        if (-not $OEMPlatformKey) { $OEMPlatformKey = "Not detected" }

        $OEMKeyExchangeKey = Find-CertificateName -Content $KEKAscii -Patterns $OEMKEKPatterns
        if (-not $OEMKeyExchangeKey) { $OEMKeyExchangeKey = "Not detected" }

        $AllDetectedKEK = Find-AllCertificateNames -Content $KEKAscii -Patterns $KEKPatterns
        $AllDetectedDB = Find-AllCertificateNames -Content $DBAscii -Patterns $DBPatterns

        $HasKEK2023 = [bool]$DetectedKEK2023
        $HasDB2023 = [bool]$DetectedDB2023
        $HasDBX = ($DBXBytesCount -gt 0)
    }
    catch {
        $UnsupportedReason = $_.Exception.Message
    }
}

#endregion

#region Additional Checks

$AvailableUpdates = Get-AvailableUpdatesValue
$BitLocker = Get-BitLockerStatus

#endregion

#region Events

$LastSecureBootEventId = $null
$LastSecureBootEventDate = $null
$LastSecureBootEventMessage = $null
$SecureBootEventStatus = "Not checked"

if ($CheckEvents) {
    try {
        $Events = Get-WinEvent -LogName "Microsoft-Windows-TPM-WMI/Operational" `
            -FilterXPath "*[System[(EventID=1795 or EventID=1796 or EventID=1801 or EventID=1808)]]" `
            -MaxEvents 20 `
            -ErrorAction Stop

        if ($Events) {
            $LastEvent = $Events | Sort-Object TimeCreated -Descending | Select-Object -First 1

            $LastSecureBootEventId = $LastEvent.Id
            $LastSecureBootEventDate = $LastEvent.TimeCreated
            $LastSecureBootEventMessage = $LastEvent.Message

            $SecureBootEventStatus = switch ($LastEvent.Id) {
                1808 { "Secure Boot update appears successfully applied." }
                1795 { "Secure Boot update detected or initiated." }
                1796 { "Secure Boot update warning or issue detected." }
                1801 { "Secure Boot update issue detected." }
                default { "Secure Boot related event detected." }
            }
        }
        else {
            $SecureBootEventStatus = "No Secure Boot related TPM-WMI event found."
        }
    }
    catch {
        if ($_.Exception.Message -match "There is not an event log") {
            $SecureBootEventStatus = "TPM-WMI event log not available on this device."
        }
        else {
            $SecureBootEventStatus = "Unable to read TPM-WMI events: $($_.Exception.Message)"
        }
    }
}

#endregion

#region Scoring

$Score = 0

if ($IsUEFI) { $Score += 20 }
if ($SecureBootEnabled) { $Score += 20 }
if ($HasKEK2023) { $Score += 20 }
if ($HasDB2023) { $Score += 20 }
if ($HasDBX) { $Score += 20 }

$Status = Get-StatusFromScore -IsUEFI $IsUEFI -Score $Score

$Recommendation = Get-ReadinessRecommendation `
    -IsUEFI $IsUEFI `
    -SecureBootEnabled $SecureBootEnabled `
    -HasKEK2023 $HasKEK2023 `
    -HasDB2023 $HasDB2023 `
    -HasDBX $HasDBX

#endregion

#region Result Object

$Result = [PSCustomObject]@{
    ComputerName                 = $env:COMPUTERNAME
    Manufacturer                 = $Manufacturer
    Model                        = $Model
    BIOSVersion                  = $BIOSVersion
    BIOSDate                     = $BIOSDate
    OSVersion                    = $OSVersion
    OSBuild                      = $OSBuild

    FirmwareMode                 = $FirmwareMode
    IsUEFI                       = $IsUEFI
    SecureBootEnabled            = $SecureBootEnabled
    KEK2023Present               = $HasKEK2023
    DB2023Present                = $HasDB2023
    DBXPresent                   = $HasDBX

    OEMPlatformKey               = $OEMPlatformKey
    OEMKeyExchangeKey            = $OEMKeyExchangeKey
    DetectedKEK2023              = $DetectedKEK2023
    DetectedDB2023               = $DetectedDB2023
    AllDetectedKEK               = Convert-ArrayToDisplayString -Values $AllDetectedKEK
    AllDetectedDB                = Convert-ArrayToDisplayString -Values $AllDetectedDB
    DBXBytesCount                = $DBXBytesCount

    AvailableUpdates             = $AvailableUpdates
    BitLockerProtectionStatus    = $BitLocker.ProtectionStatus
    BitLockerVolumeStatus        = $BitLocker.VolumeStatus
    BitLockerEncryptionMethod    = $BitLocker.EncryptionMethod

    CheckEvents                  = [bool]$CheckEvents
    LastSecureBootEventId        = $LastSecureBootEventId
    LastSecureBootEventDate      = $LastSecureBootEventDate
    SecureBootEventStatus        = $SecureBootEventStatus
    LastSecureBootEventMessage   = $LastSecureBootEventMessage

    Score                        = $Score
    Status                       = $Status
    Recommendation               = $Recommendation
    LastError                    = $UnsupportedReason
    ScanDate                     = (Get-Date).ToString("s")
}

#endregion

#region Output

if (-not $Quiet) {
    Write-ConsoleReport -Result $Result -Detailed:$Detailed -CheckEvents:$CheckEvents
}

if ($ExportJson) {
    $JsonFile = Export-JsonReport -Result $Result -OutputPath $OutputPath

    if (-not $Quiet) {
        Write-Host "JSON Export    : $JsonFile"
    }
}

if ($ExportCsv) {
    $CsvFile = Export-CsvReport -Result $Result -OutputPath $OutputPath

    if (-not $Quiet) {
        Write-Host "CSV Export     : $CsvFile"
    }
}

if ($ExportHtml) {
    $HtmlFile = Export-HtmlReport -Result $Result -OutputPath $OutputPath

    if (-not $Quiet) {
        Write-Host "HTML Export    : $HtmlFile"
    }

    if ($OpenReport -and (Test-Path $HtmlFile)) {
        Start-Process $HtmlFile
    }
}

#endregion

#region Exit

$ExitCode = Get-ExitCode -Status $Result.Status

if ($Quiet) {
    Write-Output "$($Result.Status);Score=$($Result.Score);KEK2023=$($Result.KEK2023Present);DB2023=$($Result.DB2023Present);DBX=$($Result.DBXPresent)"
    exit $ExitCode
}

exit 0

#endregion
