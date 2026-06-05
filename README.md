# Secure Boot Readiness Checker

Secure Boot Readiness Checker is a PowerShell-based audit tool designed to assess a device's readiness for Microsoft's Secure Boot 2023 certificate deployment and the upcoming Secure Boot changes related to the 2026 certificate transition.

The tool performs a non-intrusive audit of the local device and provides a clear readiness assessment, detailed certificate information, firmware details, BitLocker status, and optional reporting capabilities.

---

## Features

### Secure Boot Assessment

* Detects UEFI firmware mode
* Verifies Secure Boot status
* Detects Microsoft KEK 2023 certificate
* Detects Microsoft DB 2023 certificate
* Verifies DBX presence
* Generates a readiness score

### OEM Certificate Detection

Detects OEM-specific Secure Boot certificates when available:

* Dell Platform Key
* Dell Key Exchange Key
* Lenovo Secure Boot KEK
* HP Secure Boot KEK

### Additional Security Checks

* BitLocker protection status
* BitLocker encryption method
* Secure Boot AvailableUpdates registry value

### Secure Boot Event Analysis

Optionally analyzes Secure Boot-related TPM-WMI events:

* Event ID 1795
* Event ID 1796
* Event ID 1801
* Event ID 1808

### Reporting

Supports multiple output formats:

* Console Report
* JSON Export
* CSV Export
* HTML Report

---

## Why This Tool?

Microsoft is introducing Secure Boot certificate updates that include the transition from legacy Secure Boot certificates to the newer 2023 certificate chain.

Many organizations currently have limited visibility into:

* Secure Boot configuration
* Certificate deployment status
* OEM Secure Boot keys
* Firmware readiness
* Device compliance

This tool provides a simple way to assess device readiness before large-scale deployments.

---

## Requirements

### Operating System

* Windows 10
* Windows 11
* Windows Server (where Secure Boot cmdlets are available)

### PowerShell

* Windows PowerShell 5.1 or later

### Permissions

Administrator privileges are recommended.

Some Secure Boot variables may not be accessible without elevated permissions.

---

## Installation

Download the script:

```powershell
SecureBootReadinessChecker.ps1
```

No installation is required.

---

## Usage

### Basic Audit

```powershell
.\SecureBootReadinessChecker.ps1
```

### Detailed Audit

```powershell
.\SecureBootReadinessChecker.ps1 -Detailed
```

### Check TPM-WMI Events

```powershell
.\SecureBootReadinessChecker.ps1 -Detailed -CheckEvents
```

### Export HTML Report

```powershell
.\SecureBootReadinessChecker.ps1 -ExportHtml
```

### Export JSON

```powershell
.\SecureBootReadinessChecker.ps1 -ExportJson
```

### Export CSV

```powershell
.\SecureBootReadinessChecker.ps1 -ExportCsv
```

### Export All Formats

```powershell
.\SecureBootReadinessChecker.ps1 `
    -Detailed `
    -CheckEvents `
    -ExportJson `
    -ExportCsv `
    -ExportHtml
```

### Open HTML Report Automatically

```powershell
.\SecureBootReadinessChecker.ps1 `
    -ExportHtml `
    -OpenReport
```

---

## Readiness Status

### READY

The device meets all current Secure Boot readiness checks.

Requirements:

* UEFI firmware
* Secure Boot enabled
* Microsoft KEK 2023 present
* Microsoft DB 2023 present
* DBX present

### READY WITH WARNING

The device is partially compliant but may require additional validation.

### ACTION REQUIRED

One or more critical Secure Boot components are missing.

### UNSUPPORTED

The device appears to be running in Legacy BIOS mode or Secure Boot cmdlets are unavailable.

---

## Example Output

```text
==================================================
 Secure Boot Readiness Checker v2.0
 Lijane Consulting
==================================================

Computer Name : DEVICE01
Manufacturer  : Dell Inc.
Model         : Latitude 7420

Firmware Mode : UEFI
Secure Boot   : True
KEK 2023      : True
DB 2023       : True
DBX Present   : True

Status        : READY
Score         : 100 / 100
```

---

## Disclaimer

This tool is provided for auditing and assessment purposes only.

The script does not modify:

* Secure Boot configuration
* UEFI variables
* Firmware settings
* BitLocker configuration
* Windows security settings

No changes are performed on the audited device.

---

## Contributing

Contributions, feedback, bug reports, and improvement suggestions are welcome.

Please open an issue or submit a pull request.

---

## Author

Lijane Consulting

Digital Workplace • Endpoint Management • Intune • Configuration Manager • PowerShell

Website: https://lijaneconsulting.com

---

## License

MIT License
