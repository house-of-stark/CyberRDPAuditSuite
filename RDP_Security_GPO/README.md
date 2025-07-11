# CyberRDP Audit Suite - GPO Deployment Guide

<!-- NAVIGATION_START -->
[🏠 Home](../README.md) > [CyberRDP Audit Suite](../README.md) > [GPO Configuration](README.md) > **GPO Deployment Guide**

## Table of Contents

- [Overview](#overview)
- [Contents](#contents)
- [Prerequisites](#prerequisites)
- [Deployment Steps](#deployment-steps)
  - [1. Install ADMX Templates](#1-install-admx-templates)
  - [2. Import and Link GPOs](#2-import-and-link-gpos)
  - [3. Verify Settings](#3-verify-settings)
- [GPO Settings](#gpo-settings)
  - [Server Settings (Computer Configuration)](#server-settings-computer-configuration)
  - [Client Settings (User Configuration)](#client-settings-user-configuration)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)

---

<!-- NAVIGATION_END -->


*Last updated: 2025-06-24*
> **Part of CyberRDP Audit Suite** - This GPO package is designed to work with the CyberRDP Audit Suite for comprehensive RDP security assessment and hardening.

## Overview
This package contains Group Policy Objects (GPOs) and templates to enforce and validate RDP security settings across your Active Directory domain. These policies are specifically designed to work with the CyberRDP Audit Suite for comprehensive security testing and compliance validation.

## Contents
- `RDP_Security_Server.admx` - ADMX template for RDP server settings
- `RDP_Security_Server.adml` - ADML language file
- `RDP_Security_Client.admx` - ADMX template for RDP client settings
- `RDP_Security_Client.adml` - ADML language file
- `Deploy-GPOS.ps1` - PowerShell script to import and link GPOs
- `Audit-RDPSecurity.ps1` - Script to verify settings

## Prerequisites
- Domain Administrator privileges
- Windows Server with Group Policy Management Console (GPMC)
- PowerShell 5.1 or later

## Deployment Steps
### 1. Install ADMX Templates
```powershell
# Copy ADMX files to PolicyDefinitions
Copy-Item ".\*.admx" "%SystemRoot%\PolicyDefinitions\" -Force

# Copy ADML files to en-US directory
if (-not (Test-Path "%SystemRoot%\PolicyDefinitions\en-US")) {
    New-Item -ItemType Directory -Path "%SystemRoot%\PolicyDefinitions\en-US" -Force
}
Copy-Item ".\*.adml" "%SystemRoot%\PolicyDefinitions\en-US\" -Force
```

### 2. Import and Link GPOs
```powershell
# Import GPOs from backup
Import-GPO -BackupGpoName "RDP Security - Server Settings" -Path ".\GPO_Backup" -TargetName "RDP Security - Server Settings" -CreateIfNeeded
Import-GPO -BackupGpoName "RDP Security - Client Settings" -Path ".\GPO_Backup" -TargetName "RDP Security - Client Settings" -CreateIfNeeded

# Link GPOs to appropriate OUs
$domain = (Get-ADDomain).DistinguishedName
$serverOU = "OU=Servers,$domain"  # Update with your server OU
$workstationOU = "OU=Workstations,$domain"  # Update with your workstation OU

New-GPLink -Name "RDP Security - Server Settings" -Target $serverOU -LinkEnabled Yes -Enforced Yes
New-GPLink -Name "RDP Security - Client Settings" -Target $workstationOU -LinkEnabled Yes -Enforced Yes
```

### 3. Verify Settings
```powershell
# Check GPO application
Get-GPOReport -Name "RDP Security - Server Settings" -ReportType HTML -Path ".\RDP_Server_Report.html"
Get-GPOReport -Name "RDP Security - Client Settings" -ReportType HTML -Path ".\RDP_Client_Report.html"

# Run audit script on target machines
Invoke-Command -ComputerName <target> -FilePath ".\Audit-RDPSecurity.ps1"
```

## GPO Settings
### Server Settings (Computer Configuration)
- **Network Level Authentication**: Enabled
- **Encryption Level**: High (128-bit)
- **Session Timeouts**:
  - Idle: 15 minutes
  - Active: 4 hours
- **Device Redirection**: Disabled
- **Security Layer**: SSL (TLS 1.2)

### Client Settings (User Configuration)
- **Do not allow passwords to be saved**: Enabled
- **Prompt for credentials on client computer**: Enabled
- **Do not allow drive redirection**: Enabled
- **Limit audio and video playback**: Enabled

## Verification
1. Run `gpupdate /force` on target machines
2. Check Event Viewer for Group Policy events
3. Verify settings with `rsop.msc`

## Troubleshooting
- **GPO Not Applying**: Check GPO status with `gpresult /h report.html`
- **Permission Issues**: Ensure Domain Computers have Read and Apply Group Policy permissions
- **Replication Issues**: Run `repadmin /syncall` on domain controllers
