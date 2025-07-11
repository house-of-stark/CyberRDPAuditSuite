# Apply-RDPSecurity.ps1
# Description: Applies security hardening settings for RDP sessions
# Requires: Run as Administrator
# Version: 1.0

[CmdletBinding()]
param (
    [switch]$WhatIf,
    [string]$LogPath = "$env:ProgramData\RDP_Security\Logs",
    [string]$BackupPath = "$env:ProgramData\RDP_Security\Backups"
)

#region Helper Functions
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    Write-Output $logMessage
    Add-Content -Path "$LogPath\RDPSecurity_$(Get-Date -Format 'yyyyMMdd').log" -Value $logMessage -ErrorAction SilentlyContinue
}

function Backup-RegistryKey {
    param([string]$KeyPath, [string]$BackupFile)
    try {
        if (-not (Test-Path $KeyPath)) { return $false }
        if (-not (Test-Path (Split-Path $BackupFile -Parent))) {
            New-Item -ItemType Directory -Path (Split-Path $BackupFile -Parent) -Force | Out-Null
        }
        reg export "$($KeyPath -replace '^HKEY_LOCAL_MACHINE\\', 'HKLM\\')" $BackupFile /y | Out-Null
        return $?
    } catch { 
        Write-Log "Error backing up $KeyPath : $_"
        return $false 
    }
}
#endregion

#region Initialization
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

# Create necessary directories
foreach ($dir in ($LogPath, $BackupPath)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

Write-Log "=== Starting RDP Security Hardening ==="
Write-Log "Logs: $LogPath"
Write-Log "Backups: $BackupPath"

# Backup current settings
$backupFile = "$BackupPath\RDP_Settings_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"
$backupKeys = @(
    "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server",
    "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
)

Write-Log "Backing up current settings..."
$backupSuccess = $true
foreach ($key in $backupKeys) {
    $file = "$BackupPath\$($key.Replace('\','_'))_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"
    if (-not (Backup-RegistryKey -KeyPath $key -BackupFile $file)) {
        $backupSuccess = $false
        Write-Log "Warning: Failed to backup $key"
    }
}

if (-not $backupSuccess) {
    $confirmation = Read-Host "Some registry keys could not be backed up. Continue? (Y/N)"
    if ($confirmation -ne 'Y') {
        Write-Log "Aborted by user"
        exit 1
    }
}
#endregion

#region Security Settings
$settings = @{
    # Authentication
    "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication" = @{ Value = 1; Type = 'DWord' }  # Enable NLA
    "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\SecurityLayer" = @{ Value = 2; Type = 'DWord' }  # SSL Required
    
    # Encryption
    "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\MinEncryptionLevel" = @{ Value = 3; Type = 'DWord' }  # High (128-bit)
    "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\fEncryptRPCTraffic" = @{ Value = 1; Type = 'DWord' }  # Encrypt RPC
    
    # Session Timeouts
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MaxIdleTime" = @{ Value = 900000; Type = 'DWord' }  # 15 minutes
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MaxConnectionTime" = @{ Value = 14400000; Type = 'DWord' }  # 4 hours
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MaxDisconnectionTime" = @{ Value = 60000; Type = 'DWord' }  # 1 minute
    
    # Security Options
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword" = @{ Value = 1; Type = 'DWord' }  # Always prompt for password
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic" = @{ Value = 1; Type = 'DWord' }  # Encrypt RPC traffic
    
    # Device Redirection
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableClip" = @{ Value = 1; Type = 'DWord' }  # Disable clipboard
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableLPT" = @{ Value = 1; Type = 'DWord' }   # Disable LPT ports
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableCcm" = @{ Value = 1; Type = 'DWord' }   # Disable COM ports
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableCdm" = @{ Value = 1; Type = 'DWord' }   # Disable drives
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableCpm" = @{ Value = 1; Type = 'DWord' }   # Disable LPT/COM port mapping
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableExe" = @{ Value = 1; Type = 'DWord' }   # Disable program execution
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableFilesystem" = @{ Value = 1; Type = 'DWord' }  # Disable filesystem redirection
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisablePNP" = @{ Value = 1; Type = 'DWord' }   # Disable PNP
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisablePNPRedir" = @{ Value = 1; Type = 'DWord' }  # Disable PNP redirection
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisablePrinter" = @{ Value = 1; Type = 'DWord' }  # Disable printer redirection
    
    # Logging
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\LoggingEnabled" = @{ Value = 1; Type = 'DWord' }  # Enable logging
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\LogFileDirectory" = @{ Value = "C:\Logs\RDP"; Type = 'String' }  # Log directory
}

# Apply settings
Write-Log "Applying security settings..."
foreach ($setting in $settings.GetEnumerator()) {
    $path = $setting.Key
    $value = $setting.Value.Value
    $type = $setting.Value.Type
    
    $parentPath = Split-Path -Path $path -Parent
    $name = Split-Path -Path $path -Leaf
    
    try {
        if (-not (Test-Path $parentPath)) {
            New-Item -Path $parentPath -Force | Out-Null
        }
        
        Write-Log "Setting $path = $value ($type)"
        if (-not $WhatIf) {
            Set-ItemProperty -Path $parentPath -Name $name -Value $value -Type $type -Force
        }
    } catch {
        Write-Log "Error setting $path : $_"
    }
}
#endregion

#region Enable and Configure Windows Firewall
Write-Log "Configuring Windows Firewall..."
if (-not $WhatIf) {
    try {
        # Enable Windows Firewall
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction Stop
        
        # Create RDP rule if it doesn't exist
        if (-not (Get-NetFirewallRule -DisplayName "RDP (TCP-In) - Restricted" -ErrorAction SilentlyContinue)) {
            $localIPs = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne '127.0.0.1' }).IPAddress -join ","
            New-NetFirewallRule -DisplayName "RDP (TCP-In) - Restricted" `
                               -Direction Inbound `
                               -LocalPort 3389 `
                               -Protocol TCP `
                               -Action Allow `
                               -Profile Any `
                               -LocalAddress $localIPs `
                               -Description "Restricted RDP access" | Out-Null
        }
    } catch {
        Write-Log "Error configuring firewall: $_"
    }
}
#endregion

#region Enable Event Logging
Write-Log "Configuring event logging..."
if (-not $WhatIf) {
    try {
        wevtutil sl "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" /e:true /q
        wevtutil sl "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" /e:true /q
        
        # Enable process creation auditing
        auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
    } catch {
        Write-Log "Error configuring event logging: $_"
    }
}
#endregion

Write-Log "=== RDP Security Hardening Complete ==="
Write-Log "Note: Some changes may require a system restart to take effect."
Write-Log "Backup of original settings: $BackupPath"
