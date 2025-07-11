<#
.SYNOPSIS
    Backs up current RDP-related GPO settings before making changes.
.DESCRIPTION
    This script creates a backup of all RDP-related Group Policy settings and registry keys
    to allow for rollback if needed. It exports both GPOs and relevant registry settings.
.PARAMETER BackupPath
    The directory where backup files will be stored. Defaults to 'RDP_GPO_Backup_<timestamp>' in the current directory.
.EXAMPLE
    .\Backup-GPOSettings.ps1 -BackupPath "C:\Backups\RDP_Settings_Backup"
#>

[CmdletBinding()]
param (
    [string]$BackupPath = "RDP_GPO_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

# Ensure we're running as administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires administrator privileges. Please run as Administrator."
    exit 1
}

# Create backup directory if it doesn't exist
$BackupPath = $PSScriptRoot + "\" + $BackupPath
if (-not (Test-Path -Path $BackupPath)) {
    New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
}

# Create subdirectories for different backup types
$gpoBackupPath = Join-Path $BackupPath "GPO_Backup"
$regBackupPath = Join-Path $BackupPath "Registry_Backup"
$logPath = Join-Path $BackupPath "Backup_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

$pathsToCreate = @($gpoBackupPath, $regBackupPath)
foreach ($path in $pathsToCreate) {
    if (-not (Test-Path -Path $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
}

# Start logging
Start-Transcript -Path $logPath -Force

# Function to export registry keys
function Export-RegistryKey {
    param (
        [string]$KeyPath,
        [string]$OutputFile
    )
    
    try {
        $key = Get-Item -Path $KeyPath -ErrorAction Stop
        $key | Export-Clixml -Path $OutputFile -Force
        Write-Host "Backed up registry key: $KeyPath"
        return $true
    } catch {
        Write-Warning "Failed to back up registry key: $KeyPath - $_"
        return $false
    }
}

# Backup RDP-related registry keys
Write-Host "`nBacking up registry keys..." -ForegroundColor Cyan

$registryKeys = @(
    "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server"
)

$registryBackupResults = @()
foreach ($key in $registryKeys) {
    $fileName = ($key -replace '[\\:]+', '_').Trim('_') + '.reg'
    $outputFile = Join-Path $regBackupPath $fileName
    
    $result = [PSCustomObject]@{
        Key = $key
        Status = 'Failed'
        OutputFile = $outputFile
    }
    
    try {
        # Export using reg.exe for better compatibility
        $regArgs = @('export', "`"$($key -replace '^[^\\]+\\', '$0\\')"", "`"$outputFile`"", '/y')
        $process = Start-Process -FilePath 'reg.exe' -ArgumentList $regArgs -NoNewWindow -Wait -PassThru -ErrorAction Stop
        
        if ($process.ExitCode -eq 0) {
            $result.Status = 'Success'
            Write-Host "Backed up registry key: $key" -ForegroundColor Green
        } else {
            Write-Warning "Failed to back up registry key: $key (Exit code: $($process.ExitCode))"
        }
    } catch {
        Write-Warning "Error backing up registry key $key : $_"
    }
    
    $registryBackupResults += $result
}

# Backup GPOs if GroupPolicy module is available
$gpoBackupResults = @()
if (Get-Module -ListAvailable -Name GroupPolicy) {
    Write-Host "`nBacking up GPOs..." -ForegroundColor Cyan
    
    # Get all GPOs that might contain RDP settings
    $gpoFilter = @(
        '*remote*', '*terminal*', '*rdp*', '*session*',
        '*credential*', '*authentication*', '*security*'
    )
    
    $gpos = Get-GPO -All | Where-Object {
        $displayName = $_.DisplayName.ToLower()
        $gpoFilter | Where-Object { $displayName -like $_ } | Select-Object -First 1
    }
    
    foreach ($gpo in $gpos) {
        $backupName = "$($gpo.DisplayName) - $($gpo.Id)"
        $backupName = [System.IO.Path]::GetInvalidFileNameChars().ForEach({ $backupName = $backupName.Replace($_, '_') })
        $backupFolder = Join-Path $gpoBackupPath $backupName
        
        $result = [PSCustomObject]@{
            GPOName = $gpo.DisplayName
            Status = 'Failed'
            BackupPath = $backupFolder
        }
        
        try {
            if (-not (Test-Path -Path $backupFolder)) {
                New-Item -ItemType Directory -Path $backupFolder -Force | Out-Null
            }
            
            $backup = Backup-GPO -Guid $gpo.Id -Path $gpoBackupPath -ErrorAction Stop
            $result.Status = 'Success'
            Write-Host "Backed up GPO: $($gpo.DisplayName)" -ForegroundColor Green
        } catch {
            Write-Warning "Failed to back up GPO $($gpo.DisplayName): $_"
        }
        
        $gpoBackupResults += $result
    }
} else {
    Write-Warning "GroupPolicy module not available. Skipping GPO backup."
}

# Export local security policy
$seceditBackup = Join-Path $BackupPath "Local_Security_Policy.inf"
try {
    secedit /export /cfg $seceditBackup /areas SECURITYPOLICY | Out-Null
    Write-Host "Backed up local security policy to $seceditBackup" -ForegroundColor Green
} catch {
    Write-Warning "Failed to back up local security policy: $_"
}

# Create a summary report
$summary = @"
=== RDP Settings Backup Summary ===
Backup Location: $BackupPath
Backup Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

=== Registry Keys Backed Up ===
$($registryBackupResults | Format-Table -AutoSize | Out-String)

=== GPOs Backed Up ===
$($gpoBackupResults | Format-Table -AutoSize | Out-String)

=== Next Steps ===
1. Review the backup files in: $BackupPath
2. If needed, you can restore settings using the Restore-RDPSettings.ps1 script
"@

$summary | Out-File -FilePath (Join-Path $BackupPath "Backup_Summary.txt") -Force
Write-Host $summary

# Stop logging
Stop-Transcript

Write-Host "`nBackup completed. Log file: $logPath" -ForegroundColor Green
Write-Host "To restore these settings, run: .\Restore-RDPSettings.ps1 -BackupPath '$BackupPath'" -ForegroundColor Yellow
