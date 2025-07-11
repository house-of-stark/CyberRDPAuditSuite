<#
.SYNOPSIS
    Deploys RDP Security GPOs to Active Directory
.DESCRIPTION
    This script imports and links RDP Security GPOs to the specified OUs.
    It also copies the necessary ADMX/ADML files to the PolicyDefinitions folder.
.PARAMETER Domain
    The DNS name of the domain (e.g., contoso.com)
.PARAMETER ServerOU
    DistinguishedName of the OU containing servers (e.g., "OU=Servers,DC=contoso,DC=com")
.PARAMETER WorkstationOU
    DistinguishedName of the OU containing workstations (e.g., "OU=Workstations,DC=contoso,DC=com")
.EXAMPLE
    .\Deploy-GPOS.ps1 -Domain contoso.com -ServerOU "OU=Servers,DC=contoso,DC=com" -WorkstationOU "OU=Workstations,DC=contoso,DC=com"
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$Domain,
    
    [Parameter(Mandatory=$true)]
    [string]$ServerOU,
    
    [Parameter(Mandatory=$true)]
    [string]$WorkstationOU
)

#region Functions
function Test-IsElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-ADModuleInstalled {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Copy-ADMXFiles {
    param([string]$SourcePath)
    
    $policyDefinitions = "$env:SystemRoot\PolicyDefinitions"
    $admlPath = "$policyDefinitions\en-US"
    
    try {
        # Create directories if they don't exist
        if (-not (Test-Path $policyDefinitions)) {
            New-Item -ItemType Directory -Path $policyDefinitions -Force | Out-Null
        }
        
        if (-not (Test-Path $admlPath)) {
            New-Item -ItemType Directory -Path $admlPath -Force | Out-Null
        }
        
        # Copy ADMX files
        Get-ChildItem -Path $SourcePath\*.admx | ForEach-Object {
            $destination = Join-Path $policyDefinitions $_.Name
            Copy-Item -Path $_.FullName -Destination $destination -Force
            Write-Host "Copied $($_.Name) to $policyDefinitions"
        }
        
        # Copy ADML files
        Get-ChildItem -Path $SourcePath\en-US\*.adml | ForEach-Object {
            $destination = Join-Path $admlPath $_.Name
            Copy-Item -Path $_.FullName -Destination $destination -Force
            Write-Host "Copied $($_.Name) to $admlPath"
        }
        
        return $true
    } catch {
        Write-Error "Error copying ADMX/ADML files: $_"
        return $false
    }
}
#endregion

#region Main Execution
# Check elevation
if (-not (Test-IsElevated)) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

# Check for Active Directory module
if (-not (Test-ADModuleInstalled)) {
    Write-Error "Active Directory module is not installed. Please install RSAT-AD-PowerShell and try again."
    exit 1
}

# Get script directory
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$admxSource = Join-Path $scriptPath "RDP_Security_GPO"

# Copy ADMX/ADML files
Write-Host "Copying ADMX/ADML files..."
if (-not (Copy-ADMXFiles -SourcePath $admxSource)) {
    exit 1
}

# Import GPOs
$gpoBackupPath = Join-Path $scriptPath "GPO_Backup"

# Server GPO
$serverGPOName = "RDP Security - Server Settings"
$serverGPOPath = Join-Path $gpoBackupPath $serverGPOName

Write-Host "Importing Server GPO..."
if (-not (Get-GPO -Name $serverGPOName -ErrorAction SilentlyContinue)) {
    Import-GPO -BackupGpoName $serverGPOName -Path $gpoBackupPath -TargetName $serverGPOName -CreateIfNeeded
}

# Link Server GPO
$serverGPOLink = Get-GPLink -Name $serverGPOName -Target $ServerOU -ErrorAction SilentlyContinue
if (-not $serverGPOLink) {
    New-GPLink -Name $serverGPOName -Target $ServerOU -LinkEnabled Yes -Enforced Yes
}

# Client GPO
$clientGPOName = "RDP Security - Client Settings"
$clientGPOPath = Join-Path $gpoBackupPath $clientGPOName

Write-Host "Importing Client GPO..."
if (-not (Get-GPO -Name $clientGPOName -ErrorAction SilentlyContinue)) {
    Import-GPO -BackupGpoName $clientGPOName -Path $gpoBackupPath -TargetName $clientGPOName -CreateIfNeeded
}

# Link Client GPO
$clientGPOLink = Get-GPLink -Name $clientGPOName -Target $WorkstationOU -ErrorAction SilentlyContinue
if (-not $clientGPOLink) {
    New-GPLink -Name $clientGPOName -Target $WorkstationOU -LinkEnabled Yes -Enforced Yes
}

# Force GPO update
Write-Host "Forcing GPO update on domain controllers..."
$domainControllers = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
foreach ($dc in $domainControllers) {
    try {
        Invoke-Command -ComputerName $dc -ScriptBlock { gpupdate /force }
        Write-Host "Updated GPO on $dc"
    } catch {
        Write-Warning "Failed to update GPO on $dc : $_"
    }
}

Write-Host "`nDeployment complete!"
Write-Host "Server GPO: $serverGPOName linked to $ServerOU"
Write-Host "Client GPO: $clientGPOName linked to $WorkstationOU"
#endregion
