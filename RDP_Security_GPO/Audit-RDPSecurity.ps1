<#
.SYNOPSIS
    Audits RDP security settings on local or remote computers.
.DESCRIPTION
    This script checks various RDP-related security settings and configurations
    to ensure they meet security best practices. It can be run against the local
    machine or against multiple remote computers.
.PARAMETER ComputerName
    Specifies the target computer. Default is localhost.
.PARAMETER OutputFile
    Specifies the path to save the audit results.
.EXAMPLE
    .\Audit-RDPSecurity.ps1 -ComputerName "SERVER01" -OutputFile "C:\Audit\RDP_Audit.csv"
#>

[CmdletBinding()]
param (
    [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [Alias('CN', 'Computer')]
    [string[]]$ComputerName = $env:COMPUTERNAME,
    
    [string]$OutputFile = "RDP_Security_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

begin {
    # Define the properties to check with their expected values
    $propertiesToCheck = @(
        @{Name = 'NLA_Enabled'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; ValueName = 'UserAuthentication'; ExpectedValue = 1; Type = 'DWord' },
        @{Name = 'SecurityLayer'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; ValueName = 'SecurityLayer'; ExpectedValue = 2; Type = 'DWord' },
        @{Name = 'MinEncryptionLevel'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; ValueName = 'MinEncryptionLevel'; ExpectedValue = 3; Type = 'DWord' },
        @{Name = 'fEncryptRPCTraffic'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; ValueName = 'fEncryptRPCTraffic'; ExpectedValue = 1; Type = 'DWord' },
        @{Name = 'MaxIdleTime'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; ValueName = 'MaxIdleTime'; ExpectedValue = 900000; Type = 'DWord' },
        @{Name = 'MaxConnectionTime'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; ValueName = 'MaxConnectionTime'; ExpectedValue = 14400000; Type = 'DWord' },
        @{Name = 'fDisableClip'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; ValueName = 'fDisableClip'; ExpectedValue = 1; Type = 'DWord' },
        @{Name = 'fDisableCdm'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; ValueName = 'fDisableCdm'; ExpectedValue = 1; Type = 'DWord' },
        @{Name = 'fDisablePrinter'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; ValueName = 'fDisablePrinter'; ExpectedValue = 1; Type = 'DWord' },
        @{Name = 'fPromptForPassword'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; ValueName = 'fPromptForPassword'; ExpectedValue = 1; Type = 'DWord' },
        @{Name = 'RDP_Port'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; ValueName = 'PortNumber'; ExpectedValue = 3389; Type = 'DWord' }
    )

    # Initialize results array
    $results = @()
}

process {
    foreach ($computer in $ComputerName) {
        Write-Host "Auditing $computer..." -ForegroundColor Cyan
        
        $computerResult = [PSCustomObject]@{
            ComputerName = $computer
            Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            OS = ''
            RDP_Enabled = $false
            RDP_Service = ''
            Firewall_Rule = $false
        }
        
        # Add properties to check
        foreach ($prop in $propertiesToCheck) {
            $computerResult | Add-Member -MemberType NoteProperty -Name $prop.Name -Value $null
            $computerResult | Add-Member -MemberType NoteProperty -Name "$($prop.Name)_Compliant" -Value $false
        }
        
        try {
            # Check if computer is reachable
            if (-not (Test-Connection -ComputerName $computer -Count 1 -Quiet)) {
                $computerResult | Add-Member -MemberType NoteProperty -Name 'Status' -Value 'Offline'
                $results += $computerResult
                continue
            }
            
            # Get OS information
            $osInfo = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $computer -ErrorAction Stop
            $computerResult.OS = "$($osInfo.Caption) $($osInfo.Version)"
            
            # Check RDP service status
            $rdpService = Get-Service -Name TermService -ComputerName $computer -ErrorAction SilentlyContinue
            if ($rdpService) {
                $computerResult.RDP_Service = $rdpService.Status
                $computerResult.RDP_Enabled = $rdpService.Status -eq 'Running'
            }
            
            # Check firewall rule
            $firewallRule = Get-NetFirewallRule -DisplayName 'Remote Desktop*' -Enabled True -ErrorAction SilentlyContinue | 
                           Where-Object { $_.Profile -eq 'Domain' -and $_.Direction -eq 'Inbound' }
            $computerResult.Firewall_Rule = [bool]$firewallRule
            
            # Check registry settings
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $computer)
            
            foreach ($prop in $propertiesToCheck) {
                $regPath = $prop.Path -replace '^HKLM:\\', ''
                $key = $reg.OpenSubKey($regPath)
                
                if ($key) {
                    $value = $key.GetValue($prop.ValueName, $null)
                    $computerResult.($prop.Name) = $value
                    $computerResult."$($prop.Name)_Compliant" = ($value -eq $prop.ExpectedValue)
                } else {
                    $computerResult.($prop.Name) = 'Key not found'
                    $computerResult."$($prop.Name)_Compliant" = $false
                }
                
                if ($key) { $key.Close() }
            }
            
            $computerResult | Add-Member -MemberType NoteProperty -Name 'Status' -Value 'Completed'
            
        } catch {
            $computerResult | Add-Member -MemberType NoteProperty -Name 'Status' -Value "Error: $($_.Exception.Message)"
        }
        
        $results += $computerResult
    }
}

end {
    # Output results
    $results | Format-Table -AutoSize
    
    # Export to CSV if output file is specified
    if ($OutputFile) {
        $results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
        Write-Host "Audit results saved to: $OutputFile" -ForegroundColor Green
    }
    
    # Generate summary
    $summary = @{
        'ComputersAudited' = $results.Count
        'Online' = ($results | Where-Object { $_.Status -eq 'Completed' }).Count
        'RDP_Enabled' = ($results | Where-Object { $_.RDP_Enabled -eq $true }).Count
        'Compliant_All' = ($results | Where-Object { 
            $_.PSObject.Properties.Name -like '*_Compliant' | 
            ForEach-Object { $_.$_.Compliant } | 
            Where-Object { $_ -eq $false } | 
            Measure-Object | Select-Object -ExpandProperty Count
        } | Where-Object { $_ -eq 0 }).Count
    }
    
    Write-Host "`n=== Audit Summary ===" -ForegroundColor Cyan
    $summary.GetEnumerator() | ForEach-Object {
        Write-Host ("{0,-20}: {1}" -f $_.Key, $_.Value)
    }
    
    # Return results
    return $results
}

<#
.SYNOPSIS
    Gets the RDP security configuration for the specified computer.
.DESCRIPTION
    This function retrieves the RDP security configuration from the registry.
    It's used internally by the Audit-RDPSecurity script.
#>
function Get-RDPSecurityConfig {
    [CmdletBinding()]
    param (
        [string]$ComputerName = $env:COMPUTERNAME
    )
    
    $result = @{
        ComputerName = $ComputerName
        Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    }
    
    try {
        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
        
        foreach ($prop in $propertiesToCheck) {
            $regPath = $prop.Path -replace '^HKLM:\\', ''
            $key = $reg.OpenSubKey($regPath)
            
            if ($key) {
                $value = $key.GetValue($prop.ValueName, $null)
                $result[$prop.Name] = $value
                $result["$($prop.Name)_Compliant"] = ($value -eq $prop.ExpectedValue)
                $key.Close()
            } else {
                $result[$prop.Name] = $null
                $result["$($prop.Name)_Compliant"] = $false
            }
        }
        
        $result['Status'] = 'Success'
    } catch {
        $result['Status'] = "Error: $_"
    }
    
    return [PSCustomObject]$result
}
