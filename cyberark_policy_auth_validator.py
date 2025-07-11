#!/usr/bin/env python3
"""
CyberArk PAPM RDP Policy Authentication Validator
This module validates RDP authentication methods against CyberArk PAPM security policies.
It's designed as a component of the CyberArk Policy Validator suite.
"""

import os
import sys
import json
import logging
import winrm
from datetime import datetime
from typing import Dict, List, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('cyberark_auth_validation.log')
    ]
)
logger = logging.getLogger(__name__)

def validate_nla_requirement(session, target: str, required: bool = True) -> Dict[str, Any]:
    """Validate Network Level Authentication requirement
    
    Args:
        session: WinRM session object
        target: Target hostname or IP
        required: Whether NLA is required by policy
        
    Returns:
        Dict: Test results with findings
    """
    logger.info(f"Validating NLA requirement on {target}...")
    
    result = {
        'test': 'nla_requirement',
        'status': 'unknown',
        'findings': [],
        'violations': []
    }
    
    try:
        # Query NLA setting from registry
        ps_script = """$nla = Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -Name "SecurityLayer" -ErrorAction SilentlyContinue
                      if ($nla) {
                          switch ($nla.SecurityLayer) {
                              0 { Write-Output "native_rdp_encryption" }
                              1 { Write-Output "negotiate" }
                              2 { Write-Output "ssl_required" }
                              3 { Write-Output "nla_required" }
                              default { Write-Output "unknown" }
                          }
                      } else {
                          Write-Output "not_found"
                      }"""
        
        result_data = session.run_ps(ps_script)
        security_layer = result_data.std_out.decode('utf-8').strip().lower()
        
        # Also check the UserAuthentication setting which must be 1 for NLA
        ps_script_ua = """$ua = Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue
                          if ($ua) {
                              Write-Output $ua.UserAuthentication
                          } else {
                              Write-Output "not_found"
                          }"""
        
        result_ua = session.run_ps(ps_script_ua)
        user_auth = result_ua.std_out.decode('utf-8').strip()
        
        nla_enabled = False
        
        if security_layer == "nla_required" and user_auth == "1":
            nla_enabled = True
            result['findings'].append("NLA is enabled and required")
        else:
            result['findings'].append(f"Security Layer: {security_layer}")
            result['findings'].append(f"User Authentication: {user_auth}")
            result['findings'].append("NLA is not properly configured")
            
        # Check compliance with policy
        if required == nla_enabled:
            result['status'] = 'passed'
        else:
            result['status'] = 'failed'
            if required:
                result['findings'].append("NLA should be enabled according to CyberArk PAPM policy")
                result['violations'].append({
                    'policy': 'nla_required',
                    'expected': True,
                    'actual': False,
                    'severity': 'critical',
                    'description': 'NLA is not properly enabled, exposing the system to authentication attacks',
                    'remediation': 'Enable NLA by setting SecurityLayer=3 and UserAuthentication=1 in the RDP-Tcp registry'
                })
            else:
                # This is unusual as NLA is generally recommended
                result['findings'].append("NLA is enabled but policy does not require it")
                
    except Exception as e:
        logger.error(f"Error validating NLA requirement: {e}")
        result['status'] = 'error'
        result['findings'].append(f"Error: {str(e)}")
    
    return result


def validate_restricted_admin_mode(session, target: str, required: bool = True) -> Dict[str, Any]:
    """Validate Restricted Admin Mode setting
    
    Args:
        session: WinRM session object
        target: Target hostname or IP
        required: Whether Restricted Admin Mode is required by policy
        
    Returns:
        Dict: Test results with findings
    """
    logger.info(f"Validating Restricted Admin Mode on {target}...")
    
    result = {
        'test': 'restricted_admin_mode',
        'status': 'unknown',
        'findings': [],
        'violations': []
    }
    
    try:
        # Query Restricted Admin Mode setting from registry
        ps_script = """$ram = Get-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Lsa" -Name "DisableRestrictedAdmin" -ErrorAction SilentlyContinue
                      if ($ram -ne $null) {
                          # DisableRestrictedAdmin = 0 means Restricted Admin is enabled
                          if ($ram.DisableRestrictedAdmin -eq 0) {
                              Write-Output "enabled"
                          } else {
                              Write-Output "disabled"
                          }
                      } else {
                          # Key doesn't exist, which means Restricted Admin is disabled by default
                          Write-Output "not_configured"
                      }"""
        
        result_data = session.run_ps(ps_script)
        ram_status = result_data.std_out.decode('utf-8').strip().lower()
        
        result['findings'].append(f"Restricted Admin Mode is: {ram_status}")
        
        # Check compliance with policy
        is_compliant = False
        if required:
            is_compliant = (ram_status == "enabled")
        else:
            is_compliant = (ram_status == "disabled" or ram_status == "not_configured")
            
        if is_compliant:
            result['status'] = 'passed'
        else:
            result['status'] = 'failed'
            if required:
                result['violations'].append({
                    'policy': 'rdp_restricted_admin',
                    'expected': True,
                    'actual': False,
                    'severity': 'high',
                    'description': 'Restricted Admin Mode is not enabled as required by CyberArk PAPM policy',
                    'remediation': 'Enable Restricted Admin Mode by setting DisableRestrictedAdmin=0 in the registry'
                })
            else:
                result['violations'].append({
                    'policy': 'rdp_restricted_admin',
                    'expected': False,
                    'actual': True,
                    'severity': 'medium',
                    'description': 'Restricted Admin Mode is enabled but should be disabled according to CyberArk PAPM policy',
                    'remediation': 'Disable Restricted Admin Mode by setting DisableRestrictedAdmin=1 in the registry'
                })
                
    except Exception as e:
        logger.error(f"Error validating Restricted Admin Mode: {e}")
        result['status'] = 'error'
        result['findings'].append(f"Error: {str(e)}")
    
    return result


def validate_certificate_validation(session, target: str, required: bool = True) -> Dict[str, Any]:
    """Validate certificate validation requirements
    
    Args:
        session: WinRM session object
        target: Target hostname or IP
        required: Whether certificate validation is required by policy
        
    Returns:
        Dict: Test results with findings
    """
    logger.info(f"Validating certificate validation settings on {target}...")
    
    result = {
        'test': 'certificate_validation',
        'status': 'unknown',
        'findings': [],
        'violations': []
    }
    
    try:
        # Query certificate validation settings
        ps_script = """$auth = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" -Name "AuthenticationLevel" -ErrorAction SilentlyContinue
                      if ($auth -ne $null) {
                          Write-Output $auth.AuthenticationLevel
                      } else {
                          # Default is typically 2
                          Write-Output "not_configured"
                      }"""
        
        result_data = session.run_ps(ps_script)
        auth_level = result_data.std_out.decode('utf-8').strip().lower()
        
        if auth_level == "not_configured":
            result['findings'].append("Certificate validation setting is not explicitly configured")
            auth_level = "2"  # Default value
        
        # Map authentication levels
        auth_map = {
            "0": "no_authentication",
            "1": "warn_if_authentication_fails",
            "2": "require_authentication"
        }
        
        auth_desc = auth_map.get(auth_level, f"unknown_{auth_level}")
        result['findings'].append(f"Certificate authentication level: {auth_desc}")
        
        # Check compliance with policy
        cert_validation_enabled = (auth_level == "2")
        if (required and cert_validation_enabled) or (not required and not cert_validation_enabled):
            result['status'] = 'passed'
        else:
            result['status'] = 'failed'
            if required:
                result['violations'].append({
                    'policy': 'certificate_validation',
                    'expected': True,
                    'actual': False,
                    'severity': 'high',
                    'description': 'Certificate validation is not properly configured as required by CyberArk PAPM policy',
                    'remediation': 'Enable certificate validation by setting AuthenticationLevel=2 in the registry'
                })
            else:
                result['violations'].append({
                    'policy': 'certificate_validation',
                    'expected': False,
                    'actual': True,
                    'severity': 'low',
                    'description': 'Certificate validation is enabled but not required by CyberArk PAPM policy',
                    'remediation': 'Consider keeping certificate validation enabled for security'
                })
                
    except Exception as e:
        logger.error(f"Error validating certificate validation: {e}")
        result['status'] = 'error'
        result['findings'].append(f"Error: {str(e)}")
    
    return result


def check_cyberark_auth_integration(session, target: str) -> Dict[str, Any]:
    """Check for CyberArk authentication integration
    
    Args:
        session: WinRM session object
        target: Target hostname or IP
        
    Returns:
        Dict: Test results with findings
    """
    logger.info(f"Checking CyberArk authentication integration on {target}...")
    
    result = {
        'test': 'cyberark_auth_integration',
        'status': 'unknown',
        'findings': [],
        'vulnerabilities': []
    }
    
    try:
        # Check for CyberArk PSM components
        ps_script = """$psmComponents = @(
            "C:\\Program Files\\CyberArk\\PSM\\Components",
            "C:\\Program Files\\CyberArk\\PSM\\Logs",
            "C:\\Program Files (x86)\\CyberArk\\PSM"
        )
        
        $found = $false
        foreach ($path in $psmComponents) {
            if (Test-Path $path) {
                Write-Output "FOUND:$path"
                $found = $true
            }
        }
        
        # Check for CyberArk registry keys
        $cyberArkKey = "HKLM:\\SOFTWARE\\CyberArk\\PSM"
        if (Test-Path $cyberArkKey) {
            Write-Output "FOUND:CyberArk_PSM_Registry"
            $found = $true
            
            $version = Get-ItemProperty -Path $cyberArkKey -Name "Version" -ErrorAction SilentlyContinue
            if ($version) {
                Write-Output "VERSION:$($version.Version)"
            }
        }
        
        # Check for EPM client
        $epmPath = "C:\\Program Files\\CyberArk\\EPM\\Agent"
        if (Test-Path $epmPath) {
            Write-Output "FOUND:CyberArk_EPM_Agent"
            $found = $true
        }
        
        if (-not $found) {
            Write-Output "NO_CYBERARK_COMPONENTS_FOUND"
        }"""
        
        result_data = session.run_ps(ps_script)
        output_lines = result_data.std_out.decode('utf-8').strip().split('\n')
        
        cyberark_components = []
        cyberark_version = None
        
        for line in output_lines:
            line = line.strip()
            if line.startswith("FOUND:"):
                component = line[6:]
                cyberark_components.append(component)
                result['findings'].append(f"Found CyberArk component: {component}")
            elif line.startswith("VERSION:"):
                cyberark_version = line[8:]
                result['findings'].append(f"CyberArk PSM version: {cyberark_version}")
            elif line == "NO_CYBERARK_COMPONENTS_FOUND":
                result['findings'].append("No CyberArk components found")
        
        # Determine status based on findings
        if cyberark_components:
            result['status'] = 'passed'
            result['findings'].append("CyberArk integration detected")
        else:
            result['status'] = 'warning'  # Not a failure, but may be a concern
            result['findings'].append("No CyberArk integration detected")
            result['vulnerabilities'].append({
                'severity': 'medium',
                'description': 'System does not appear to have CyberArk privileged access components installed',
                'remediation': 'Consider implementing CyberArk PSM for secure privileged access management'
            })
                
    except Exception as e:
        logger.error(f"Error checking CyberArk auth integration: {e}")
        result['status'] = 'error'
        result['findings'].append(f"Error: {str(e)}")
    
    return result


# Main function for testing
if __name__ == "__main__":
    print("CyberArk PAPM RDP Policy Authentication Validator")
    print("This module should be imported by the main validator module")
    print("For standalone testing, use the main cyberark_policy_validator.py")
