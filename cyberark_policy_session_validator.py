#!/usr/bin/env python3
"""
CyberArk PAPM RDP Session Policy Validator
This module validates RDP session timeout and security settings against CyberArk PAPM policies.
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
        logging.FileHandler('cyberark_session_validation.log')
    ]
)
logger = logging.getLogger(__name__)

def validate_session_timeout(session, target: str, max_idle_time: int = 600, 
                            max_session_time: int = 28800) -> Dict[str, Any]:
    """Validate session timeout settings
    
    Args:
        session: WinRM session object
        target: Target hostname or IP
        max_idle_time: Maximum idle time in seconds
        max_session_time: Maximum session duration in seconds
        
    Returns:
        Dict: Test results with findings
    """
    logger.info(f"Validating session timeout settings on {target}...")
    
    result = {
        'test': 'session_timeout',
        'status': 'unknown',
        'findings': [],
        'violations': []
    }
    
    try:
        # Query session timeout settings
        ps_script = """# Idle timeout
                      $idleTimeout = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" -Name "MaxIdleTime" -ErrorAction SilentlyContinue
                      if ($idleTimeout -ne $null) {
                          Write-Output "idle:$($idleTimeout.MaxIdleTime)"
                      } else {
                          # Default is no timeout
                          Write-Output "idle:0"
                      }
                      
                      # Session timeout
                      $sessionTimeout = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" -Name "MaxDisconnectionTime" -ErrorAction SilentlyContinue
                      if ($sessionTimeout -ne $null) {
                          Write-Output "session:$($sessionTimeout.MaxDisconnectionTime)"
                      } else {
                          # Default is no timeout
                          Write-Output "session:0"
                      }
                      
                      # Max connection time
                      $maxConnectionTime = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" -Name "MaxConnectionTime" -ErrorAction SilentlyContinue
                      if ($maxConnectionTime -ne $null) {
                          Write-Output "connection:$($maxConnectionTime.MaxConnectionTime)"
                      } else {
                          # Default is no limit
                          Write-Output "connection:0"
                      }"""
        
        result_data = session.run_ps(ps_script)
        timeout_settings = result_data.std_out.decode('utf-8').strip().split('\n')
        
        actual_idle_timeout = 0
        actual_session_timeout = 0
        actual_connection_timeout = 0
        
        violations = []
        
        for setting in timeout_settings:
            setting = setting.strip()
            if setting.startswith("idle:"):
                # Note: Registry values are in milliseconds
                actual_idle_timeout = int(setting.split(':')[1]) / 1000
                result['findings'].append(f"Idle timeout: {actual_idle_timeout} seconds")
                
                if actual_idle_timeout == 0 or actual_idle_timeout > max_idle_time:
                    violations.append({
                        'policy': 'max_idle_time',
                        'expected': max_idle_time,
                        'actual': actual_idle_timeout,
                        'severity': 'medium',
                        'description': f'Idle timeout ({actual_idle_timeout}s) exceeds CyberArk PAPM maximum ({max_idle_time}s)',
                        'remediation': f'Set MaxIdleTime to {max_idle_time * 1000} milliseconds or less in the registry'
                    })
                    
            elif setting.startswith("session:"):
                # Convert milliseconds to seconds
                actual_session_timeout = int(setting.split(':')[1]) / 1000
                result['findings'].append(f"Session timeout: {actual_session_timeout} seconds")
                
                if actual_session_timeout == 0 or actual_session_timeout > max_session_time:
                    violations.append({
                        'policy': 'max_session_time',
                        'expected': max_session_time,
                        'actual': actual_session_timeout,
                        'severity': 'high',
                        'description': f'Session timeout ({actual_session_timeout}s) exceeds CyberArk PAPM maximum ({max_session_time}s)',
                        'remediation': f'Set MaxDisconnectionTime to {max_session_time * 1000} milliseconds or less in the registry'
                    })
                    
            elif setting.startswith("connection:"):
                # Convert milliseconds to seconds
                actual_connection_timeout = int(setting.split(':')[1]) / 1000
                result['findings'].append(f"Connection timeout: {actual_connection_timeout} seconds")
                
                if actual_connection_timeout == 0 or actual_connection_timeout > max_session_time:
                    violations.append({
                        'policy': 'max_connection_time',
                        'expected': max_session_time,
                        'actual': actual_connection_timeout,
                        'severity': 'medium',
                        'description': f'Connection timeout ({actual_connection_timeout}s) exceeds CyberArk PAPM maximum ({max_session_time}s)',
                        'remediation': f'Set MaxConnectionTime to {max_session_time * 1000} milliseconds or less in the registry'
                    })
        
        # Determine overall compliance
        if violations:
            result['status'] = 'failed'
            result['violations'] = violations
        else:
            result['status'] = 'passed'
            result['findings'].append("All session timeout settings comply with CyberArk PAPM policy")
                
    except Exception as e:
        logger.error(f"Error validating session timeout: {e}")
        result['status'] = 'error'
        result['findings'].append(f"Error: {str(e)}")
    
    return result


def validate_remote_credential_guard(session, target: str, required: bool = True) -> Dict[str, Any]:
    """Validate Remote Credential Guard settings
    
    Args:
        session: WinRM session object
        target: Target hostname or IP
        required: Whether Remote Credential Guard is required by policy
        
    Returns:
        Dict: Test results with findings
    """
    logger.info(f"Validating Remote Credential Guard on {target}...")
    
    result = {
        'test': 'remote_credential_guard',
        'status': 'unknown',
        'findings': [],
        'violations': []
    }
    
    try:
        # Query Remote Credential Guard settings
        ps_script = """# Check Group Policy setting first
                      $gpSetting = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation" -Name "RestrictedRemoteCredentialGuard" -ErrorAction SilentlyContinue
                      if ($gpSetting -ne $null) {
                          Write-Output "RCG:$($gpSetting.RestrictedRemoteCredentialGuard)"
                      } else {
                          $localSetting = Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "RestrictedRemoteCredentialGuard" -ErrorAction SilentlyContinue
                          if ($localSetting -ne $null) {
                              Write-Output "RCG:$($localSetting.RestrictedRemoteCredentialGuard)"
                          } else {
                              # Default is disabled (0)
                              Write-Output "RCG:0"
                          }
                      }
                      
                      # Also check if Remote Credential Guard is supported (Windows 10/Server 2016 or later)
                      $osVersion = [System.Environment]::OSVersion.Version
                      if (($osVersion.Major -gt 10) -or ($osVersion.Major -eq 10 -and $osVersion.Build -ge 14393)) {
                          Write-Output "SUPPORTED:1"
                      } else {
                          Write-Output "SUPPORTED:0"
                      }"""
        
        result_data = session.run_ps(ps_script)
        rcg_settings = result_data.std_out.decode('utf-8').strip().split('\n')
        
        rcg_enabled = False
        rcg_supported = False
        
        for setting in rcg_settings:
            setting = setting.strip()
            if setting.startswith("RCG:"):
                rcg_value = int(setting.split(':')[1])
                rcg_enabled = (rcg_value == 1)
                result['findings'].append(f"Remote Credential Guard is {'enabled' if rcg_enabled else 'disabled'}")
            elif setting.startswith("SUPPORTED:"):
                rcg_supported = (int(setting.split(':')[1]) == 1)
                result['findings'].append(f"Remote Credential Guard is {'supported' if rcg_supported else 'not supported'} on this OS")
        
        # Check compliance with policy
        if not rcg_supported:
            result['status'] = 'warning'
            result['findings'].append("Remote Credential Guard is not supported on this OS version")
            if required:
                result['violations'].append({
                    'policy': 'remote_credential_guard',
                    'expected': True,
                    'actual': 'unsupported',
                    'severity': 'high',
                    'description': 'Remote Credential Guard is required by policy but not supported on this OS version',
                    'remediation': 'Upgrade to Windows 10/Server 2016 or later to support Remote Credential Guard'
                })
        else:
            if (required and rcg_enabled) or (not required and not rcg_enabled):
                result['status'] = 'passed'
            else:
                result['status'] = 'failed'
                if required:
                    result['violations'].append({
                        'policy': 'remote_credential_guard',
                        'expected': True,
                        'actual': False,
                        'severity': 'high',
                        'description': 'Remote Credential Guard is not enabled as required by CyberArk PAPM policy',
                        'remediation': 'Enable Remote Credential Guard through Group Policy or registry'
                    })
                else:
                    result['violations'].append({
                        'policy': 'remote_credential_guard',
                        'expected': False,
                        'actual': True,
                        'severity': 'low',
                        'description': 'Remote Credential Guard is enabled but not required by CyberArk PAPM policy',
                        'remediation': 'Consider keeping Remote Credential Guard enabled for security'
                    })
                    
    except Exception as e:
        logger.error(f"Error validating Remote Credential Guard: {e}")
        result['status'] = 'error'
        result['findings'].append(f"Error: {str(e)}")
    
    return result


def validate_rdp_shortpath(session, target: str, allowed: bool = False) -> Dict[str, Any]:
    """Validate RDP Shortpath settings
    
    Args:
        session: WinRM session object
        target: Target hostname or IP
        allowed: Whether RDP Shortpath is allowed by policy
        
    Returns:
        Dict: Test results with findings
    """
    logger.info(f"Validating RDP Shortpath on {target}...")
    
    result = {
        'test': 'rdp_shortpath',
        'status': 'unknown',
        'findings': [],
        'violations': []
    }
    
    try:
        # Query RDP Shortpath settings
        ps_script = """# Check if RDP Shortpath is enabled
                      $shortpath = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" -Name "fUseUdpPortRedirector" -ErrorAction SilentlyContinue
                      if ($shortpath -ne $null) {
                          Write-Output "SHORTPATH:$($shortpath.fUseUdpPortRedirector)"
                      } else {
                          # Check local setting
                          $localShortpath = Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations" -Name "fUseUdpPortRedirector" -ErrorAction SilentlyContinue
                          if ($localShortpath -ne $null) {
                              Write-Output "SHORTPATH:$($localShortpath.fUseUdpPortRedirector)"
                          } else {
                              # Default depends on OS version, typically 1 (enabled) on newer systems
                              $osVersion = [System.Environment]::OSVersion.Version
                              if (($osVersion.Major -gt 10) -or ($osVersion.Major -eq 10 -and $osVersion.Build -ge 19041)) {
                                  # Windows 10 20H1 or later - enabled by default
                                  Write-Output "SHORTPATH:1"
                              } else {
                                  # Earlier versions - disabled by default
                                  Write-Output "SHORTPATH:0"
                              }
                          }
                      }"""
        
        result_data = session.run_ps(ps_script)
        shortpath_settings = result_data.std_out.decode('utf-8').strip().split('\n')
        
        shortpath_enabled = False
        
        for setting in shortpath_settings:
            setting = setting.strip()
            if setting.startswith("SHORTPATH:"):
                shortpath_value = int(setting.split(':')[1])
                shortpath_enabled = (shortpath_value == 1)
                result['findings'].append(f"RDP Shortpath is {'enabled' if shortpath_enabled else 'disabled'}")
        
        # Check compliance with policy
        if (allowed and shortpath_enabled) or (not allowed and not shortpath_enabled):
            result['status'] = 'passed'
            result['findings'].append("RDP Shortpath setting complies with CyberArk PAPM policy")
        else:
            result['status'] = 'failed'
            if allowed:
                result['violations'].append({
                    'policy': 'rdp_shortpath',
                    'expected': True,
                    'actual': False,
                    'severity': 'low',
                    'description': 'RDP Shortpath is disabled but allowed by CyberArk PAPM policy',
                    'remediation': 'Enable RDP Shortpath by setting fUseUdpPortRedirector=1 in the registry'
                })
            else:
                result['violations'].append({
                    'policy': 'rdp_shortpath',
                    'expected': False,
                    'actual': True,
                    'severity': 'medium',
                    'description': 'RDP Shortpath is enabled but should be disabled according to CyberArk PAPM policy',
                    'remediation': 'Disable RDP Shortpath by setting fUseUdpPortRedirector=0 in the registry'
                })
                
    except Exception as e:
        logger.error(f"Error validating RDP Shortpath: {e}")
        result['status'] = 'error'
        result['findings'].append(f"Error: {str(e)}")
    
    return result


def validate_session_security(session, target: str, policies: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Validate all session security settings based on supplied policies
    
    Args:
        session: WinRM session object
        target: Target hostname or IP
        policies: Dictionary of policy settings
        
    Returns:
        Dict: Combined test results
    """
    logger.info(f"Validating all session security settings on {target}...")
    
    results = {}
    
    # Session timeout
    max_idle_time = policies.get("max_idle_time", 600)
    max_session_time = policies.get("max_session_time", 28800)
    results['timeout'] = validate_session_timeout(
        session, target, max_idle_time, max_session_time)
    
    # Remote Credential Guard
    rcg_required = policies.get("remote_credential_guard", True)
    results['credential_guard'] = validate_remote_credential_guard(
        session, target, rcg_required)
    
    # RDP Shortpath
    shortpath_allowed = policies.get("rdp_shortpath", False)
    results['shortpath'] = validate_rdp_shortpath(
        session, target, shortpath_allowed)
    
    logger.info(f"Completed session security validation for {target}")
    return results


# Main function for testing
if __name__ == "__main__":
    print("CyberArk PAPM RDP Session Policy Validator")
    print("This module should be imported by the main validator module")
    print("For standalone testing, use the main cyberark_policy_validator.py")
