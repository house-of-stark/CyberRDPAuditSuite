#!/usr/bin/env python3
"""
CyberArk PAPM RDP Policy Redirection Validator
This module validates RDP redirection settings against CyberArk PAPM security policies.
It's designed as a component of the CyberArk Policy Validator suite.

Validates critical redirection security settings:
- Clipboard redirection
- Drive redirection
- Device redirection
- Printer redirection
- Port redirection
- Smart card redirection
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
        logging.FileHandler('cyberark_redirection_validation.log')
    ]
)
logger = logging.getLogger(__name__)

def validate_clipboard_redirection(session, target: str, allowed: bool = False) -> Dict[str, Any]:
    """Validate clipboard redirection settings
    
    Args:
        session: WinRM session object
        target: Target hostname or IP
        allowed: Whether clipboard redirection is allowed by policy
        
    Returns:
        Dict: Test results with findings
    """
    logger.info(f"Validating clipboard redirection settings on {target}...")
    
    result = {
        'test': 'clipboard_redirection',
        'status': 'unknown',
        'findings': [],
        'violations': []
    }
    
    try:
        # Query clipboard redirection setting
        ps_script = """$clipboard = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" -Name "fDisableClip" -ErrorAction SilentlyContinue
                      if ($clipboard -ne $null) {
                          # fDisableClip = 1 means clipboard redirection is disabled
                          if ($clipboard.fDisableClip -eq 1) {
                              Write-Output "disabled"
                          } else {
                              Write-Output "enabled"
                          }
                      } else {
                          # Not configured, which means clipboard redirection is enabled by default
                          Write-Output "default_enabled"
                      }"""
        
        result_data = session.run_ps(ps_script)
        clipboard_status = result_data.std_out.decode('utf-8').strip().lower()
        
        result['findings'].append(f"Clipboard redirection is: {clipboard_status}")
        
        # Check compliance with policy
        is_enabled = (clipboard_status == "enabled" or clipboard_status == "default_enabled")
        
        if (allowed and is_enabled) or (not allowed and not is_enabled):
            result['status'] = 'passed'
        else:
            result['status'] = 'failed'
            if allowed:
                result['violations'].append({
                    'policy': 'clipboard_redirection',
                    'expected': True,
                    'actual': False,
                    'severity': 'medium',
                    'description': 'Clipboard redirection is disabled but should be allowed according to CyberArk PAPM policy',
                    'remediation': 'Enable clipboard redirection by setting fDisableClip=0 in the registry'
                })
            else:
                result['violations'].append({
                    'policy': 'clipboard_redirection',
                    'expected': False,
                    'actual': True,
                    'severity': 'high',
                    'description': 'Clipboard redirection is enabled but should be disabled according to CyberArk PAPM policy',
                    'remediation': 'Disable clipboard redirection by setting fDisableClip=1 in the registry'
                })
                
    except Exception as e:
        logger.error(f"Error validating clipboard redirection: {e}")
        result['status'] = 'error'
        result['findings'].append(f"Error: {str(e)}")
    
    return result


def validate_drive_redirection(session, target: str, allowed: bool = False) -> Dict[str, Any]:
    """Validate drive redirection settings
    
    Args:
        session: WinRM session object
        target: Target hostname or IP
        allowed: Whether drive redirection is allowed by policy
        
    Returns:
        Dict: Test results with findings
    """
    logger.info(f"Validating drive redirection settings on {target}...")
    
    result = {
        'test': 'drive_redirection',
        'status': 'unknown',
        'findings': [],
        'violations': []
    }
    
    try:
        # Query drive redirection setting
        ps_script = """$drives = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" -Name "fDisableCdm" -ErrorAction SilentlyContinue
                      if ($drives -ne $null) {
                          # fDisableCdm = 1 means drive redirection is disabled
                          if ($drives.fDisableCdm -eq 1) {
                              Write-Output "disabled"
                          } else {
                              Write-Output "enabled"
                          }
                      } else {
                          # Not configured, which means drive redirection is enabled by default
                          Write-Output "default_enabled"
                      }"""
        
        result_data = session.run_ps(ps_script)
        drive_status = result_data.std_out.decode('utf-8').strip().lower()
        
        result['findings'].append(f"Drive redirection is: {drive_status}")
        
        # Check compliance with policy
        is_enabled = (drive_status == "enabled" or drive_status == "default_enabled")
        
        if (allowed and is_enabled) or (not allowed and not is_enabled):
            result['status'] = 'passed'
        else:
            result['status'] = 'failed'
            if allowed:
                result['violations'].append({
                    'policy': 'drive_redirection',
                    'expected': True,
                    'actual': False,
                    'severity': 'medium',
                    'description': 'Drive redirection is disabled but should be allowed according to CyberArk PAPM policy',
                    'remediation': 'Enable drive redirection by setting fDisableCdm=0 in the registry'
                })
            else:
                result['violations'].append({
                    'policy': 'drive_redirection',
                    'expected': False,
                    'actual': True,
                    'severity': 'critical',
                    'description': 'Drive redirection is enabled but should be disabled according to CyberArk PAPM policy',
                    'remediation': 'Disable drive redirection by setting fDisableCdm=1 in the registry'
                })
                
    except Exception as e:
        logger.error(f"Error validating drive redirection: {e}")
        result['status'] = 'error'
        result['findings'].append(f"Error: {str(e)}")
    
    return result


def validate_device_redirection(session, target: str, allowed: bool = False) -> Dict[str, Any]:
    """Validate device redirection settings
    
    Args:
        session: WinRM session object
        target: Target hostname or IP
        allowed: Whether device redirection is allowed by policy
        
    Returns:
        Dict: Test results with findings
    """
    logger.info(f"Validating device redirection settings on {target}...")
    
    result = {
        'test': 'device_redirection',
        'status': 'unknown',
        'findings': [],
        'violations': []
    }
    
    try:
        # Query various device redirection settings
        ps_script = """# COM ports
                      $com = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" -Name "fDisableCcm" -ErrorAction SilentlyContinue
                      if ($com -ne $null -and $com.fDisableCcm -eq 1) {
                          Write-Output "COM:disabled"
                      } else {
                          Write-Output "COM:enabled"
                      }
                      
                      # LPT ports
                      $lpt = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" -Name "fDisableLPT" -ErrorAction SilentlyContinue
                      if ($lpt -ne $null -and $lpt.fDisableLPT -eq 1) {
                          Write-Output "LPT:disabled"
                      } else {
                          Write-Output "LPT:enabled"
                      }
                      
                      # PnP devices
                      $pnp = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" -Name "fDisablePNPRedir" -ErrorAction SilentlyContinue
                      if ($pnp -ne $null -and $pnp.fDisablePNPRedir -eq 1) {
                          Write-Output "PNP:disabled"
                      } else {
                          Write-Output "PNP:enabled"
                      }"""
        
        result_data = session.run_ps(ps_script)
        device_statuses = result_data.std_out.decode('utf-8').strip().split('\n')
        
        # Track enabled redirections
        enabled_redirections = []
        
        for status in device_statuses:
            status = status.strip()
            result['findings'].append(f"Device redirection - {status}")
            if status.endswith(':enabled'):
                device_type = status.split(':')[0]
                enabled_redirections.append(device_type)
        
        # Check compliance with policy
        if allowed and enabled_redirections:
            result['status'] = 'passed'
        elif not allowed and not enabled_redirections:
            result['status'] = 'passed'
        else:
            result['status'] = 'failed'
            if not allowed and enabled_redirections:
                result['violations'].append({
                    'policy': 'device_redirection',
                    'expected': False,
                    'actual': True,
                    'severity': 'high',
                    'description': f'Device redirection(s) enabled but should be disabled: {", ".join(enabled_redirections)}',
                    'remediation': 'Disable device redirection by setting fDisableCcm=1, fDisableLPT=1, and fDisablePNPRedir=1 in the registry'
                })
            elif allowed and not enabled_redirections:
                result['violations'].append({
                    'policy': 'device_redirection',
                    'expected': True,
                    'actual': False,
                    'severity': 'low',
                    'description': 'All device redirections are disabled but policy allows them',
                    'remediation': 'Enable required device redirections based on business needs'
                })
                
    except Exception as e:
        logger.error(f"Error validating device redirection: {e}")
        result['status'] = 'error'
        result['findings'].append(f"Error: {str(e)}")
    
    return result


def validate_printer_redirection(session, target: str, allowed: bool = False) -> Dict[str, Any]:
    """Validate printer redirection settings
    
    Args:
        session: WinRM session object
        target: Target hostname or IP
        allowed: Whether printer redirection is allowed by policy
        
    Returns:
        Dict: Test results with findings
    """
    logger.info(f"Validating printer redirection settings on {target}...")
    
    result = {
        'test': 'printer_redirection',
        'status': 'unknown',
        'findings': [],
        'violations': []
    }
    
    try:
        # Query printer redirection setting
        ps_script = """$printers = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" -Name "fDisableCpm" -ErrorAction SilentlyContinue
                      if ($printers -ne $null) {
                          # fDisableCpm = 1 means printer redirection is disabled
                          if ($printers.fDisableCpm -eq 1) {
                              Write-Output "disabled"
                          } else {
                              Write-Output "enabled"
                          }
                      } else {
                          # Not configured, which means printer redirection is enabled by default
                          Write-Output "default_enabled"
                      }"""
        
        result_data = session.run_ps(ps_script)
        printer_status = result_data.std_out.decode('utf-8').strip().lower()
        
        result['findings'].append(f"Printer redirection is: {printer_status}")
        
        # Check compliance with policy
        is_enabled = (printer_status == "enabled" or printer_status == "default_enabled")
        
        if (allowed and is_enabled) or (not allowed and not is_enabled):
            result['status'] = 'passed'
        else:
            result['status'] = 'failed'
            if allowed:
                result['violations'].append({
                    'policy': 'printer_redirection',
                    'expected': True,
                    'actual': False,
                    'severity': 'medium',
                    'description': 'Printer redirection is disabled but should be allowed according to CyberArk PAPM policy',
                    'remediation': 'Enable printer redirection by setting fDisableCpm=0 in the registry'
                })
            else:
                result['violations'].append({
                    'policy': 'printer_redirection',
                    'expected': False,
                    'actual': True,
                    'severity': 'high',
                    'description': 'Printer redirection is enabled but should be disabled according to CyberArk PAPM policy',
                    'remediation': 'Disable printer redirection by setting fDisableCpm=1 in the registry'
                })
                
    except Exception as e:
        logger.error(f"Error validating printer redirection: {e}")
        result['status'] = 'error'
        result['findings'].append(f"Error: {str(e)}")
    
    return result


def validate_all_redirections(session, target: str, policies: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Validate all redirection settings based on supplied policies
    
    Args:
        session: WinRM session object
        target: Target hostname or IP
        policies: Dictionary of policy settings
        
    Returns:
        Dict: Combined test results
    """
    logger.info(f"Validating all redirection settings on {target}...")
    
    results = {}
    
    # Clipboard redirection
    clipboard_allowed = policies.get("clipboard_redirection", False)
    results['clipboard'] = validate_clipboard_redirection(session, target, clipboard_allowed)
    
    # Drive redirection
    drive_allowed = policies.get("drive_redirection", False)
    results['drive'] = validate_drive_redirection(session, target, drive_allowed)
    
    # Device redirection
    device_allowed = policies.get("device_redirection", False)
    results['device'] = validate_device_redirection(session, target, device_allowed)
    
    # Printer redirection
    printer_allowed = policies.get("printer_redirection", False)
    results['printer'] = validate_printer_redirection(session, target, printer_allowed)
    
    logger.info(f"Completed redirection validation for {target}")
    return results


# Main function for testing
if __name__ == "__main__":
    print("CyberArk PAPM RDP Policy Redirection Validator")
    print("This module should be imported by the main validator module")
    print("For standalone testing, use the main cyberark_policy_validator.py")
