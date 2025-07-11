#!/usr/bin/env python3
"""
Shadow Session Security Tester
This module tests the security of RDP shadow session functionality.

The module focuses on:
1. Detecting if shadow sessions are enabled
2. Testing shadow session permission controls
3. Testing notification settings
4. Checking for proper auditing and logging
5. Testing session control permissions
"""

import os
import sys
import json
import time
import socket
import logging
import subprocess
import argparse
import winrm
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('rdp_shadow_tests.log')
    ]
)
logger = logging.getLogger(__name__)

class RDPShadowTester:
    """Tests RDP shadow session security characteristics"""
    
    def __init__(self, target: str, port: int = 3389, username: str = None, 
                 password: str = None, domain: str = "", admin_username: str = None,
                 admin_password: str = None, admin_domain: str = "", verbose: bool = False):
        """Initialize the shadow session tester with target information"""
        self.target = target
        self.port = port
        self.username = username
        self.password = password
        self.domain = domain
        self.admin_username = admin_username or username
        self.admin_password = admin_password or password
        self.admin_domain = admin_domain or domain
        self.verbose = verbose
        
        # Results dictionary to store findings
        self.results = {
            'target': target,
            'port': port,
            'timestamp': datetime.utcnow().isoformat(),
            'shadow_enabled': None,
            'vulnerabilities': [],
            'recommendations': [],
            'tests': {},
        }
        
        # Initialize counters
        self.tests_run = 0
        self.tests_passed = 0
        self.tests_failed = 0
        
    def detect_shadow_session_enabled(self) -> bool:
        """Detect if shadow sessions are enabled on the target
        
        Returns:
            bool: True if shadow sessions are enabled, False otherwise
        """
        logger.info(f"Detecting if shadow sessions are enabled on {self.target}...")
        self.tests_run += 1
        
        # Method 1: Query using PowerShell remotely (requires WinRM)
        try:
            if self.admin_username and self.admin_password:
                # Connect to WinRM
                session = winrm.Session(f'http://{self.target}:5985/wsman',
                                        auth=(f"{self.admin_domain}\\{self.admin_username}" 
                                              if self.admin_domain else self.admin_username, 
                                             self.admin_password))
                
                # Query Terminal Services Configuration
                ps_script = """$tsconfig = Get-WmiObject -class "Win32_TerminalServiceSetting" -namespace "root\\cimv2\\terminalservices"
                              if ($tsconfig.AllowShadow -eq 1) { Write-Output "Enabled" } else { Write-Output "Disabled" }"""
                result = session.run_ps(ps_script)
                
                if "Enabled" in result.std_out.decode('utf-8'):
                    logger.info("Shadow sessions are enabled")
                    self.tests_passed += 1
                    return True
                else:
                    logger.info("Shadow sessions are disabled")
                    self.tests_failed += 1
                    return False
            else:
                logger.warning("Admin credentials not provided, using alternate detection method")
        except Exception as e:
            logger.warning(f"WinRM detection failed: {e}, falling back to registry query")
            
        # Method 2: Try via registry query if possible (less reliable)
        try:
            if self.admin_username and self.admin_password:
                session = winrm.Session(f'http://{self.target}:5985/wsman',
                                        auth=(f"{self.admin_domain}\\{self.admin_username}" 
                                              if self.admin_domain else self.admin_username, 
                                             self.admin_password))
                
                # Query shadow registry key
                ps_script = """$regKey = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" -Name "Shadow" -ErrorAction SilentlyContinue
                              if ($regKey -and $regKey.Shadow -ne 0) { Write-Output "Enabled" } else { Write-Output "Unknown" }"""
                result = session.run_ps(ps_script)
                
                if "Enabled" in result.std_out.decode('utf-8'):
                    logger.info("Shadow sessions are enabled via registry")
                    self.tests_passed += 1
                    return True
                elif "Unknown" in result.std_out.decode('utf-8'):
                    logger.warning("Shadow session state could not be determined via registry")
                    # Don't consider this a failure as the registry key might not exist
                    return None
                else:
                    logger.info("Shadow sessions are disabled via registry")
                    self.tests_failed += 1
                    return False
        except Exception as e:
            logger.warning(f"Registry query failed: {e}")
        
        # If we can't determine for sure, assume it might be enabled
        # but mark it as unknown in the results
        logger.warning("Could not definitively determine shadow session status")
        return None
    
    def test_shadow_permissions(self) -> Dict[str, Any]:
        """Test the security of shadow session permissions
        
        Returns:
            Dict: Test results with findings
        """
        logger.info("Testing shadow session permission controls...")
        self.tests_run += 1
        
        result = {
            'test': 'shadow_permissions',
            'status': 'unknown',
            'findings': [],
            'vulnerabilities': []
        }
        
        try:
            if not self.admin_username or not self.admin_password:
                logger.warning("Admin credentials required for shadow permission testing")
                result['status'] = 'skipped'
                result['findings'].append("No admin credentials provided for testing")
                return result
                
            # Connect to WinRM
            session = winrm.Session(f'http://{self.target}:5985/wsman',
                                    auth=(f"{self.admin_domain}\\{self.admin_username}" 
                                          if self.admin_domain else self.admin_username, 
                                         self.admin_password))
            
            # Query shadow permission level via registry
            ps_script = """$regKey = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" -Name "Shadow" -ErrorAction SilentlyContinue
                          if ($regKey) { Write-Output $regKey.Shadow } else { 
                              # Try default Windows location
                              $regKey = Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" -Name "Shadow" -ErrorAction SilentlyContinue
                              if ($regKey) { Write-Output $regKey.Shadow } else { Write-Output "NotFound" }
                          }"""
            result_data = session.run_ps(ps_script)
            shadow_level = result_data.std_out.decode('utf-8').strip()
            
            if shadow_level == "NotFound":
                result['findings'].append("Shadow permission registry key not found")
                result['status'] = 'warning'
                return result
                
            # Check shadow permission level
            # 0: Disabled, 1: Full Control w/o permission, 2: Full Control w/ permission
            # 3: View Only w/o permission, 4: View Only w/ permission
            try:
                shadow_level = int(shadow_level)
                if shadow_level == 0:
                    result['status'] = 'passed'
                    result['findings'].append("Shadow sessions are disabled")
                elif shadow_level == 1:
                    result['status'] = 'failed'
                    result['findings'].append("Shadow sessions allow full control without permission")
                    result['vulnerabilities'].append({
                        'severity': 'high',
                        'description': 'Shadow sessions configured to allow full control without user permission',
                        'remediation': 'Change shadow session configuration to require user permission (level 2 or 4)'
                    })
                elif shadow_level == 2:
                    result['status'] = 'passed'
                    result['findings'].append("Shadow sessions require permission for full control")
                elif shadow_level == 3:
                    result['status'] = 'warning'
                    result['findings'].append("Shadow sessions allow view-only access without permission")
                    result['vulnerabilities'].append({
                        'severity': 'medium',
                        'description': 'Shadow sessions configured to allow view-only without user permission',
                        'remediation': 'Change shadow session configuration to require user permission (level 2 or 4)'
                    })
                elif shadow_level == 4:
                    result['status'] = 'passed'
                    result['findings'].append("Shadow sessions require permission for view-only access")
                else:
                    result['status'] = 'warning'
                    result['findings'].append(f"Unknown shadow permission level: {shadow_level}")
            except ValueError:
                result['status'] = 'warning'
                result['findings'].append(f"Unable to parse shadow level value: {shadow_level}")
            
        except Exception as e:
            logger.error(f"Error testing shadow permissions: {e}")
            result['status'] = 'error'
            result['findings'].append(f"Error: {str(e)}")
        
        if result['status'] == 'passed':
            self.tests_passed += 1
        elif result['status'] in ['failed', 'error']:
            self.tests_failed += 1
            
        return result
    
    def test_notification_settings(self) -> Dict[str, Any]:
        """Test shadow session notification settings
        
        Returns:
            Dict: Test results with findings
        """
        logger.info("Testing shadow session notification settings...")
        self.tests_run += 1
        
        result = {
            'test': 'shadow_notifications',
            'status': 'unknown',
            'findings': [],
            'vulnerabilities': []
        }
        
        try:
            if not self.admin_username or not self.admin_password:
                logger.warning("Admin credentials required for notification testing")
                result['status'] = 'skipped'
                result['findings'].append("No admin credentials provided for testing")
                return result
                
            # Connect to WinRM
            session = winrm.Session(f'http://{self.target}:5985/wsman',
                                    auth=(f"{self.admin_domain}\\{self.admin_username}" 
                                          if self.admin_domain else self.admin_username, 
                                         self.admin_password))
            
            # Check group policy or registry settings for shadow notification
            ps_script = """$notifyRegKey = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" -Name "NotifyRDPShadow" -ErrorAction SilentlyContinue
                          if ($notifyRegKey) { 
                              Write-Output $notifyRegKey.NotifyRDPShadow 
                          } else { 
                              # Default is to notify (consider secure)
                              Write-Output "1"
                          }"""
            
            result_data = session.run_ps(ps_script)
            notify_setting = result_data.std_out.decode('utf-8').strip()
            
            try:
                notify_setting = int(notify_setting)
                if notify_setting == 1 or notify_setting == "1":
                    result['status'] = 'passed'
                    result['findings'].append("Shadow session notifications are enabled")
                else:
                    result['status'] = 'failed'
                    result['findings'].append("Shadow session notifications are disabled")
                    result['vulnerabilities'].append({
                        'severity': 'high',
                        'description': 'Shadow session notifications are disabled, allowing stealth monitoring',
                        'remediation': 'Enable shadow session notifications via Group Policy or registry settings'
                    })
            except ValueError:
                result['status'] = 'warning'
                result['findings'].append(f"Unable to determine notification setting: {notify_setting}")
                
        except Exception as e:
            logger.error(f"Error testing notification settings: {e}")
            result['status'] = 'error'
            result['findings'].append(f"Error: {str(e)}")
        
        if result['status'] == 'passed':
            self.tests_passed += 1
        elif result['status'] in ['failed', 'error']:
            self.tests_failed += 1
            
        return result
        
    def test_rdp_shadow_auditing(self) -> Dict[str, Any]:
        """Test if RDP shadow session auditing is enabled
        
        Returns:
            Dict: Test results with findings
        """
        logger.info("Testing RDP shadow session auditing...")
        self.tests_run += 1
        
        result = {
            'test': 'shadow_auditing',
            'status': 'unknown',
            'findings': [],
            'vulnerabilities': []
        }
        
        try:
            if not self.admin_username or not self.admin_password:
                logger.warning("Admin credentials required for auditing testing")
                result['status'] = 'skipped'
                result['findings'].append("No admin credentials provided for testing")
                return result
                
            # Connect to WinRM
            session = winrm.Session(f'http://{self.target}:5985/wsman',
                                    auth=(f"{self.admin_domain}\\{self.admin_username}" 
                                          if self.admin_domain else self.admin_username, 
                                         self.admin_password))
            
            # Check audit policy for RDP session shadowing
            ps_script = """$auditSettingTS = auditpol /get /subcategory:"Terminal Services Session Reconnection" /r | ConvertFrom-Csv
                          if ($auditSettingTS.'Inclusion Setting' -match 'Success|Failure') {
                              Write-Output "TS_Audit_Enabled"
                          } else {
                              Write-Output "TS_Audit_Disabled"
                          }
                          
                          # Also check for general RDP auditing
                          $auditSettingRDP = auditpol /get /subcategory:"Other Logon/Logoff Events" /r | ConvertFrom-Csv
                          if ($auditSettingRDP.'Inclusion Setting' -match 'Success|Failure') {
                              Write-Output "RDP_Audit_Enabled"
                          } else {
                              Write-Output "RDP_Audit_Disabled"
                          }"""
                          
            result_data = session.run_ps(ps_script)
            audit_lines = result_data.std_out.decode('utf-8').strip().split('\n')
            
            ts_audit = "TS_Audit_Disabled"
            rdp_audit = "RDP_Audit_Disabled"
            
            for line in audit_lines:
                if "TS_Audit_Enabled" in line:
                    ts_audit = "TS_Audit_Enabled"
                elif "RDP_Audit_Enabled" in line:
                    rdp_audit = "RDP_Audit_Enabled"
            
            if ts_audit == "TS_Audit_Enabled" and rdp_audit == "RDP_Audit_Enabled":
                result['status'] = 'passed'
                result['findings'].append("Both Terminal Services and RDP auditing are enabled")
            elif ts_audit == "TS_Audit_Enabled":
                result['status'] = 'warning'
                result['findings'].append("Terminal Services auditing is enabled, but RDP auditing is disabled")
                result['vulnerabilities'].append({
                    'severity': 'medium',
                    'description': 'RDP general auditing is disabled, potentially missing important events',
                    'remediation': 'Enable auditing for "Other Logon/Logoff Events" via Group Policy'
                })
            elif rdp_audit == "RDP_Audit_Enabled":
                result['status'] = 'warning'
                result['findings'].append("RDP auditing is enabled, but Terminal Services auditing is disabled")
                result['vulnerabilities'].append({
                    'severity': 'medium',
                    'description': 'Terminal Services Session Reconnection auditing is disabled',
                    'remediation': 'Enable auditing for "Terminal Services Session Reconnection" via Group Policy'
                })
            else:
                result['status'] = 'failed'
                result['findings'].append("Both Terminal Services and RDP auditing are disabled")
                result['vulnerabilities'].append({
                    'severity': 'high',
                    'description': 'No auditing enabled for Terminal Services or RDP events',
                    'remediation': 'Enable auditing for both "Terminal Services Session Reconnection" and "Other Logon/Logoff Events" via Group Policy'
                })
            
        except Exception as e:
            logger.error(f"Error testing auditing settings: {e}")
            result['status'] = 'error'
            result['findings'].append(f"Error: {str(e)}")
        
        if result['status'] == 'passed':
            self.tests_passed += 1
        elif result['status'] in ['failed', 'error']:
            self.tests_failed += 1
            
        return result
