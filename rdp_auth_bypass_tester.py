#!/usr/bin/env python3
"""
RDP Authentication Bypass Scenario Tester
This module tests RDP servers for authentication bypass vulnerabilities and misconfigurations.

Authentication bypass scenarios include:
- Network Level Authentication (NLA) bypass attempts
- Guest account access
- Weak authentication protocols
- Session takeover vulnerabilities
- Credential relay attacks
"""

import os
import sys
import json
import time
import socket
import logging
import argparse
import subprocess
from datetime import datetime
from typing import Dict, List, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('rdp_auth_bypass.log')
    ]
)
logger = logging.getLogger(__name__)


class RDPAuthBypassTester:
    """Tests RDP servers for authentication bypass vulnerabilities"""
    
    def __init__(self, target: str, port: int = 3389, username: str = None,
                 password: str = None, domain: str = None, verbose: bool = False):
        """Initialize the RDP Authentication Bypass tester
        
        Args:
            target: Target hostname or IP
            port: RDP port
            username: Username for authentication
            password: Password for authentication
            domain: Domain for authentication
            verbose: Enable verbose output
        """
        self.target = target
        self.port = port
        self.username = username
        self.password = password
        self.domain = domain
        self.verbose = verbose
        self.supports_winrm = False
        
        # Set up result structure
        self.results = {
            'target': target,
            'port': port,
            'timestamp': datetime.now().isoformat(),
            'tests': {},
            'vulnerable_to_auth_bypass': False,
            'findings': [],
            'recommendations': []
        }
        
        # Track test statistics
        self.tests_run = 0
        self.tests_passed = 0
        self.tests_failed = 0
        
        if verbose:
            logger.setLevel(logging.DEBUG)
            
        logger.info(f"Initialized RDP Authentication Bypass Tester for {target}:{port}")
        
        # Check if WinRM is available for extended tests
        try:
            import winrm
            self.supports_winrm = True
        except ImportError:
            logger.warning("WinRM module not available, some tests will be skipped")
    
    def test_nla_bypass_attempts(self) -> Dict[str, Any]:
        """Test for Network Level Authentication bypass vulnerabilities
        
        Returns:
            Dict: Test results
        """
        logger.info(f"Testing NLA bypass attempts on {self.target}")
        
        result = {
            'test': 'nla_bypass_attempts',
            'description': 'Tests for Network Level Authentication bypass vulnerabilities',
            'status': 'unknown',
            'findings': [],
            'vulnerable': False
        }
        
        try:
            # Test basic RDP connection without authentication
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            try:
                # Attempt connection to RDP port
                sock.connect((self.target, self.port))
                result['findings'].append(f"RDP port {self.port} is accessible")
                
                # Send RDP negotiation request without NLA
                # This tests if the server allows connections without NLA
                rdp_nego_no_nla = b'\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x00\x00\x00\x00'
                sock.send(rdp_nego_no_nla)
                
                # Read response with timeout
                sock.settimeout(5)
                response = sock.recv(1024)
                
                if response:
                    result['findings'].append("Received RDP response to non-NLA negotiation")
                    
                    # Check if connection was accepted without NLA
                    if len(response) >= 4 and response[0:2] == b'\x03\x00':
                        # Look for connection acceptance without NLA requirement
                        if b'\x02\x00' in response:
                            result['findings'].append("RDP connection accepted without NLA - VULNERABLE")
                            result['vulnerable'] = True
                            self.results['vulnerable_to_auth_bypass'] = True
                            self.results['findings'].append("NLA bypass possible - authentication can be bypassed")
                            
                            # Add recommendations
                            self.results['recommendations'].append("Enable Network Level Authentication (NLA) immediately")
                            self.results['recommendations'].append("Configure RDP to require authentication before connection")
                            
                        else:
                            result['findings'].append("RDP requires proper authentication negotiation")
                    else:
                        result['findings'].append("Invalid RDP response format")
                else:
                    result['findings'].append("No response to NLA bypass attempt")
                    
            except socket.timeout:
                result['findings'].append("Connection timeout during NLA bypass test")
                result['status'] = 'warning'
            except ConnectionRefusedError:
                result['findings'].append("RDP connection refused - service may be disabled")
                result['status'] = 'skipped'
            except Exception as conn_error:
                result['findings'].append(f"Connection error: {str(conn_error)}")
                result['status'] = 'error'
            finally:
                sock.close()
                
            # Test with WinRM for more detailed NLA configuration
            if self.supports_winrm and self.username and self.password:
                nla_config = self._check_nla_configuration()
                if nla_config:
                    result['findings'].extend(nla_config['findings'])
                    if nla_config.get('nla_disabled', False):
                        result['vulnerable'] = True
                        self.results['vulnerable_to_auth_bypass'] = True
                        
        except Exception as e:
            logger.error(f"Error testing NLA bypass: {e}")
            result['findings'].append(f"Error: {str(e)}")
            result['status'] = 'error'
        
        # Determine final status
        if result['status'] == 'unknown':
            if result['vulnerable']:
                result['status'] = 'failed'
            else:
                result['status'] = 'passed'
                result['findings'].append("No NLA bypass vulnerabilities detected")
        
        # Update test statistics
        self.tests_run += 1
        if result['status'] == 'passed':
            self.tests_passed += 1
        elif result['status'] == 'failed':
            self.tests_failed += 1
            
        # Store test results
        self.results['tests']['nla_bypass_attempts'] = result
        return result
    
    def _check_nla_configuration(self) -> Optional[Dict[str, Any]]:
        """Check NLA configuration via WinRM"""
        try:
            import winrm
            
            # Create WinRM session
            auth = f"{self.domain}\\{self.username}" if self.domain else self.username
            session = winrm.Session(
                f'http://{self.target}:5985/wsman',
                auth=(auth, self.password)
            )
            
            # PowerShell script to check NLA configuration
            ps_script = """
            # Check Network Level Authentication setting
            $nla = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue
            if ($nla -ne $null) {
                Write-Output "NLA_Setting: $($nla.UserAuthentication)"
            } else {
                Write-Output "NLA_Setting: Not configured"
            }
            
            # Check if Guest account is enabled
            $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
            if ($guest -ne $null) {
                Write-Output "Guest_Enabled: $($guest.Enabled)"
            } else {
                Write-Output "Guest_Enabled: Account not found"
            }
            
            # Check Remote Desktop Users group
            try {
                $rdpUsers = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue
                $guestInRDP = $rdpUsers | Where-Object {$_.Name -like "*Guest*"}
                if ($guestInRDP) {
                    Write-Output "Guest_RDP_Access: YES - VULNERABLE"
                } else {
                    Write-Output "Guest_RDP_Access: NO"
                }
            } catch {
                Write-Output "Guest_RDP_Access: Could not check"
            }
            """
            
            result_data = session.run_ps(ps_script)
            output = result_data.std_out.decode('utf-8', errors='ignore')
            
            findings = []
            nla_disabled = False
            guest_enabled = False
            
            for line in output.splitlines():
                line = line.strip()
                findings.append(line)
                
                if line.startswith("NLA_Setting:"):
                    try:
                        nla_value = line.split(":")[1].strip()
                        if nla_value == "0" or nla_value == "Not configured":
                            nla_disabled = True
                            findings.append("Network Level Authentication is DISABLED - major security risk")
                    except (ValueError, IndexError):
                        pass
                        
                if line.startswith("Guest_Account: True"):
                    guest_enabled = True
                    findings.append("Guest account is ENABLED - authentication bypass risk")
                    
            return {
                'findings': findings,
                'nla_disabled': nla_disabled,
                'guest_enabled': guest_enabled
            }
            
        except Exception as e:
            logger.warning(f"Could not check NLA configuration: {e}")
            return None
            
    def test_guest_account_access(self) -> Dict[str, Any]:
        """Test for guest account access vulnerabilities
        
        Returns:
            Dict: Test results
        """
        logger.info(f"Testing guest account access on {self.target}")
        
        result = {
            'test': 'guest_account_access',
            'description': 'Tests for guest account access and anonymous RDP connections',
            'status': 'unknown',
            'findings': [],
            'vulnerable': False
        }
        
        # Skip if WinRM is not available
        if not self.supports_winrm or not self.username or not self.password:
            result['status'] = 'skipped'
            result['findings'].append("Skipped test - requires WinRM and credentials")
            self.results['tests']['guest_account_access'] = result
            return result
        
        try:
            import winrm
            
            # Create WinRM session
            auth = f"{self.domain}\\{self.username}" if self.domain else self.username
            session = winrm.Session(
                f'http://{self.target}:5985/wsman',
                auth=(auth, self.password)
            )
            
            # PowerShell script to check guest account and anonymous access
            ps_script = """
            # Check Guest account status
            try {
                $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
                if ($guest -ne $null) {
                    Write-Output "Guest_Enabled: $($guest.Enabled)"
                    Write-Output "Guest_Description: $($guest.Description)"
                    Write-Output "Guest_LastLogon: $($guest.LastLogon)"
                } else {
                    Write-Output "Guest_Enabled: Account not found"
                }
            } catch {
                Write-Output "Guest_Enabled: Could not check"
            }
            
            # Check if Guest is in Remote Desktop Users group
            try {
                $rdpUsers = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue
                $guestInRDP = $rdpUsers | Where-Object {$_.Name -like "*Guest*"}
                if ($guestInRDP) {
                    Write-Output "Guest_RDP_Access: YES - VULNERABLE"
                } else {
                    Write-Output "Guest_RDP_Access: NO"
                }
            } catch {
                Write-Output "Guest_RDP_Access: Could not check"
            }
            
            # Check anonymous access policies
            $anonPolicy = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -ErrorAction SilentlyContinue
            if ($anonPolicy -ne $null) {
                Write-Output "Anonymous_Restriction: $($anonPolicy.RestrictAnonymous)"
            } else {
                Write-Output "Anonymous_Restriction: Not configured"
            }
            
            # Check blank password policy
            $blankPwd = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -ErrorAction SilentlyContinue
            if ($blankPwd -ne $null) {
                Write-Output "Blank_Password_Restriction: $($blankPwd.LimitBlankPasswordUse)"
            } else {
                Write-Output "Blank_Password_Restriction: Not configured"
            }
            
            # Check for accounts with blank passwords (dangerous)
            try {
                $users = Get-LocalUser | Where-Object {$_.Enabled -eq $true}
                foreach ($user in $users) {
                    # This is a basic check - full password testing would require different approaches
                    if ($user.PasswordRequired -eq $false) {
                        Write-Output "Blank_Password_User: $($user.Name) - VULNERABLE"
                    }
                }
            } catch {
                Write-Output "Blank_Password_Check: Could not perform"
            }
            
            # Check Everyone group permissions
            try {
                $everyonePerms = Get-Acl "C:\" | Select-Object -ExpandProperty Access | Where-Object {$_.IdentityReference -like "*Everyone*"}
                if ($everyonePerms) {
                    Write-Output "Everyone_Permissions: Found - potential risk"
                } else {
                    Write-Output "Everyone_Permissions: Not found"
                }
            } catch {
                Write-Output "Everyone_Permissions: Could not check"
            }
            """
            
            result_data = session.run_ps(ps_script)
            output = result_data.std_out.decode('utf-8', errors='ignore')
            
            # Process the output
            guest_enabled = False
            guest_rdp_access = False
            anonymous_unrestricted = False
            blank_password_allowed = False
            vulnerable_users = []
            
            for line in output.splitlines():
                line = line.strip()
                result['findings'].append(line)
                
                if line.startswith("Guest_Enabled: True"):
                    guest_enabled = True
                    
                if line.startswith("Guest_RDP_Access: YES"):
                    guest_rdp_access = True
                    result['vulnerable'] = True
                    self.results['vulnerable_to_auth_bypass'] = True
                    
                if line.startswith("Anonymous_Restriction: 0") or line.startswith("Anonymous_Restriction: Not configured"):
                    anonymous_unrestricted = True
                    
                if line.startswith("Blank_Password_Restriction: 0") or line.startswith("Blank_Password_Restriction: Not configured"):
                    blank_password_allowed = True
                    
                if line.startswith("Blank_Password_User:"):
                    vulnerable_users.append(line.split(":")[1].strip().split(" - ")[0])
                    result['vulnerable'] = True
                    self.results['vulnerable_to_auth_bypass'] = True
            
            # Evaluate security issues
            security_issues = []
            
            if guest_enabled:
                security_issues.append("Guest account is enabled - potential security risk")
                if guest_rdp_access:
                    security_issues.append("CRITICAL: Guest account has RDP access - authentication bypass possible")
                    
            if anonymous_unrestricted:
                security_issues.append("Anonymous access is not properly restricted")
                
            if blank_password_allowed:
                security_issues.append("Blank passwords are allowed - major authentication weakness")
                
            if vulnerable_users:
                security_issues.append(f"Users with blank passwords detected: {', '.join(vulnerable_users)}")
                
            # Add findings and recommendations
            if security_issues:
                result['status'] = 'failed'
                result['vulnerable'] = True
                self.results['vulnerable_to_auth_bypass'] = True
                
                for issue in security_issues:
                    self.results['findings'].append(f"Guest/Anonymous access issue: {issue}")
                    
                # Add recommendations
                self.results['recommendations'].append("Disable Guest account if not needed")
                self.results['recommendations'].append("Remove Guest account from Remote Desktop Users group")
                self.results['recommendations'].append("Configure anonymous access restrictions")
                self.results['recommendations'].append("Enforce strong password policies")
                
            else:
                result['status'] = 'passed'
                result['findings'].append("No guest account or anonymous access vulnerabilities detected")
                
        except Exception as e:
            logger.error(f"Error testing guest account access: {e}")
            result['findings'].append(f"Error: {str(e)}")
            result['status'] = 'error'
        
        # Update test statistics
        self.tests_run += 1
        if result['status'] == 'passed':
            self.tests_passed += 1
        elif result['status'] == 'failed':
            self.tests_failed += 1
            
        # Store test results
        self.results['tests']['guest_account_access'] = result
        return result
    
    def test_weak_authentication_protocols(self) -> Dict[str, Any]:
        """Test for weak authentication protocols and configurations
        
        Returns:
            Dict: Test results
        """
        logger.info(f"Testing weak authentication protocols on {self.target}")
        
        result = {
            'test': 'weak_authentication_protocols',
            'description': 'Tests for weak authentication protocols and insecure configurations',
            'status': 'unknown',
            'findings': [],
            'vulnerable': False
        }
        
        # Skip if WinRM is not available
        if not self.supports_winrm or not self.username or not self.password:
            result['status'] = 'skipped'
            result['findings'].append("Skipped test - requires WinRM and credentials")
            self.results['tests']['weak_authentication_protocols'] = result
            return result
        
        try:
            import winrm
            
            # Create WinRM session
            auth = f"{self.domain}\\{self.username}" if self.domain else self.username
            session = winrm.Session(
                f'http://{self.target}:5985/wsman',
                auth=(auth, self.password)
            )
            
            # PowerShell script to check authentication protocols
            ps_script = r"""
            # Check RDP security layer
            $secLayer = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -ErrorAction SilentlyContinue
            if ($secLayer -ne $null) {
                Write-Output "Security_Layer: $($secLayer.SecurityLayer)"
            } else {
                Write-Output "Security_Layer: Not configured"
            }
            
            # Check encryption level
            $encLevel = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue
            if ($encLevel -ne $null) {
                Write-Output "Encryption_Level: $($encLevel.MinEncryptionLevel)"
            } else {
                Write-Output "Encryption_Level: Not configured"
            }
            
            # Check LM authentication level
            $lmLevel = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue
            if ($lmLevel -ne $null) {
                Write-Output "LM_Auth_Level: $($lmLevel.LmCompatibilityLevel)"
            } else {
                Write-Output "LM_Auth_Level: Not configured"
            }
            
            # Check NTLM settings
            $ntlmLevel = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinClientSec" -ErrorAction SilentlyContinue
            if ($ntlmLevel -ne $null) {
                Write-Output "NTLM_Min_Security: $($ntlmLevel.NTLMMinClientSec)"
            } else {
                Write-Output "NTLM_Min_Security: Not configured"
            }
            
            # Check if old protocols are enabled
            $sslEnabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name "Enabled" -ErrorAction SilentlyContinue
            if ($sslEnabled -ne $null -and $sslEnabled.Enabled -eq 1) {
                Write-Output "SSL2_Enabled: YES - VULNERABLE"
            } else {
                Write-Output "SSL2_Enabled: NO"
            }
            
            # Check TLS versions
            $tls10 = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -ErrorAction SilentlyContinue
            if ($tls10 -ne $null) {
                Write-Output "TLS10_Enabled: $($tls10.Enabled)"
            } else {
                Write-Output "TLS10_Enabled: Default"
            }
            
            # Check password complexity requirements
            try {
                $secPolicy = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireSignOrSeal" -ErrorAction SilentlyContinue
                if ($secPolicy -ne $null) {
                    Write-Output "Netlogon_Security: $($secPolicy.RequireSignOrSeal)"
                } else {
                    Write-Output "Netlogon_Security: Not configured"
                }
            } catch {
                Write-Output "Netlogon_Security: Could not check"
            }
            
            # Check for insecure cipher suites
            try {
                $ciphers = Get-TlsCipherSuite -ErrorAction SilentlyContinue
                $weakCiphers = $ciphers | Where-Object {$_.Name -like "*RC4*" -or $_.Name -like "*DES*" -or $_.Name -like "*NULL*"}
                if ($weakCiphers) {
                    Write-Output "Weak_Ciphers: Found $($weakCiphers.Count) weak cipher suites"
                    $weakCiphers | ForEach-Object { Write-Output "Weak_Cipher: $($_.Name)" }
                } else {
                    Write-Output "Weak_Ciphers: None found"
                }
            } catch {
                Write-Output "Weak_Ciphers: Could not check"
            }
            """
            
            script = ps_script
            
            result_data = session.run_ps(script)
            output = result_data.std_out.decode('utf-8', errors='ignore')
            
            # Process the output
            weak_security = []
            weak_protocols = []
            
            for line in output.splitlines():
                line = line.strip()
                result['findings'].append(line)
                
                # Check security layer - should be 2 (TLS/SSL)
                if line.startswith("Security_Layer:"):
                    try:
                        sec_layer = int(line.split(":")[1].strip())
                        if sec_layer == 0:
                            weak_security.append("RDP Security Layer set to RDP Security - very weak")
                            result['vulnerable'] = True
                        elif sec_layer == 1:
                            weak_security.append("RDP Security Layer set to Negotiate - potentially weak")
                    except (ValueError, IndexError):
                        pass
                        
                # Check encryption level - should be 3 or 4 (High or FIPS)
                if line.startswith("Encryption_Level:"):
                    try:
                        enc_level = int(line.split(":")[1].strip())
                        if enc_level < 3:
                            weak_security.append(f"RDP Encryption Level is {enc_level} - should be 3 (High) or 4 (FIPS)")
                            result['vulnerable'] = True
                    except (ValueError, IndexError):
                        pass
                        
                # Check LM authentication level - should be 5
                if line.startswith("LM_Auth_Level:"):
                    try:
                        lm_level = int(line.split(":")[1].strip())
                        if lm_level < 5:
                            weak_security.append(f"LM Authentication Level is {lm_level} - should be 5 for maximum security")
                            result['vulnerable'] = True
                    except (ValueError, IndexError):
                        pass
                        
                # Check for SSL 2.0
                if "SSL2_Enabled: YES" in line:
                    weak_protocols.append("SSL 2.0 is enabled - extremely insecure protocol")
                    result['vulnerable'] = True
                    
                # Check for weak ciphers
                if line.startswith("Weak_Cipher:"):
                    cipher_name = line.split(":")[1].strip()
                    weak_protocols.append(f"Weak cipher suite enabled: {cipher_name}")
                    result['vulnerable'] = True
            
            # Evaluate overall security
            if weak_security or weak_protocols:
                result['status'] = 'failed'
                self.results['vulnerable_to_auth_bypass'] = True
                
                for issue in weak_security + weak_protocols:
                    result['findings'].append(issue)
                    self.results['findings'].append(f"Weak authentication: {issue}")
                    
                # Add recommendations
                self.results['recommendations'].append("Configure RDP Security Layer to use TLS/SSL (value 2)")
                self.results['recommendations'].append("Set RDP Encryption Level to High (3) or FIPS (4)")
                self.results['recommendations'].append("Set LM Authentication Level to 5 (NTLMv2 only)")
                self.results['recommendations'].append("Disable weak protocols like SSL 2.0 and TLS 1.0")
                self.results['recommendations'].append("Remove weak cipher suites from TLS configuration")
                
            else:
                result['status'] = 'passed'
                result['findings'].append("No weak authentication protocols detected")
                
        except Exception as e:
            logger.error(f"Error testing weak authentication protocols: {e}")
            result['findings'].append(f"Error: {str(e)}")
            result['status'] = 'error'
        
        # Update test statistics
        self.tests_run += 1
        if result['status'] == 'passed':
            self.tests_passed += 1
        elif result['status'] == 'failed':
            self.tests_failed += 1
            
        # Store test results
        self.results['tests']['weak_authentication_protocols'] = result
        return result

    def _run_test_safely(self, test_func, test_name: str, *args, **kwargs) -> Dict[str, Any]:
        """Safely run a test function with error handling and result tracking
        
        Args:
            test_func: Test function to execute
            test_name: Name of the test for logging
            *args: Positional arguments to pass to test_func
            **kwargs: Keyword arguments to pass to test_func
            
        Returns:
            Dict: Test results
        """
        logger.info(f"Running test: {test_name}")
        self.tests_run += 1
        
        # Initialize test result
        result = {
            'test': test_name,
            'status': 'error',
            'start_time': datetime.now().isoformat(),
            'findings': [],
            'error': None,
            'details': {}
        }
        
        try:
            # Execute the test
            test_result = test_func(*args, **kwargs)
            
            # Update test status based on results
            if test_result and 'vulnerable' in test_result:
                if test_result['vulnerable']:
                    result['status'] = 'failed'
                    self.tests_failed += 1
                    logger.warning(f"Test {test_name} found vulnerabilities")
                    self.results['vulnerable_to_auth_bypass'] = True
                else:
                    result['status'] = 'passed'
                    self.tests_passed += 1
                    logger.info(f"Test {test_name} completed successfully")
            
            # Merge test results
            result.update(test_result)
            
        except Exception as e:
            error_msg = f"Error in test {test_name}: {str(e)}"
            logger.error(error_msg, exc_info=self.verbose)
            result.update({
                'status': 'error',
                'error': error_msg,
                'details': {
                    'exception_type': type(e).__name__,
                    'exception_args': str(e.args) if hasattr(e, 'args') else str(e)
                }
            })
            self.tests_failed += 1
        
        # Add end time and duration
        result['end_time'] = datetime.now().isoformat()
        
        # Calculate duration if start_time is available
        if 'start_time' in result and 'end_time' in result:
            try:
                start = datetime.fromisoformat(result['start_time'])
                end = datetime.fromisoformat(result['end_time'])
                result['duration_seconds'] = (end - start).total_seconds()
            except Exception as e:
                logger.warning(f"Error calculating test duration: {str(e)}")
        
        # Store test results
        if 'tests' not in self.results:
            self.results['tests'] = {}
        self.results['tests'][test_name] = result
        
        return result
    
    def _generate_recommendations(self):
        """Generate security recommendations based on test results"""
        recommendations = [
            "Enable Network Level Authentication (NLA) for all RDP connections.",
            "Disable guest account access to RDP.",
            "Implement account lockout policies to prevent brute force attacks.",
            "Use strong passwords and consider multi-factor authentication.",
            "Regularly update and patch all systems to the latest security updates.",
            "Monitor RDP logs for suspicious authentication attempts.",
            "Restrict RDP access to specific IP addresses using firewalls.",
            "Consider using a VPN instead of exposing RDP directly to the internet."
        ]
        
        # Add specific recommendations based on test results
        for test_name, test_result in self.results.get('tests', {}).items():
            if test_result.get('vulnerable', False):
                if 'nla' in test_name.lower():
                    recommendations.append(
                        "Ensure Network Level Authentication (NLA) is properly configured and required."
                    )
                elif 'guest' in test_name.lower():
                    recommendations.append(
                        "Disable guest account and ensure it cannot be used for RDP access."
                    )
                elif 'weak' in test_name.lower():
                    recommendations.append(
                        "Disable weak authentication protocols and enforce strong encryption."
                    )
        
        # Remove duplicates while preserving order
        self.results['recommendations'] = list(dict.fromkeys(recommendations))
    
    def _compile_findings(self) -> List[str]:
        """Compile findings from all tests into a single list"""
        findings = []
        
        # Add findings from each test
        for test_name, test_result in self.results.get('tests', {}).items():
            if test_result.get('findings'):
                findings.extend(test_result['findings'])
        
        # Add overall status
        if self.results.get('vulnerable_to_auth_bypass', False):
            findings.insert(0, "System is VULNERABLE to authentication bypass attacks")
        else:
            findings.insert(0, "No critical authentication bypass vulnerabilities detected")
        
        return findings
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all authentication bypass tests with comprehensive error handling
        
        Returns:
            Dict: Comprehensive test results
        """
        logger.info(f"Running all RDP authentication bypass tests against {self.target}:{self.port}")
        start_time = time.time()
        
        # Initialize test results
        self.results.update({
            'start_time': datetime.now().isoformat(),
            'tests_run': 0,
            'tests_passed': 0,
            'tests_failed': 0,
            'execution_time_seconds': 0,
            'status': 'completed',
            'error': None
        })
        
        try:
            # Reset test counters
            self.tests_run = 0
            self.tests_passed = 0
            self.tests_failed = 0
            
            # Run all test methods with error handling
            self._run_test_safely(self.test_nla_bypass_attempts, 'nla_bypass_attempts')
            self._run_test_safely(self.test_guest_account_access, 'guest_account_access')
            self._run_test_safely(self.test_weak_authentication_protocols, 'weak_authentication_protocols')
            
            # Generate recommendations
            self._generate_recommendations()
            
            # Update final status
            self.results.update({
                'status': 'completed',
                'tests_run': self.tests_run,
                'tests_passed': self.tests_passed,
                'tests_failed': self.tests_failed,
                'end_time': datetime.now().isoformat(),
                'execution_time_seconds': time.time() - start_time,
                'findings': self._compile_findings()
            })
            
            # Log completion status
            status = 'VULNERABLE' if self.results['vulnerable_to_auth_bypass'] else 'SECURE'
            logger.info(
                f"Completed RDP authentication bypass tests. Status: {status}. "
                f"Tests: {self.tests_passed}/{self.tests_run} passed. "
                f"Time: {self.results['execution_time_seconds']:.2f} seconds"
            )
            
        except Exception as e:
            # Handle unexpected errors during test execution
            error_msg = f"Error during test execution: {str(e)}"
            logger.error(error_msg, exc_info=self.verbose)
            self.results.update({
                'status': 'error',
                'error': error_msg,
                'end_time': datetime.now().isoformat(),
                'execution_time_seconds': time.time() - start_time
            })
            
            # Add error to test results if we have partial results
            if 'tests' not in self.results:
                self.results['tests'] = {}
                
            self.results['tests']['execution_error'] = {
                'test': 'test_execution',
                'status': 'error',
                'error': error_msg,
                'timestamp': datetime.now().isoformat(),
                'details': {
                    'exception_type': type(e).__name__,
                    'exception_args': str(e.args) if hasattr(e, 'args') else str(e)
                }
            }
            
            # Generate basic recommendations even in case of error
            self._generate_recommendations()
        
        return self.results

    def generate_report(self, output_file: str = None) -> Dict[str, Any]:
        """Generate a JSON report with test results
        
        Args:
            output_file: Optional path to write JSON report
            
        Returns:
            Dict: Complete test results
        """
        # If we haven't run tests yet, do so
        if 'summary' not in self.results:
            self.run_all_tests()
            
        # If output file specified, write results to file
        if output_file:
            try:
                # Create directory if it doesn't exist
                os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
                
                with open(output_file, 'w') as f:
                    json.dump(self.results, f, indent=4)
                logger.info(f"Report saved to {output_file}")
            except Exception as e:
                logger.error(f"Error saving report: {e}")
        
        return self.results

    def print_report_summary(self):
        """Print a summary of the test results to the console"""
        if 'summary' not in self.results:
            logger.warning("No test results available to print")
            return
        
        print("\n" + "="*80)
        print(" RDP Authentication Bypass Test Report")
        print(f" Target: {self.target}:{self.port}")
        print(f" Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*80 + "\n")
        
        vulnerable = self.results.get('vulnerable_to_auth_bypass', False)
        
        print(f"Authentication Bypass Vulnerability: {'✗ VULNERABLE' if vulnerable else '✓ SECURE'}")
        print(f"Tests Run: {self.tests_run}")
        print(f"Tests Passed: {self.tests_passed}")
        print(f"Tests Failed: {self.tests_failed}")
        
        if self.results.get('findings'):
            print("\nFindings:")
            for i, finding in enumerate(self.results['findings'], 1):
                print(f"  {i}. {finding}")
                
        if self.results.get('recommendations'):
            print("\nRecommendations:")
            for i, rec in enumerate(self.results['recommendations'], 1):
                print(f"  {i}. {rec}")
                
        if vulnerable:
            print("\n⚠️  WARNING: This system may be vulnerable to authentication bypass attacks")
            print("   Review the findings and apply the recommended security controls")
                
        print(f"\nFull report {'saved to ' + self.results.get('report_file', 'JSON report') if 'report_file' in self.results else 'available in JSON format'}")
        print("\n" + "="*80)

def main():
    parser = argparse.ArgumentParser(description='RDP Authentication Bypass Scenario Tester')
    parser.add_argument('target', help='Target hostname or IP')
    parser.add_argument('-p', '--port', type=int, default=3389, help='RDP port')
    parser.add_argument('-u', '--username', help='Username for authentication')
    parser.add_argument('-d', '--domain', help='Domain for authentication')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    args = parser.parse_args()
    
    tester = RDPAuthBypassTester(args.target, args.port, args.username, None, args.domain, args.verbose)
    
    results = tester.run_all_tests()
    tester.print_report_summary()

if __name__ == '__main__':
    main()
