#!/usr/bin/env python3
"""
RDP Relay Attack Tester
This module tests RDP servers for susceptibility to credential relay attacks.

It includes detection of security measures that prevent relay attacks, such as:
- Restricted Admin Mode settings
- Protocol security level
- Authentication configuration
- Credential Guard integration
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
        logging.FileHandler('rdp_relay_attack.log')
    ]
)
logger = logging.getLogger(__name__)


class RDPRelayAttackTester:
    """Tests RDP servers for relay attack vulnerabilities"""
    
    def __init__(self, target: str, port: int = 3389, username: str = None,
                 password: str = None, domain: str = None, verbose: bool = False):
        """Initialize the RDP relay attack tester
        
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
            'vulnerable_to_relay': False,
            'findings': [],
            'recommendations': []
        }
        
        # Track test statistics
        self.tests_run = 0
        self.tests_passed = 0
        self.tests_failed = 0
        
        if verbose:
            logger.setLevel(logging.DEBUG)
            
        logger.info(f"Initialized RDP Relay Attack Tester for {target}:{port}")
        
        # Check if WinRM is available for extended tests
        try:
            import winrm
            self.supports_winrm = True
        except ImportError:
            logger.warning("WinRM module not available, some tests will be skipped")
    
    def test_restricted_admin_mode(self) -> Dict[str, Any]:
        """Test if Restricted Admin Mode is enabled
        
        Returns:
            Dict: Test results
        """
        logger.info(f"Testing Restricted Admin Mode on {self.target}")
        
        result = {
            'test': 'restricted_admin_mode',
            'description': 'Checks if Restricted Admin Mode is enabled, which helps prevent credential relay',
            'status': 'unknown',
            'findings': [],
            'vulnerable': True  # Default to vulnerable
        }
        
        try:
            # Check if the target allows connections with restricted admin mode
            # This uses xfreerdp with restricted admin flag (/restricted-admin)
            cmd = [
                'xfreerdp', '/v:' + self.target, '/port:' + str(self.port),
                '/restricted-admin', '+auth-only', '/cert-ignore'
            ]
            
            if self.username:
                cmd.append('/u:' + self.username)
            if self.password:
                cmd.append('/p:' + self.password)
            if self.domain:
                cmd.append('/d:' + self.domain)
                
            if self.verbose:
                logger.debug(f"Running command: {' '.join(cmd)}")
                
            # Use timeout to prevent hanging
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            try:
                stdout, stderr = process.communicate(timeout=10)
                stdout = stdout.decode('utf-8', errors='ignore')
                stderr = stderr.decode('utf-8', errors='ignore')
                exit_code = process.returncode
                
                # Process the output
                if exit_code == 0:
                    # Successfully authenticated with restricted admin
                    result['findings'].append("Server allows Restricted Admin Mode - helps prevent credential relay")
                    result['status'] = 'passed'
                    result['vulnerable'] = False
                    self.results['findings'].append("Server supports Restricted Admin Mode - good protection against credential theft")
                elif "SERVER_DENIED_CONNECTION" in stderr or "denied" in stderr.lower():
                    # Server denied restricted admin connection
                    result['findings'].append("Server has disabled Restricted Admin Mode - vulnerable to credential relay")
                    result['status'] = 'failed'
                    result['vulnerable'] = True
                    self.results['findings'].append("Server has disabled Restricted Admin Mode - vulnerable to credential relay")
                    self.results['recommendations'].append("Enable Restricted Admin Mode for RDP connections")
                else:
                    # Other error
                    result['findings'].append(f"Could not determine Restricted Admin Mode status: {stderr}")
                    result['status'] = 'error'
                    
            except subprocess.TimeoutExpired:
                process.kill()
                logger.error("Command timed out while testing Restricted Admin Mode")
                result['findings'].append("Test timed out - could not determine Restricted Admin Mode status")
                result['status'] = 'error'
                
        except Exception as e:
            logger.error(f"Error testing Restricted Admin Mode: {e}")
            result['findings'].append(f"Error: {str(e)}")
            result['status'] = 'error'
        
        # Update test statistics
        self.tests_run += 1
        if result['status'] == 'passed':
            self.tests_passed += 1
        elif result['status'] == 'failed':
            self.tests_failed += 1
            
        # Update overall vulnerability status
        if result['vulnerable']:
            self.results['vulnerable_to_relay'] = True
            
        # Store test results
        self.results['tests']['restricted_admin_mode'] = result
        return result
    
    def test_nla_required(self) -> Dict[str, Any]:
        """Test if Network Level Authentication is required
        
        Returns:
            Dict: Test results
        """
        logger.info(f"Testing NLA requirement on {self.target}")
        
        result = {
            'test': 'nla_required',
            'description': 'Checks if Network Level Authentication is required, which helps prevent relay attacks',
            'status': 'unknown',
            'findings': [],
            'vulnerable': True  # Default to vulnerable
        }
        
        try:
            # Try to connect without NLA to see if the connection is allowed
            cmd = [
                'xfreerdp', '/v:' + self.target, '/port:' + str(self.port),
                '+auth-only', '-sec-nla', '/cert-ignore'
            ]
            
            if self.username:
                cmd.append('/u:' + self.username)
            if self.password:
                cmd.append('/p:' + self.password)
            if self.domain:
                cmd.append('/d:' + self.domain)
                
            if self.verbose:
                logger.debug(f"Running command: {' '.join(cmd)}")
                
            # Use timeout to prevent hanging
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            try:
                stdout, stderr = process.communicate(timeout=10)
                stdout = stdout.decode('utf-8', errors='ignore')
                stderr = stderr.decode('utf-8', errors='ignore')
                exit_code = process.returncode
                
                # Process the output
                if exit_code == 0:
                    # Successfully authenticated without NLA
                    result['findings'].append("Server does not require NLA - vulnerable to relay attacks")
                    result['status'] = 'failed'
                    result['vulnerable'] = True
                    self.results['findings'].append("Server does not require NLA - vulnerable to relay attacks")
                    self.results['recommendations'].append("Enable Network Level Authentication (NLA) for all RDP connections")
                elif "HYBRID_REQUIRED_BY_SERVER" in stderr or "nla" in stderr.lower() or "authentication" in stderr.lower():
                    # Server requires NLA
                    result['findings'].append("Server requires NLA - good protection against relay attacks")
                    result['status'] = 'passed'
                    result['vulnerable'] = False
                    self.results['findings'].append("Server requires NLA - good protection against relay attacks")
                else:
                    # Other error
                    result['findings'].append(f"Could not determine NLA status: {stderr}")
                    result['status'] = 'error'
                    
            except subprocess.TimeoutExpired:
                process.kill()
                logger.error("Command timed out while testing NLA requirement")
                result['findings'].append("Test timed out - could not determine NLA status")
                result['status'] = 'error'
                
        except Exception as e:
            logger.error(f"Error testing NLA requirement: {e}")
            result['findings'].append(f"Error: {str(e)}")
            result['status'] = 'error'
        
        # Update test statistics
        self.tests_run += 1
        if result['status'] == 'passed':
            self.tests_passed += 1
        elif result['status'] == 'failed':
            self.tests_failed += 1
            
        # Update overall vulnerability status
        if result['vulnerable']:
            self.results['vulnerable_to_relay'] = True
            
        # Store test results
        self.results['tests']['nla_required'] = result
        return result

    def test_credential_guard(self) -> Dict[str, Any]:
        """Test if Windows Credential Guard is available and configured
        
        Returns:
            Dict: Test results
        """
        logger.info(f"Testing Windows Credential Guard on {self.target}")
        
        result = {
            'test': 'credential_guard',
            'description': 'Checks if Windows Credential Guard is enabled, which prevents credential extraction',
            'status': 'unknown',
            'findings': [],
            'vulnerable': True  # Default to vulnerable
        }
        
        # Skip if WinRM is not available
        if not self.supports_winrm or not self.username or not self.password:
            result['status'] = 'skipped'
            result['findings'].append("Skipped test - requires WinRM and credentials")
            self.results['tests']['credential_guard'] = result
            return result
        
        try:
            import winrm
            
            # Create WinRM session
            auth = f"{self.domain}\\{self.username}" if self.domain else self.username
            session = winrm.Session(
                f'http://{self.target}:5985/wsman',
                auth=(auth, self.password)
            )
            
            # PowerShell script to check Credential Guard
            ps_script = """
            $VBS = @"
            On Error Resume Next
            Set wmi = GetObject("winmgmts://./root/Microsoft/Windows/DeviceGuard")
            If Err.Number <> 0 Then
                WScript.Echo "WMI: Not Available"
                WScript.Quit
            End If
            Set InstancesOf = wmi.ExecQuery("Select * from Win32_DeviceGuard")
            For Each Instance in InstancesOf
                If Instance.SecurityServicesConfigured Then
                    For Each Service in Instance.SecurityServicesConfigured
                        WScript.Echo "SecurityServicesConfigured: " & Service
                    Next
                End If
                If Instance.SecurityServicesRunning Then
                    For Each Service in Instance.SecurityServicesRunning
                        WScript.Echo "SecurityServicesRunning: " & Service
                    Next
                End If
                WScript.Echo "VirtualizationBasedSecurityStatus: " & Instance.VirtualizationBasedSecurityStatus
                Exit For
            Next
            "@
            
            $tempFile = "$env:TEMP\\checkCredGuard.vbs"
            Set-Content -Path $tempFile -Value $VBS
            $output = cscript //nologo $tempFile
            Remove-Item -Path $tempFile -Force
            $output
            
            # Also check the registry
            $lsaRegistry = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -ErrorAction SilentlyContinue
            if ($lsaRegistry) {
                foreach ($prop in $lsaRegistry.PSObject.Properties) {
                    if ($prop.Name -like "*Credential*" -or $prop.Name -like "*LSA*") {
                        Write-Output "Registry_$($prop.Name): $($prop.Value)"
                    }
                }
            }
            """
            
            result_data = session.run_ps(ps_script)
            output = result_data.std_out.decode('utf-8', errors='ignore')
            error = result_data.std_err.decode('utf-8', errors='ignore')
            
            # Process the output
            credential_guard_enabled = False
            credential_guard_running = False
            lsa_protection_enabled = False
            
            for line in output.splitlines():
                line = line.strip()
                result['findings'].append(line)
                
                if "SecurityServicesConfigured: 1" in line or "SecurityServicesConfigured: 2" in line:
                    credential_guard_enabled = True
                    
                if "SecurityServicesRunning: 1" in line or "SecurityServicesRunning: 2" in line:
                    credential_guard_running = True
                
                if "Registry_LsaCfgFlags" in line and any(str(flag) in line for flag in ["1", "2"]):
                    lsa_protection_enabled = True
                    
                if "Registry_RunAsPPL" in line and "1" in line:
                    lsa_protection_enabled = True
            
            # Determine overall status
            if credential_guard_running:
                result['status'] = 'passed'
                result['vulnerable'] = False
                result['findings'].append("Windows Credential Guard is running - strong protection against relay attacks")
                self.results['findings'].append("Windows Credential Guard is running - excellent protection against credential theft")
            elif credential_guard_enabled and not credential_guard_running:
                result['status'] = 'warning'
                result['vulnerable'] = True
                result['findings'].append("Windows Credential Guard is configured but not running")
                self.results['findings'].append("Windows Credential Guard is configured but not running")
                self.results['recommendations'].append("Ensure hardware and boot configuration supports Credential Guard")
            elif lsa_protection_enabled:
                result['status'] = 'partial'
                result['vulnerable'] = True
                result['findings'].append("LSA protection is enabled but full Credential Guard is not")
                self.results['findings'].append("LSA protection is enabled but full Credential Guard is not")
                self.results['recommendations'].append("Enable full Windows Credential Guard for maximum protection")
            else:
                result['status'] = 'failed'
                result['vulnerable'] = True
                result['findings'].append("No credential protection mechanisms detected")
                self.results['findings'].append("No credential protection mechanisms detected - vulnerable to relay attacks")
                self.results['recommendations'].append("Enable Windows Credential Guard or at minimum LSA Protection")
                
        except Exception as e:
            logger.error(f"Error testing Windows Credential Guard: {e}")
            result['findings'].append(f"Error: {str(e)}")
            result['status'] = 'error'
        
        # Update test statistics
        self.tests_run += 1
        if result['status'] == 'passed':
            self.tests_passed += 1
        elif result['status'] == 'failed':
            self.tests_failed += 1
            
        # Update overall vulnerability status
        if result['vulnerable']:
            self.results['vulnerable_to_relay'] = True
            
        # Store test results
        self.results['tests']['credential_guard'] = result
        return result
        
    def test_rdp_security_layer(self) -> Dict[str, Any]:
        """Test RDP security layer settings
        
        Returns:
            Dict: Test results
        """
        logger.info(f"Testing RDP security layer settings on {self.target}")
        
        result = {
            'test': 'rdp_security_layer',
            'description': 'Checks if RDP security layer is configured securely, which helps prevent relay attacks',
            'status': 'unknown',
            'findings': [],
            'vulnerable': True  # Default to vulnerable
        }
        
        # Skip if WinRM is not available
        if not self.supports_winrm or not self.username or not self.password:
            result['status'] = 'skipped'
            result['findings'].append("Skipped test - requires WinRM and credentials")
            self.results['tests']['rdp_security_layer'] = result
            return result
        
        try:
            import winrm
            
            # Create WinRM session
            auth = f"{self.domain}\\{self.username}" if self.domain else self.username
            session = winrm.Session(
                f'http://{self.target}:5985/wsman',
                auth=(auth, self.password)
            )
            
            # PowerShell script to check RDP security layer
            ps_script = """
            # Check Terminal Server Security Layer settings
            $securityLayer = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -ErrorAction SilentlyContinue
            if ($securityLayer -ne $null) {
                Write-Output "SecurityLayer: $($securityLayer.SecurityLayer)"
            } else {
                Write-Output "SecurityLayer: Not configured"
            }
            
            # Check User Authentication settings
            $userAuth = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue
            if ($userAuth -ne $null) {
                Write-Output "UserAuthentication: $($userAuth.UserAuthentication)"
            } else {
                Write-Output "UserAuthentication: Not configured"
            }
            
            # Check MinEncryptionLevel
            $minEncryption = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue
            if ($minEncryption -ne $null) {
                Write-Output "MinEncryptionLevel: $($minEncryption.MinEncryptionLevel)"
            } else {
                Write-Output "MinEncryptionLevel: Not configured"
            }
            """
            
            result_data = session.run_ps(ps_script)
            output = result_data.std_out.decode('utf-8', errors='ignore')
            
            # Process the output
            security_layer = None
            user_auth = None
            min_encryption = None
            
            for line in output.splitlines():
                line = line.strip()
                result['findings'].append(line)
                
                if line.startswith("SecurityLayer:"):
                    try:
                        security_layer = int(line.split(":")[1].strip())
                    except (ValueError, IndexError):
                        security_layer = None
                        
                if line.startswith("UserAuthentication:"):
                    try:
                        user_auth = int(line.split(":")[1].strip())
                    except (ValueError, IndexError):
                        user_auth = None
                        
                if line.startswith("MinEncryptionLevel:"):
                    try:
                        min_encryption = int(line.split(":")[1].strip())
                    except (ValueError, IndexError):
                        min_encryption = None
            
            # Evaluate security based on values
            issues = []
            
            # Security Layer: 0=RDP Security, 1=Negotiate, 2=TLS/SSL
            if security_layer == 0:
                issues.append("RDP Security Layer is using legacy RDP Security")
            elif security_layer == 1:
                result['findings'].append("RDP Security Layer is set to Negotiate")
            elif security_layer == 2:
                result['findings'].append("RDP Security Layer is set to TLS/SSL (most secure)")
            else:
                issues.append("RDP Security Layer is not properly configured")
                
            # User Authentication: 0=Off, 1=On
            if user_auth == 0:
                issues.append("User Authentication for RDP is disabled")
            elif user_auth == 1:
                result['findings'].append("User Authentication for RDP is enabled")
            else:
                issues.append("User Authentication setting is not properly configured")
                
            # Min Encryption Level: 1=Low, 2=Medium, 3=High, 4=FIPS
            if min_encryption in [1, 2]:
                issues.append(f"RDP encryption level is too low: {min_encryption}")
            elif min_encryption in [3, 4]:
                result['findings'].append(f"RDP encryption level is adequately set: {min_encryption}")
            else:
                issues.append("RDP encryption level is not properly configured")
            
            # Determine overall status
            if not issues:
                result['status'] = 'passed'
                result['vulnerable'] = False
                result['findings'].append("RDP security layer is configured securely")
                self.results['findings'].append("RDP security layer is configured securely - good protection against relay attacks")
            else:
                result['status'] = 'failed'
                result['vulnerable'] = True
                for issue in issues:
                    result['findings'].append(issue)
                    self.results['findings'].append(f"Security issue: {issue}")
                
                # Add recommendations
                self.results['recommendations'].append("Configure RDP Security Layer to use TLS/SSL (value: 2)")
                self.results['recommendations'].append("Enable User Authentication for RDP (value: 1)")
                self.results['recommendations'].append("Set RDP encryption level to High or FIPS (value: 3 or 4)")
                
        except Exception as e:
            logger.error(f"Error testing RDP security layer: {e}")
            result['findings'].append(f"Error: {str(e)}")
            result['status'] = 'error'
        
        # Update test statistics
        self.tests_run += 1
        if result['status'] == 'passed':
            self.tests_passed += 1
        elif result['status'] == 'failed':
            self.tests_failed += 1
            
        # Update overall vulnerability status
        if result['vulnerable']:
            self.results['vulnerable_to_relay'] = True
            
        # Store test results
        self.results['tests']['rdp_security_layer'] = result
        return result
        
    def _check_xfreerdp_available(self) -> bool:
        """Check if xfreerdp is available in the system PATH
        
        Returns:
            bool: True if xfreerdp is available, False otherwise
        """
        try:
            result = subprocess.run(
                ['which', 'xfreerdp'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return result.returncode == 0
        except Exception as e:
            logger.warning(f"Failed to check xfreerdp availability: {str(e)}")
            return False
            
    def _generate_recommendations(self) -> None:
        """Generate security recommendations based on test results
        
        This method analyzes the test results and generates actionable
        security recommendations to mitigate identified vulnerabilities.
        """
        recommendations = []
        
        # Check Restricted Admin Mode
        restricted_admin_test = self.results['tests'].get('restricted_admin_mode', {})
        if restricted_admin_test.get('vulnerable', False):
            recommendations.extend([
                "Enable Restricted Admin Mode to prevent credential theft via relay attacks.",
                "To enable: Set 'Restrict delegation of credentials to remote servers' to 'Enabled' in Group Policy.",
                "Reference: https://docs.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard"
            ])
        
        # Check NLA requirement
        nla_test = self.results['tests'].get('nla_required', {})
        if nla_test.get('vulnerable', False):
            recommendations.extend([
                "Enforce Network Level Authentication (NLA) to prevent relay attacks.",
                "To enable: Set 'Require user authentication for remote connections by using Network Level Authentication' to 'Enabled' in Group Policy.",
                "Reference: https://docs.microsoft.com/en-us/windows/security/remote-management/winrm/winrm-security"
            ])
        
        # Check Credential Guard
        cred_guard_test = self.results['tests'].get('credential_guard', {})
        if cred_guard_test.get('vulnerable', False):
            recommendations.extend([
                "Enable Windows Defender Credential Guard to protect against credential theft.",
                "To enable: Use Group Policy or Device Guard and Credential Guard hardware readiness tool.",
                "Reference: https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard"
            ])
        
        # Check RDP Security Layer
        security_layer_test = self.results['tests'].get('rdp_security_layer', {})
        if security_layer_test.get('vulnerable', False):
            recommendations.extend([
                "Configure RDP to use TLS 1.2 or higher for all RDP connections.",
                "To configure: Set 'Require use of specific security layer for remote (RDP) connections' to 'SSL (TLS 1.0)' or higher in Group Policy.",
                "Reference: https://docs.microsoft.com/en-us/windows/security/remote-management/remote-desktop/rdp-security"
            ])
        
        # Add general recommendations if any tests failed or were skipped
        if not recommendations:
            recommendations = [
                "No specific vulnerabilities requiring immediate remediation were detected.",
                "Regularly review and update RDP security settings to maintain a strong security posture.",
                "Consider implementing additional security controls such as MFA and network segmentation."
            ]
        
        self.results['recommendations'] = recommendations
            
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all RDP relay attack tests with comprehensive error handling
        
        Returns:
            Dict: Combined test results with the following structure:
            {
                'target': str,
                'port': int,
                'timestamp': str (ISO format),
                'tests_run': int,
                'tests_passed': int,
                'tests_failed': int,
                'vulnerable_to_relay': bool,
                'tests': Dict[str, Dict],
                'findings': List[Dict],
                'recommendations': List[str],
                'execution_summary': {
                    'start_time': str (ISO format),
                    'end_time': str (ISO format),
                    'duration_seconds': float
                }
            }
        """
        start_time = datetime.now()
        logger.info(f"Running all RDP relay attack tests against {self.target}:{self.port}")
        
        # Reset test counters
        self.tests_run = 0
        self.tests_passed = 0
        self.tests_failed = 0
        
        # Check for required dependencies
        if not self._check_xfreerdp_available():
            logger.warning("xfreerdp not found. Some tests will be skipped.")
            self.results['warnings'] = self.results.get('warnings', []) + [
                'xfreerdp not found. Some tests requiring RDP connection will be skipped.'
            ]
        
        # Define test methods to run
        test_methods = [
            ('restricted_admin_mode', self.test_restricted_admin_mode),
            ('nla_required', self.test_nla_required),  # Fixed method name
            ('credential_guard', self.test_credential_guard),
            ('rdp_security_layer', self.test_rdp_security_layer)
        ]
        
        # Run each test with error handling
        for test_name, test_method in test_methods:
            try:
                logger.debug(f"Starting test: {test_name}")
                test_result = test_method()
                
                # Store test result
                self.results['tests'][test_name] = test_result
                
                # Update counters based on test status
                if test_result.get('status') == 'passed':
                    self.tests_passed += 1
                elif test_result.get('status') == 'failed':
                    self.tests_failed += 1
                    
                # Add findings if any
                if test_result.get('findings'):
                    self.results['findings'].extend(test_result['findings'])
                    
                logger.debug(f"Completed test {test_name}: {test_result.get('status')}")
                
            except Exception as e:
                error_msg = f"Error executing test {test_name}: {str(e)}"
                logger.error(error_msg, exc_info=self.verbose)
                self.results['tests'][test_name] = {
                    'test': test_name,
                    'status': 'error',
                    'error': error_msg,
                    'timestamp': datetime.now().isoformat()
                }
                self.tests_failed += 1
        
        # Update overall results
        self.results.update({
            'tests_run': self.tests_run,
            'tests_passed': self.tests_passed,
            'tests_failed': self.tests_failed,
            'vulnerable_to_relay': any(
                test.get('vulnerable', False) 
                for test in self.results['tests'].values()
                if isinstance(test, dict)
            )
        })
        
        # Generate recommendations
        try:
            self._generate_recommendations()
        except Exception as e:
            logger.error(f"Error generating recommendations: {str(e)}")
            self.results['recommendations'] = [
                "Failed to generate recommendations due to an error."
            ]
        
        # Add execution summary
        end_time = datetime.now()
        self.results['execution_summary'] = {
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration_seconds': (end_time - start_time).total_seconds()
        }
        
        status = 'VULNERABLE' if self.results['vulnerable_to_relay'] else 'SECURE'
        logger.info(
            f"Completed RDP relay attack tests. "
            f"Status: {status}. "
            f"Tests: {self.tests_passed}/{self.tests_run} passed"
        )
        
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
        print(" RDP Relay Attack Test Report")
        print(f" Target: {self.target}:{self.port}")
        print(f" Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*80 + "\n")
        
        summary = self.results['summary']
        vulnerable = self.results.get('vulnerable_to_relay', False)
        
        print(f"Relay Attack Vulnerability: {'✗ VULNERABLE' if vulnerable else '✓ SECURE'}")
        print(f"Tests Run: {summary['tests_run']}")
        print(f"Tests Passed: {summary['tests_passed']}")
        print(f"Tests Failed: {summary['tests_failed']}")
        
        if self.results.get('findings'):
            print("\nFindings:")
            for i, finding in enumerate(self.results['findings'], 1):
                print(f"  {i}. {finding}")
                
        if self.results.get('recommendations'):
            print("\nRecommendations:")
            for i, rec in enumerate(self.results['recommendations'], 1):
                print(f"  {i}. {rec}")
                
        print(f"\nFull report {'saved to ' + self.results.get('report_file', 'JSON report') if 'report_file' in self.results else 'available in JSON format'}")
        print("\n" + "="*80)


def parse_args():
    """Parse command line arguments
    
    Returns:
        argparse.Namespace: Parsed command-line arguments
    """
    parser = argparse.ArgumentParser(
        description='RDP Relay Attack Tester',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python rdp_relay_attack_tester.py 192.168.1.100
  python rdp_relay_attack_tester.py server.example.com -u admin -p password
  python rdp_relay_attack_tester.py 192.168.1.100 -u domain\\user -p password -o report.json
        """
    )
    
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--port', type=int, default=3389,
                      help='RDP port (default: 3389)')
    parser.add_argument('-u', '--username', help='Username for authentication')
    parser.add_argument('-P', '--password', help='Password for authentication')
    parser.add_argument('-d', '--domain', help='Domain for authentication')
    parser.add_argument('-o', '--output', help='Output file for JSON report')
    parser.add_argument('-v', '--verbose', action='store_true',
                      help='Enable verbose output')
    
    return parser.parse_args()


def main():
    """Main function to run the RDP relay attack tests"""
    # Parse arguments
    args = parse_args()
    
    # Set up logging verbosity
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Banner
    print("="*80)
    print(" RDP Relay Attack Tester")
    print(f" Target: {args.target}:{args.port}")
    print("="*80)
    print()
    
    try:
        # Initialize tester
        tester = RDPRelayAttackTester(
            target=args.target,
            port=args.port,
            username=args.username,
            password=args.password,
            domain=args.domain,
            verbose=args.verbose
        )
        
        # Run all tests
        results = tester.run_all_tests()
        
        # Generate report
        output_file = args.output
        if not output_file:
            # Create default output filename if not specified
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"rdp_relay_attack_{args.target}_{timestamp}.json"
            
        tester.generate_report(output_file)
        tester.results['report_file'] = output_file
        
        # Print summary
        tester.print_report_summary()
        
        # Return status code based on vulnerability
        return 1 if results.get('vulnerable_to_relay', False) else 0
    
    except KeyboardInterrupt:
        logger.warning("Testing interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Error running relay attack tests: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
