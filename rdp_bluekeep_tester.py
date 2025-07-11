#!/usr/bin/env python3
"""
RDP BlueKeep Vulnerability Tester (CVE-2019-0708)
This module tests RDP servers for BlueKeep vulnerability susceptibility.

BlueKeep is a critical vulnerability that affects older versions of Windows:
- Windows 7, Windows Server 2008 R2, and older versions
- Allows remote code execution without authentication
- Exploits RDP protocol handling vulnerabilities
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
        logging.FileHandler('rdp_bluekeep.log')
    ]
)
logger = logging.getLogger(__name__)


class RDPBlueKeepTester:
    """Tests RDP servers for BlueKeep vulnerability (CVE-2019-0708)"""
    
    def _run_command_safely(self, command: List[str], timeout: int = 30, check: bool = False) -> Dict[str, Any]:
        """Safely run a command with timeout and error handling
        
        Args:
            command: Command to run as list of strings
            timeout: Timeout in seconds
            check: If True, raises CalledProcessError on non-zero return code
            
        Returns:
            Dict containing command results or error information
        """
        result = {
            'success': False,
            'stdout': '',
            'stderr': '',
            'returncode': -1,
            'error': None
        }
        
        try:
            logger.debug(f"Running command: {' '.join(command)}")
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                result.update({
                    'success': process.returncode == 0 or not check,
                    'stdout': stdout.strip() if stdout else '',
                    'stderr': stderr.strip() if stderr else '',
                    'returncode': process.returncode
                })
                
                if check and process.returncode != 0:
                    result['error'] = f"Command failed with return code {process.returncode}"
                    logger.error(f"Command failed: {result['error']}")
                    
            except subprocess.TimeoutExpired:
                logger.warning(f"Command timed out after {timeout} seconds: {' '.join(command)}")
                process.kill()
                process.communicate()  # Clean up
                result['error'] = f"Command timed out after {timeout} seconds"
            except Exception as e:
                logger.error(f"Error executing command: {str(e)}")
                result['error'] = str(e)
                
        except Exception as e:
            logger.error(f"Failed to execute command: {str(e)}")
            result['error'] = str(e)
            
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
            
    def _check_nmap_available(self) -> bool:
        """Check if nmap is available in the system PATH
        
        Returns:
            bool: True if nmap is available, False otherwise
        """
        try:
            result = subprocess.run(
                ['which', 'nmap'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return result.returncode == 0
        except Exception as e:
            logger.warning(f"Failed to check nmap availability: {str(e)}")
            return False
            
    def __init__(self, target: str, port: int = 3389, username: str = None,
                 password: str = None, domain: str = None, verbose: bool = False):
        """Initialize the RDP BlueKeep tester with enhanced error handling
        
        Args:
            target: Target hostname or IP
            port: RDP port (default: 3389)
            username: Username for authentication (optional)
            password: Password for authentication (optional)
            domain: Domain for authentication (optional)
            verbose: Enable verbose output (default: False)
        """
        self.target = target
        self.port = port
        self.username = username
        self.password = password
        self.domain = domain
        self.verbose = verbose
        self.supports_winrm = False
        self.xfreerdp_available = False
        self.nmap_available = False
        
        # Set up result structure with enhanced metadata
        self.results = {
            'target': target,
            'port': port,
            'timestamp': datetime.now().isoformat(),
            'tests': {},
            'vulnerable_to_bluekeep': False,
            'findings': [],
            'recommendations': [],
            'warnings': [],
            'environment': {
                'python_version': sys.version,
                'platform': sys.platform,
                'executable': sys.executable
            },
            'dependencies': {
                'xfreerdp_available': False,
                'nmap_available': False,
                'winrm_available': False
            }
        }
        
        # Track test statistics
        self.tests_run = 0
        self.tests_passed = 0
        self.tests_failed = 0
        
        # Configure logging
        if verbose:
            logger.setLevel(logging.DEBUG)
            
        logger.info(f"Initialized RDP BlueKeep Tester for {target}:{port}")
        
        # Check for required tools
        self.xfreerdp_available = self._check_xfreerdp_available()
        self.nmap_available = self._check_nmap_available()
        
        # Update results with dependency information
        self.results['dependencies'].update({
            'xfreerdp_available': self.xfreerdp_available,
            'nmap_available': self.nmap_available
        })
        
        if not self.xfreerdp_available:
            msg = "xfreerdp not found in PATH. Some tests will be skipped."
            logger.warning(msg)
            self.results['warnings'].append(msg)
            
        if not self.nmap_available:
            msg = "nmap not found in PATH. Some tests will be skipped."
            logger.warning(msg)
            self.results['warnings'].append(msg)
        
        # Check if WinRM is available for extended tests
        try:
            import winrm
            self.supports_winrm = True
            self.results['dependencies']['winrm_available'] = True
        except ImportError:
            msg = "WinRM module not available, some tests will be skipped"
            logger.warning(msg)
            self.results['warnings'].append(msg)
    
    def _add_test_result(self, test_name: str, result: Dict[str, Any]) -> None:
        """Add test result to the results dictionary with enhanced metadata
        
        Args:
            test_name: Name of the test
            result: Test result dictionary
        """
        # Add common metadata
        result['timestamp'] = datetime.now().isoformat()
        result['test'] = test_name
        
        # Calculate duration if start_time is present
        if 'start_time' in result and 'end_time' in result:
            start = datetime.fromisoformat(result['start_time'])
            end = datetime.fromisoformat(result['end_time'])
            result['duration_seconds'] = (end - start).total_seconds()
            
        # Update test statistics
        self.tests_run += 1
        if result.get('status') == 'passed':
            self.tests_passed += 1
        elif result.get('status') == 'failed':
            self.tests_failed += 1
            
        # Add to results
        self.results['tests'][test_name] = result
        
        # Update overall vulnerability status if this test found a vulnerability
        if result.get('vulnerable', False):
            self.results['vulnerable_to_bluekeep'] = True
            if result.get('severity') not in self.results.get('findings', []):
                self.results['findings'].append(result.get('severity', 'medium'))
    
    def test_os_version_vulnerability(self) -> Dict[str, Any]:
        """Test if the target OS version is vulnerable to BlueKeep
        
        Returns:
            Dict: Test results with vulnerability information
        """
        test_name = 'os_version_vulnerability'
        logger.info(f"Testing OS version vulnerability on {self.target}")
        
        result = {
            'test': test_name,
            'description': 'Checks if the operating system version is vulnerable to BlueKeep',
            'status': 'unknown',
            'findings': [],
            'vulnerable': False,
            'severity': 'critical',
            'start_time': datetime.now().isoformat(),
            'details': {
                'os_detection_methods': [],
                'version_info': {}
            },
            'references': [
                'CVE-2019-0708',
                'https://nvd.nist.gov/vuln/detail/CVE-2019-0708',
                'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708'
            ]
        }
        
        # Skip if WinRM is not available
        if not self.supports_winrm or not self.username or not self.password:
            result['status'] = 'skipped'
            result['findings'].append("Skipped test - requires WinRM and credentials")
            self.results['tests']['os_version_vulnerability'] = result
            return result
        
        try:
            import winrm
            
            # Create WinRM session
            auth = f"{self.domain}\\{self.username}" if self.domain else self.username
            session = winrm.Session(
                f'http://{self.target}:5985/wsman',
                auth=(auth, self.password)
            )
            
            # PowerShell script to check OS version and patch level
            ps_script = """
            # Get OS information
            $os = Get-WmiObject -Class Win32_OperatingSystem
            Write-Output "OSVersion: $($os.Version)"
            Write-Output "OSName: $($os.Caption)"
            Write-Output "ServicePack: $($os.ServicePackMajorVersion).$($os.ServicePackMinorVersion)"
            Write-Output "Architecture: $($os.OSArchitecture)"
            Write-Output "BuildNumber: $($os.BuildNumber)"
            
            # Check for specific BlueKeep patches
            $patches = @(
                "KB4499180",  # Windows 7 / Server 2008 R2
                "KB4499175",  # Windows Server 2008
                "KB4499149",  # Windows XP
                "KB4500331"   # Additional patch
            )
            
            foreach ($patch in $patches) {
                $installed = Get-HotFix -Id $patch -ErrorAction SilentlyContinue
                if ($installed) {
                    Write-Output "Patch: $patch - INSTALLED"
                } else {
                    Write-Output "Patch: $patch - NOT INSTALLED"
                }
            }
            
            # Check RDP service status
            $rdpService = Get-Service -Name "TermService" -ErrorAction SilentlyContinue
            if ($rdpService) {
                Write-Output "RDPService: $($rdpService.Status)"
            } else {
                Write-Output "RDPService: Not found"
            }
            """
            
            result_data = session.run_ps(ps_script)
            output = result_data.std_out.decode('utf-8', errors='ignore')
            
            # Process the output
            os_version = ""
            os_name = ""
            build_number = ""
            patches_installed = []
            patches_missing = []
            rdp_service_running = False
            
            for line in output.splitlines():
                line = line.strip()
                result['findings'].append(line)
                
                if line.startswith("OSVersion:"):
                    os_version = line.split(":", 1)[1].strip()
                    
                if line.startswith("OSName:"):
                    os_name = line.split(":", 1)[1].strip()
                    
                if line.startswith("BuildNumber:"):
                    build_number = line.split(":", 1)[1].strip()
                    
                if line.startswith("Patch:"):
                    parts = line.split(" - ")
                    if len(parts) == 2:
                        patch_id = parts[0].split(":")[1].strip()
                        status = parts[1].strip()
                        if status == "INSTALLED":
                            patches_installed.append(patch_id)
                        else:
                            patches_missing.append(patch_id)
                            
                if line.startswith("RDPService: Running"):
                    rdp_service_running = True
            
            # Determine vulnerability based on OS version and patches
            vulnerable_os = False
            
            # Check for vulnerable Windows versions
            if "Windows 7" in os_name or "2008" in os_name:
                vulnerable_os = True
                result['findings'].append("Operating system is potentially vulnerable to BlueKeep")
                
            if "Windows XP" in os_name or "Windows Server 2003" in os_name:
                vulnerable_os = True
                result['findings'].append("Legacy operating system - highly vulnerable to BlueKeep")
                
            # Check build number for specific vulnerable versions
            if build_number:
                try:
                    build_num = int(build_number)
                    # Windows 7 / Server 2008 R2 build numbers
                    if 7600 <= build_num <= 7601:
                        vulnerable_os = True
                        result['findings'].append(f"Build number {build_num} is vulnerable to BlueKeep")
                except ValueError:
                    pass
            
            # Evaluate patch status
            has_bluekeep_patches = len(patches_installed) > 0
            
            if vulnerable_os and not has_bluekeep_patches:
                result['status'] = 'failed'
                result['vulnerable'] = True
                self.results['vulnerable_to_bluekeep'] = True
                result['findings'].append("VULNERABLE: OS version susceptible and no BlueKeep patches detected")
                self.results['findings'].append("System appears vulnerable to BlueKeep (CVE-2019-0708)")
                
                # Add recommendations
                self.results['recommendations'].append("URGENT: Install BlueKeep security patches immediately")
                self.results['recommendations'].append("Consider disabling RDP if not absolutely necessary")
                self.results['recommendations'].append("Implement network segmentation to limit RDP exposure")
                
            elif vulnerable_os and has_bluekeep_patches:
                result['status'] = 'passed'
                result['vulnerable'] = False
                result['findings'].append("OS version was vulnerable but patches are installed")
                self.results['findings'].append("BlueKeep patches detected - system appears protected")
                
            else:
                result['status'] = 'passed'
                result['vulnerable'] = False
                result['findings'].append("Operating system version not vulnerable to BlueKeep")
                self.results['findings'].append("OS version not affected by BlueKeep vulnerability")
                
            # Note RDP service status
            if rdp_service_running:
                result['findings'].append("RDP service is running - attack surface is active")
                if result['vulnerable']:
                    self.results['findings'].append("CRITICAL: Vulnerable system has RDP service running")
                    
        except Exception as e:
            logger.error(f"Error testing OS version vulnerability: {e}")
            result['findings'].append(f"Error: {str(e)}")
            result['status'] = 'error'
            # Assume vulnerable on error for safety
            result['vulnerable'] = True
            self.results['vulnerable_to_bluekeep'] = True
        
        # Update test statistics
        self.tests_run += 1
        if result['status'] == 'passed':
            self.tests_passed += 1
        elif result['status'] == 'failed':
            self.tests_failed += 1
            
        # Store test results
        self.results['tests']['os_version_vulnerability'] = result
        return result
        
    def test_rdp_protocol_vulnerability(self) -> Dict[str, Any]:
        """Test RDP protocol for BlueKeep vulnerability indicators with enhanced error handling
        
        Returns:
            Dict: Detailed test results with vulnerability information and mitigation guidance
        """
        test_name = 'rdp_protocol_vulnerability'
        logger.info(f"Testing RDP protocol vulnerability on {self.target}")
        
        result = {
            'test': test_name,
            'description': 'Tests RDP protocol handling for BlueKeep vulnerability indicators',
            'status': 'unknown',
            'findings': [],
            'vulnerable': False,
            'severity': 'critical',
            'start_time': datetime.now().isoformat(),
            'details': {
                'connection_attempt': None,
                'protocol_analysis': {},
                'security_checks': {},
                'error': None
            },
            'mitigations': [
                'Enable Network Level Authentication (NLA)',
                'Apply latest Windows security updates',
                'Restrict RDP access using firewalls',
                'Consider using a VPN instead of direct RDP exposure'
            ],
            'references': [
                'CVE-2019-0708',
                'https://nvd.nist.gov/vuln/detail/CVE-2019-0708',
                'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708',
                'https://www.cisa.gov/uscert/ncas/alerts/aa19-168a'
            ]
        }
        
        try:
            # Record connection attempt details
            conn_details = {
                'target': f"{self.target}:{self.port}",
                'timestamp': datetime.now().isoformat(),
                'status': 'initiated'
            }
            
            # Test basic RDP connection capabilities with enhanced error handling
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)  # 10 second timeout for connection attempt
            
            try:
                # Attempt connection to RDP port with timing
                connect_start = time.time()
                sock.connect((self.target, self.port))
                connect_time = time.time() - connect_start
                
                conn_details.update({
                    'status': 'connected',
                    'connect_time_seconds': round(connect_time, 3),
                    'remote_address': sock.getpeername(),
                    'local_address': sock.getsockname()
                })
                
                result['findings'].append(f"RDP port {self.port} is open and accepting connections")
                result['details']['connection_attempt'] = conn_details
                
                # Prepare RDP negotiation request with detailed protocol handling
                rdp_nego_request = b'\x03\x00'  # TPKT header
                rdp_nego_request += b'\x00\x13'  # Length
                rdp_nego_request += b'\x0e\xe0'  # X.224 Data TPDU
                rdp_nego_request += b'\x00\x00'  # Dst-Ref
                rdp_nego_request += b'\x00\x00'  # Src-Ref
                rdp_nego_request += b'\x00'      # Class 0
                rdp_nego_request += b'\x01'      # Connect-Request
                rdp_nego_request += b'\x00\x08'  # Destination reference
                rdp_nego_request += b'\x03'      # TPDU size
                rdp_nego_request += b'\x00'      # Data
                
                # Log the request details
                protocol_info = {
                    'request_sent': datetime.now().isoformat(),
                    'request_hex': rdp_nego_request.hex(),
                    'request_length': len(rdp_nego_request)
                }
                result['details']['protocol_analysis']['negotiation_request'] = protocol_info
                
                try:
                    # Send the negotiation request
                    sock.send(rdp_nego_request)
                    
                    # Read response with timeout
                    sock.settimeout(10)  # 10 second timeout for response
                    response_start = time.time()
                    response = sock.recv(1024)
                    response_time = time.time() - response_start
                    
                    protocol_info.update({
                        'response_received': datetime.now().isoformat(),
                        'response_time_seconds': round(response_time, 3),
                        'response_hex': response.hex() if response else None,
                        'response_length': len(response) if response else 0
                    })
                    
                    if response:
                        result['findings'].append("Received RDP negotiation response")
                    
                    # Initialize security checks
                    security_checks = {
                        'has_rdp_header': False,
                        'has_valid_protocol': False,
                        'nla_required': False,
                        'vulnerable_indicators': []
                    }
                    
                    # Analyze response for vulnerability indicators
                    if len(response) >= 4:
                        # Check RDP response structure (TPKT header)
                        if response[0:2] == b'\x03\x00':
                            security_checks['has_rdp_header'] = True
                            result['findings'].append("Valid RDP protocol response detected")
                            
                            # Check for X.224 Connection Confirm (0x0d)
                            if len(response) > 5 and response[5] == 0x0d:
                                security_checks['has_valid_protocol'] = True
                                result['findings'].append("RDP protocol negotiation successful")
                                
                                # Check protocol version
                                if len(response) > 10:
                                    protocol_version = response[8:10]
                                    protocol_info['negotiated_version'] = f"0x{protocol_version.hex()}"
                                    
                                    # Check for NLA requirement (Security Exchange)
                                    if b'\x0e\xe0' in response:  # X.224 Data TPDU
                                        security_checks['nla_required'] = True
                                        result['findings'].append("RDP requires Network Level Authentication (NLA)")
                                    else:
                                        security_checks['vulnerable_indicators'].append("NLA_NOT_REQUIRED")
                                        result['findings'].append("RDP accepts connections without NLA - potential vulnerability")
                                        
                                    # Additional vulnerability indicators
                                    if b'\x01\x00' in response:
                                        security_checks['vulnerable_indicators'].append("CREDSSP_ACCEPTED")
                                        result['findings'].append("CREDSSP accepted - potential vulnerability indicator")
                                        
                                    if b'\x02\x00' in response:  # Connection accepted
                                        security_checks['vulnerable_indicators'].append("CONNECTION_ACCEPTED")
                                        result['findings'].append("RDP connection accepted without authentication")
                    
                    # Update result with security check findings
                    result['details']['security_checks'] = security_checks
                    
                    # Determine vulnerability status based on security checks
                    if security_checks.get('vulnerable_indicators'):
                        result['vulnerable'] = True
                        result['status'] = 'failed'
                        self.results['vulnerable_to_bluekeep'] = True
                        result['findings'].append("VULNERABLE: RDP protocol analysis indicates potential BlueKeep vulnerability")
                    else:
                        result['vulnerable'] = False
                        result['status'] = 'passed'
                        result['findings'].append("No clear BlueKeep vulnerability indicators in RDP protocol")
                        
                    # Add protocol details to results
                    result['details']['protocol_analysis']['security_assessment'] = security_checks
                    
                except socket.timeout:
                    result['findings'].append("Timeout waiting for RDP protocol response")
                    result['status'] = 'error'
                    
                except Exception as e:
                    logger.error(f"Error during RDP protocol analysis: {e}")
                    result['findings'].append(f"Error analyzing RDP protocol: {str(e)}")
                    result['status'] = 'error'
                
            except socket.timeout as e:
                error_msg = f"Connection attempt timed out: {str(e)}"
                logger.warning(error_msg)
                result['findings'].append(error_msg)
                conn_details['status'] = 'timeout'
                conn_details['error'] = str(e)
                result['status'] = 'error'
                result['details']['error'] = error_msg
                
            except ConnectionRefusedError as e:
                error_msg = f"Connection to {self.target}:{self.port} was refused"
                logger.warning(error_msg)
                result['findings'].append(error_msg)
                conn_details['status'] = 'refused'
                conn_details['error'] = str(e)
                result['status'] = 'error'
                result['details']['error'] = error_msg
                
            except socket.gaierror as e:
                error_msg = f"Address resolution failed: {str(e)}"
                logger.error(error_msg)
                result['findings'].append(error_msg)
                conn_details['status'] = 'resolution_failed'
                conn_details['error'] = str(e)
                result['status'] = 'error'
                result['details']['error'] = error_msg
                
            except Exception as e:
                error_msg = f"Unexpected connection error: {str(e)}"
                logger.error(error_msg, exc_info=self.verbose)
                result['findings'].append(error_msg)
                conn_details['status'] = 'error'
                conn_details['error'] = str(e)
                result['status'] = 'error'
                result['details']['error'] = error_msg
                
            finally:
                try:
                    if 'sock' in locals() and sock:
                        sock.close()
                        conn_details['closed'] = True
                except Exception as e:
                    logger.warning(f"Error closing socket: {str(e)}")
        
        except Exception as e:
            error_msg = f"Error testing RDP protocol: {str(e)}"
            logger.error(error_msg, exc_info=self.verbose)
            result['findings'].append(error_msg)
            result['status'] = 'error'
            result['details']['error'] = error_msg
            
            # Update connection details if available
            if 'conn_details' in locals():
                conn_details['status'] = 'error'
                conn_details['error'] = str(e)
                
        # Set final status if not already set
        if result['status'] not in ['passed', 'failed', 'error']:
            if result.get('vulnerable', False):
                result['status'] = 'failed'
                self.results['vulnerable_to_bluekeep'] = True
            else:
                result['status'] = 'passed'
                result['findings'].append("No clear BlueKeep vulnerability indicators in RDP protocol")
                
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
        
        # Update test statistics and store results
        self._add_test_result(test_name, result)
        
        # Log test completion
        if result.get('status') == 'passed':
            logger.info(f"{test_name} completed successfully")
        elif result.get('status') == 'failed':
            logger.warning(f"{test_name} found potential vulnerabilities")
        else:
            logger.error(f"{test_name} encountered errors")
            
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
        
        return result
    
    def test_rdp_security_configuration(self) -> Dict[str, Any]:
        """Test RDP security configuration that might mitigate BlueKeep
        
        Returns:
            Dict: Test results
        """
        logger.info(f"Testing RDP security configuration on {self.target}")
        
        result = {
            'test': 'rdp_security_configuration',
            'description': 'Checks RDP security settings that help mitigate BlueKeep attacks',
            'status': 'unknown',
            'findings': [],
            'vulnerable': False
        }
        
        # Skip if WinRM is not available
        if not self.supports_winrm or not self.username or not self.password:
            result['status'] = 'skipped'
            result['findings'].append("Skipped test - requires WinRM and credentials")
            self.results['tests']['rdp_security_configuration'] = result
            return result
        
        try:
            import winrm
            
            # Create WinRM session
            auth = f"{self.domain}\\{self.username}" if self.domain else self.username
            session = winrm.Session(
                f'http://{self.target}:5985/wsman',
                auth=(auth, self.password)
            )
            
            # PowerShell script to check RDP security configuration
            ps_script = """
            # Check Network Level Authentication (critical for BlueKeep mitigation)
            $nla = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue
            if ($nla -ne $null) {
                Write-Output "NLA: $($nla.UserAuthentication)"
            } else {
                Write-Output "NLA: Not configured"
            }
            
            # Check security layer settings
            $secLayer = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -ErrorAction SilentlyContinue
            if ($secLayer -ne $null) {
                Write-Output "SecurityLayer: $($secLayer.SecurityLayer)"
            } else {
                Write-Output "SecurityLayer: Not configured"
            }
            
            # Check if RDP is disabled
            $rdpDisabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
            if ($rdpDisabled -ne $null) {
                Write-Output "RDPDisabled: $($rdpDisabled.fDenyTSConnections)"
            } else {
                Write-Output "RDPDisabled: Not configured"
            }
            
            # Check firewall rules for RDP
            try {
                $firewallRules = Get-NetFirewallRule -DisplayName "*Remote Desktop*" -ErrorAction SilentlyContinue | Where-Object {$_.Enabled -eq "True"}
                if ($firewallRules) {
                    Write-Output "FirewallRDP: Enabled"
                    $firewallRules | ForEach-Object { Write-Output "FirewallRule: $($_.DisplayName) - $($_.Action)" }
                } else {
                    Write-Output "FirewallRDP: No active rules"
                }
            } catch {
                Write-Output "FirewallRDP: Could not check"
            }
            
            # Check RDP port configuration
            $rdpPort = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "PortNumber" -ErrorAction SilentlyContinue
            if ($rdpPort -ne $null) {
                Write-Output "RDPPort: $($rdpPort.PortNumber)"
            } else {
                Write-Output "RDPPort: Default (3389)"
            }
            """
            
            result_data = session.run_ps(ps_script)
            output = result_data.std_out.decode('utf-8', errors='ignore')
            
            # Process the output
            nla_enabled = None
            security_layer = None
            rdp_disabled = None
            firewall_enabled = False
            rdp_port = 3389
            
            security_issues = []
            
            for line in output.splitlines():
                line = line.strip()
                result['findings'].append(line)
                
                if line.startswith("NLA:"):
                    try:
                        nla_enabled = int(line.split(":")[1].strip())
                    except (ValueError, IndexError):
                        pass
                        
                if line.startswith("SecurityLayer:"):
                    try:
                        security_layer = int(line.split(":")[1].strip())
                    except (ValueError, IndexError):
                        pass
                        
                if line.startswith("RDPDisabled:"):
                    try:
                        rdp_disabled = int(line.split(":")[1].strip())
                    except (ValueError, IndexError):
                        pass
                        
                if line.startswith("FirewallRDP: Enabled"):
                    firewall_enabled = True
                    
                if line.startswith("RDPPort:"):
                    try:
                        rdp_port = int(line.split(":")[1].strip())
                    except (ValueError, IndexError):
                        pass
            
            # Evaluate security configuration
            # Network Level Authentication is critical for BlueKeep mitigation
            if nla_enabled != 1:
                security_issues.append("Network Level Authentication (NLA) is not enabled - critical for BlueKeep protection")
                result['vulnerable'] = True
            else:
                result['findings'].append("Network Level Authentication is enabled - good BlueKeep mitigation")
                
            # Security layer should be TLS/SSL for best protection
            if security_layer != 2:
                security_issues.append("RDP Security Layer not set to TLS/SSL - less secure")
                
            # Check if RDP is disabled (best mitigation)
            if rdp_disabled == 1:
                result['findings'].append("RDP is disabled - best protection against BlueKeep")
            else:
                result['findings'].append("RDP is enabled - ensure proper security configuration")
                
            # Firewall protection
            if not firewall_enabled:
                security_issues.append("No active firewall rules found for RDP - network exposure risk")
                
            # Non-standard port provides some security through obscurity
            if rdp_port != 3389:
                result['findings'].append(f"RDP configured on non-standard port {rdp_port} - slight security improvement")
            else:
                result['findings'].append("RDP using standard port 3389 - easily discoverable")
                
            # Determine overall status
            if security_issues:
                result['status'] = 'failed'
                result['vulnerable'] = True
                for issue in security_issues:
                    result['findings'].append(issue)
                    self.results['findings'].append(f"RDP security issue: {issue}")
                    
        elif result['status'] == 'failed':
            self.tests_failed += 1
            
        # Update overall vulnerability status
        if result['vulnerable']:
            self.results['vulnerable_to_bluekeep'] = True
            
        # Store test results
        self.results['tests']['rdp_security_configuration'] = result
        return result
        
    def _generate_recommendations(self) -> None:
        """Generate security recommendations based on test results
        
        This method analyzes the test results and generates actionable
        security recommendations to mitigate BlueKeep vulnerability.
        """
        recommendations = []
        
        # Base recommendations for any vulnerable system
        if self.results.get('vulnerable_to_bluekeep', False):
            recommendations.extend([
                "Apply the latest Windows updates immediately to patch the BlueKeep vulnerability (CVE-2019-0708).",
                "If patching is not possible, enable Network Level Authentication (NLA) to mitigate the risk.",
                "Block TCP port 3389 at the network perimeter if RDP access is not required from external networks.",
                "Consider using a VPN for remote access instead of exposing RDP directly to the internet.",
                "Enable Windows Firewall to restrict RDP access to authorized IP addresses only.",
                "Review and implement the Microsoft Security Advisory for CVE-2019-0708: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708"
            ])
        
        # Add specific recommendations based on test results
        for test_name, test_result in self.results.get('tests', {}).items():
            if test_result.get('vulnerable', False):
                if test_name == 'os_version_vulnerability':
                    recommendations.append(
                        "The operating system is vulnerable to BlueKeep. Upgrade to a supported Windows version "
                        "or apply all available security updates."
                    )
                elif test_name == 'rdp_protocol_vulnerability':
                    recommendations.append(
                        "The RDP protocol configuration is vulnerable. Enable Network Level Authentication (NLA) "
                        "and require high encryption for all RDP connections."
                    )
        
        # Add general security recommendations
        recommendations.extend([
            "Regularly update and patch all systems to protect against known vulnerabilities.",
            "Implement network segmentation to limit the attack surface.",
            "Monitor for suspicious RDP connection attempts and failed authentication events.",
            "Consider using Remote Credential Guard if available on your Windows version.",
            "Regularly audit and review RDP access controls and permissions."
        ])
        
        self.results['recommendations'] = list(dict.fromkeys(recommendations))  # Remove duplicates while preserving order
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all BlueKeep vulnerability tests with comprehensive error handling
        
        Returns:
            Dict: Combined test results with detailed status and findings
        """
        logger.info(f"Running all BlueKeep vulnerability tests against {self.target}:{self.port}")
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
            
            # Run core vulnerability tests
            logger.info("Running core vulnerability tests...")
            self.test_os_version_vulnerability()
            self.test_rdp_protocol_vulnerability()
            self.test_nla_requirement()
            self.test_rdp_encryption()
            
            # Run WinRM-based tests if available
            if self.supports_winrm and self.username and self.password:
                logger.info("Running WinRM-based tests...")
                self.test_windows_updates()
                self.test_rdp_service_config()
            else:
                logger.info("Skipping WinRM tests - credentials or WinRM not available")
            
            # Update final status
            self.results.update({
                'status': 'completed',
                'tests_run': self.tests_run,
                'tests_passed': self.tests_passed,
                'tests_failed': self.tests_failed,
                'end_time': datetime.now().isoformat(),
                'execution_time_seconds': time.time() - start_time,
                'vulnerable_to_bluekeep': any(
                    test.get('vulnerable', False) 
                    for test in self.results.get('tests', {}).values()
                )
            })
            
            # Generate recommendations based on test results
            self._generate_recommendations()
            
            # Log completion status
            status = 'VULNERABLE' if self.results['vulnerable_to_bluekeep'] else 'SECURE'
            logger.info(
                f"Completed BlueKeep vulnerability tests. Status: {status}. "
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
        print(" RDP BlueKeep Vulnerability Test Report")
        print(f" Target: {self.target}:{self.port}")
        print(f" Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*80 + "\n")
        
        summary = self.results['summary']
        vulnerable = self.results.get('vulnerable_to_bluekeep', False)
        
        print(f"BlueKeep Vulnerability: {'✗ VULNERABLE' if vulnerable else '✓ SECURE'}")
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
                
        if vulnerable:
            print("\n⚠️  CRITICAL: This system appears vulnerable to BlueKeep (CVE-2019-0708)")
            print("   This is a CRITICAL vulnerability that allows remote code execution")
            print("   without authentication. Immediate patching is required!")
                
        print(f"\nFull report {'saved to ' + self.results.get('report_file', 'JSON report') if 'report_file' in self.results else 'available in JSON format'}")
        print("\n" + "="*80)


def parse_args():
    """Parse command line arguments
    
    Returns:
        argparse.Namespace: Parsed command-line arguments
    """
    parser = argparse.ArgumentParser(
        description='RDP BlueKeep Vulnerability Tester (CVE-2019-0708)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python rdp_bluekeep_tester.py 192.168.1.100
  python rdp_bluekeep_tester.py server.example.com -u admin -p password
  python rdp_bluekeep_tester.py 192.168.1.100 -u domain\\user -p password -o report.json

CRITICAL: BlueKeep is a severe vulnerability that allows remote code execution
without authentication. Vulnerable systems should be patched immediately.
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
    """Main function to run the RDP BlueKeep vulnerability tests"""
    # Parse arguments
    args = parse_args()
    
    # Set up logging verbosity
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Banner
    print("="*80)
    print(" RDP BlueKeep Vulnerability Tester (CVE-2019-0708)")
    print(f" Target: {args.target}:{args.port}")
    print(" ⚠️  CRITICAL VULNERABILITY SCANNER ⚠️")
    print("="*80)
    print()
    
    try:
        # Initialize tester
        tester = RDPBlueKeepTester(
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
            output_file = f"rdp_bluekeep_{args.target}_{timestamp}.json"
            
        tester.generate_report(output_file)
        tester.results['report_file'] = output_file
        
        # Print summary
        tester.print_report_summary()
        
        # Return status code based on vulnerability
        return 1 if results.get('vulnerable_to_bluekeep', False) else 0
    
    except KeyboardInterrupt:
        logger.warning("Testing interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Error running BlueKeep tests: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
