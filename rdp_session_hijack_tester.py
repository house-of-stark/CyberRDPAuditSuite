#!/usr/bin/env python3
"""
RDP Session Hijack Tester
This module tests RDP servers for susceptibility to session hijacking attacks.

It includes detection of security measures that prevent session hijacking, such as:
- Session isolation and security
- Console session protection
- Session ownership validation  
- Disconnection handling security
- Multi-user session controls
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
        logging.FileHandler('rdp_session_hijack.log')
    ]
)
logger = logging.getLogger(__name__)


class RDPSessionHijackTester:
    """Tests RDP servers for session hijacking vulnerabilities"""
    
    def __init__(self, target: str, port: int = 3389, username: str = None,
                 password: str = None, domain: str = None, verbose: bool = False):
        """Initialize the RDP session hijack tester
        
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
            'vulnerable_to_hijacking': False,
            'findings': [],
            'recommendations': []
        }
        
        # Track test statistics
        self.tests_run = 0
        self.tests_passed = 0
        self.tests_failed = 0
        
        if verbose:
            logger.setLevel(logging.DEBUG)
            
        logger.info(f"Initialized RDP Session Hijack Tester for {target}:{port}")
        
        # Check if WinRM is available for extended tests
        try:
            import winrm
            self.supports_winrm = True
        except ImportError:
            logger.warning("WinRM module not available, some tests will be skipped")
    
    def test_console_session_protection(self) -> Dict[str, Any]:
        """Test console session protection settings
        
        Returns:
            Dict: Test results
        """
        logger.info(f"Testing console session protection on {self.target}")
        
        result = {
            'test': 'console_session_protection',
            'description': 'Checks if console session is protected from hijacking',
            'status': 'unknown',
            'findings': [],
            'vulnerable': True  # Default to vulnerable
        }
        
        # Skip if WinRM is not available
        if not self.supports_winrm or not self.username or not self.password:
            result['status'] = 'skipped'
            result['findings'].append("Skipped test - requires WinRM and credentials")
            self.results['tests']['console_session_protection'] = result
            return result
        
        try:
            import winrm
            
            # Create WinRM session
            auth = f"{self.domain}\\{self.username}" if self.domain else self.username
            session = winrm.Session(
                f'http://{self.target}:5985/wsman',
                auth=(auth, self.password)
            )
            
            # PowerShell script to check console session protection
            ps_script = """
            # Check if console session can be shadowed/controlled by other users
            $tsconfig = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue
            
            # Check TSUserEnabled (Terminal Services User Access)
            $tsUserEnabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "TSUserEnabled" -ErrorAction SilentlyContinue
            if ($tsUserEnabled -ne $null) {
                Write-Output "TSUserEnabled: $($tsUserEnabled.TSUserEnabled)"
            } else {
                Write-Output "TSUserEnabled: Not configured"
            }
            
            # Check TSEnabled (Terminal Services Enabled)
            $tsEnabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
            if ($tsEnabled -ne $null) {
                Write-Output "fDenyTSConnections: $($tsEnabled.fDenyTSConnections)"
            } else {
                Write-Output "fDenyTSConnections: Not configured"
            }
            
            # Check AllowTSConnections
            $allowTS = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "AllowTSConnections" -ErrorAction SilentlyContinue
            if ($allowTS -ne $null) {
                Write-Output "AllowTSConnections: $($allowTS.AllowTSConnections)"
            } else {
                Write-Output "AllowTSConnections: Not configured"
            }
            
            # Check session directory settings
            $sessionDir = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\ClusterSettings" -ErrorAction SilentlyContinue
            if ($sessionDir -ne $null) {
                Write-Output "SessionDirectoryActive: $($sessionDir.SessionDirectoryActive)"
                Write-Output "SessionDirectoryLocation: $($sessionDir.SessionDirectoryLocation)"
            } else {
                Write-Output "SessionDirectory: Not configured"
            }
            
            # Check current active sessions
            try {
                $sessions = quser 2>$null
                if ($sessions) {
                    Write-Output "ActiveSessions: Found"
                    $sessions | ForEach-Object { Write-Output "Session: $_" }
                } else {
                    Write-Output "ActiveSessions: None found"
                }
            } catch {
                Write-Output "ActiveSessions: Could not query"
            }
            """
            
            result_data = session.run_ps(ps_script)
            output = result_data.std_out.decode('utf-8', errors='ignore')
            
            # Process the output
            ts_user_enabled = None
            deny_connections = None
            allow_connections = None
            session_dir_active = False
            active_sessions = False
            
            issues = []
            
            for line in output.splitlines():
                line = line.strip()
                result['findings'].append(line)
                
                if line.startswith("TSUserEnabled:"):
                    try:
                        ts_user_enabled = int(line.split(":")[1].strip())
                    except (ValueError, IndexError):
                        pass
                        
                if line.startswith("fDenyTSConnections:"):
                    try:
                        deny_connections = int(line.split(":")[1].strip())
                    except (ValueError, IndexError):
                        pass
                        
                if line.startswith("AllowTSConnections:"):
                    try:
                        allow_connections = int(line.split(":")[1].strip())
                    except (ValueError, IndexError):
                        pass
                        
                if line.startswith("SessionDirectoryActive:"):
                    try:
                        session_dir_active = int(line.split(":")[1].strip()) == 1
                    except (ValueError, IndexError):
                        pass
                        
                if line.startswith("ActiveSessions: Found") or line.startswith("Session:"):
                    active_sessions = True
            
            # Evaluate security based on values
            # TSUserEnabled: 0=Disabled (more secure), 1=Enabled
            if ts_user_enabled == 1:
                issues.append("Terminal Services user access is enabled - potential hijacking risk")
                
            # fDenyTSConnections: 0=Allow connections, 1=Deny connections
            if deny_connections == 0:
                result['findings'].append("Terminal Services connections are allowed")
            elif deny_connections == 1:
                result['findings'].append("Terminal Services connections are denied")
                
            # Session Directory can help with session management but also creates centralized attack target
            if session_dir_active:
                result['findings'].append("Session Directory is active - centralized session management")
                
            if active_sessions:
                issues.append("Active sessions detected - potential targets for hijacking")
                self.results['findings'].append("Active RDP sessions detected - verify session isolation")
                
            # Determine overall status
            if not issues:
                result['status'] = 'passed'
                result['vulnerable'] = False
                result['findings'].append("Console session protection appears adequate")
                self.results['findings'].append("Console session protection settings are secure")
            else:
                result['status'] = 'failed' if len(issues) > 1 else 'warning'
                result['vulnerable'] = True
                for issue in issues:
                    result['findings'].append(issue)
                    self.results['findings'].append(f"Security concern: {issue}")
                
                # Add recommendations
                self.results['recommendations'].append("Review Terminal Services configuration for security")
                self.results['recommendations'].append("Implement session isolation and monitoring")
                self.results['recommendations'].append("Consider disabling unused RDP features")
                
        except Exception as e:
            logger.error(f"Error testing console session protection: {e}")
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
            self.results['vulnerable_to_hijacking'] = True
            
        # Store test results
        self.results['tests']['console_session_protection'] = result
        return result
        
    def test_session_isolation(self) -> Dict[str, Any]:
        """Test session isolation mechanisms
        
        Returns:
            Dict: Test results
        """
        logger.info(f"Testing session isolation on {self.target}")
        
        result = {
            'test': 'session_isolation',
            'description': 'Checks if RDP sessions are properly isolated from each other',
            'status': 'unknown',
            'findings': [],
            'vulnerable': True  # Default to vulnerable
        }
        
        # Skip if WinRM is not available
        if not self.supports_winrm or not self.username or not self.password:
            result['status'] = 'skipped'
            result['findings'].append("Skipped test - requires WinRM and credentials")
            self.results['tests']['session_isolation'] = result
            return result
        
        try:
            import winrm
            
            # Create WinRM session
            auth = f"{self.domain}\\{self.username}" if self.domain else self.username
            session = winrm.Session(
                f'http://{self.target}:5985/wsman',
                auth=(auth, self.password)
            )
            
            # PowerShell script to check session isolation
            ps_script = """
            # Check session isolation settings
            $isolation = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "fInheritAutoLogon" -ErrorAction SilentlyContinue
            if ($isolation -ne $null) {
                Write-Output "fInheritAutoLogon: $($isolation.fInheritAutoLogon)"
            } else {
                Write-Output "fInheritAutoLogon: Not configured"
            }
            
            # Check PerSessionTempDir
            $tempDir = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "PerSessionTempDir" -ErrorAction SilentlyContinue
            if ($tempDir -ne $null) {
                Write-Output "PerSessionTempDir: $($tempDir.PerSessionTempDir)"
            } else {
                Write-Output "PerSessionTempDir: Not configured"
            }
            
            # Check DeleteTempDirsOnExit
            $deleteTempDirs = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "DeleteTempDirsOnExit" -ErrorAction SilentlyContinue
            if ($deleteTempDirs -ne $null) {
                Write-Output "DeleteTempDirsOnExit: $($deleteTempDirs.DeleteTempDirsOnExit)"
            } else {
                Write-Output "DeleteTempDirsOnExit: Not configured"
            }
            
            # Check session timeout settings
            $idleTimeout = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MaxIdleTime" -ErrorAction SilentlyContinue
            if ($idleTimeout -ne $null) {
                Write-Output "MaxIdleTime: $($idleTimeout.MaxIdleTime)"
            } else {
                Write-Output "MaxIdleTime: Not configured"
            }
            
            # Check disconnection timeout
            $disconnectTimeout = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MaxDisconnectionTime" -ErrorAction SilentlyContinue
            if ($disconnectTimeout -ne $null) {
                Write-Output "MaxDisconnectionTime: $($disconnectTimeout.MaxDisconnectionTime)"
            } else {
                Write-Output "MaxDisconnectionTime: Not configured"
            }
            
            # Check if sessions share resources inappropriately
            $sessionSharing = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "TSAppCompat" -ErrorAction SilentlyContinue
            if ($sessionSharing -ne $null) {
                Write-Output "TSAppCompat: $($sessionSharing.TSAppCompat)"
            } else {
                Write-Output "TSAppCompat: Not configured"
            }
            """
            
            result_data = session.run_ps(ps_script)
            output = result_data.std_out.decode('utf-8', errors='ignore')
            
            # Process the output
            inherit_autologon = None
            per_session_temp = None
            delete_temp_dirs = None
            max_idle_time = None
            max_disconnect_time = None
            ts_app_compat = None
            
            issues = []
            
            for line in output.splitlines():
                line = line.strip()
                result['findings'].append(line)
                
                if line.startswith("fInheritAutoLogon:"):
                    try:
                        inherit_autologon = int(line.split(":")[1].strip())
                    except (ValueError, IndexError):
                        pass
                        
                if line.startswith("PerSessionTempDir:"):
                    try:
                        per_session_temp = int(line.split(":")[1].strip())
                    except (ValueError, IndexError):
                        pass
                        
                if line.startswith("DeleteTempDirsOnExit:"):
                    try:
                        delete_temp_dirs = int(line.split(":")[1].strip())
                    except (ValueError, IndexError):
                        pass
                        
                if line.startswith("MaxIdleTime:"):
                    try:
                        max_idle_time = int(line.split(":")[1].strip())
                    except (ValueError, IndexError):
                        pass
                        
                if line.startswith("MaxDisconnectionTime:"):
                    try:
                        max_disconnect_time = int(line.split(":")[1].strip())
                    except (ValueError, IndexError):
                        pass
                        
                if line.startswith("TSAppCompat:"):
                    try:
                        ts_app_compat = int(line.split(":")[1].strip())
                    except (ValueError, IndexError):
                        pass
            
            # Evaluate security based on values
            # fInheritAutoLogon: 0=Don't inherit (more secure), 1=Inherit
            if inherit_autologon == 1:
                issues.append("Sessions inherit auto-logon settings - potential session mixing")
                
            # PerSessionTempDir: 0=Shared temp dirs, 1=Per-session temp dirs (more secure)
            if per_session_temp == 0:
                issues.append("Sessions share temporary directories - data leakage risk")
            elif per_session_temp == 1:
                result['findings'].append("Per-session temporary directories are enabled")
                
            # DeleteTempDirsOnExit: 0=Don't delete, 1=Delete (more secure)
            if delete_temp_dirs == 0:
                issues.append("Temporary directories not cleaned on session exit")
            elif delete_temp_dirs == 1:
                result['findings'].append("Temporary directories are cleaned on session exit")
                
            # Check for reasonable timeout values (convert from milliseconds)
            if max_idle_time and max_idle_time == 0:
                issues.append("No idle timeout configured - sessions may remain active indefinitely")
            elif max_idle_time and max_idle_time > 0:
                idle_minutes = max_idle_time // (1000 * 60)
                result['findings'].append(f"Idle timeout set to {idle_minutes} minutes")
                if idle_minutes > 120:  # More than 2 hours
                    issues.append(f"Idle timeout too long ({idle_minutes} minutes) - increases hijack window")
                    
            if max_disconnect_time and max_disconnect_time == 0:
                issues.append("No disconnection timeout - disconnected sessions persist indefinitely")
            elif max_disconnect_time and max_disconnect_time > 0:
                disconnect_minutes = max_disconnect_time // (1000 * 60)
                result['findings'].append(f"Disconnection timeout set to {disconnect_minutes} minutes")
                if disconnect_minutes > 240:  # More than 4 hours
                    issues.append(f"Disconnection timeout too long ({disconnect_minutes} minutes)")
            
            # Determine overall status
            if not issues:
                result['status'] = 'passed'
                result['vulnerable'] = False
                result['findings'].append("Session isolation appears properly configured")
                self.results['findings'].append("RDP session isolation is configured securely")
            else:
                result['status'] = 'failed'
                result['vulnerable'] = True
                for issue in issues:
                    result['findings'].append(issue)
                    self.results['findings'].append(f"Session isolation issue: {issue}")
                
                # Add recommendations
                self.results['recommendations'].append("Enable per-session temporary directories")
                self.results['recommendations'].append("Configure appropriate session timeouts")
                self.results['recommendations'].append("Enable automatic cleanup of session resources")
                
        except Exception as e:
            logger.error(f"Error testing session isolation: {e}")
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
            self.results['vulnerable_to_hijacking'] = True
            
        # Store test results
        self.results['tests']['session_isolation'] = result
        return result
        
    def test_multiuser_session_controls(self) -> Dict[str, Any]:
        """Test multi-user session control mechanisms
        
        Returns:
            Dict: Test results
        """
        logger.info(f"Testing multi-user session controls on {self.target}")
        
        result = {
            'test': 'multiuser_session_controls',
            'description': 'Checks controls that prevent unauthorized session access or takeover',
            'status': 'unknown',
            'findings': [],
            'vulnerable': True  # Default to vulnerable
        }
        
        # Skip if WinRM is not available
        if not self.supports_winrm or not self.username or not self.password:
            result['status'] = 'skipped'
            result['findings'].append("Skipped test - requires WinRM and credentials")
            self.results['tests']['multiuser_session_controls'] = result
            return result
        
        try:
            import winrm
            
            # Create WinRM session
            auth = f"{self.domain}\\{self.username}" if self.domain else self.username
            session = winrm.Session(
                f'http://{self.target}:5985/wsman',
                auth=(auth, self.password)
            )
            
            # PowerShell script to check multi-user session controls
            ps_script = """
            # Check if multiple users can connect simultaneously
            $maxConnections = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MaxInstanceCount" -ErrorAction SilentlyContinue
            if ($maxConnections -ne $null) {
                Write-Output "MaxInstanceCount: $($maxConnections.MaxInstanceCount)"
            } else {
                Write-Output "MaxInstanceCount: Not configured"
            }
            
            # Check single session per user setting
            $singleSession = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fSingleSessionPerUser" -ErrorAction SilentlyContinue
            if ($singleSession -ne $null) {
                Write-Output "fSingleSessionPerUser: $($singleSession.fSingleSessionPerUser)"
            } else {
                Write-Output "fSingleSessionPerUser: Not configured"
            }
            
            # Check if console session is restricted
            $consoleSession = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "TSEnabled" -ErrorAction SilentlyContinue
            if ($consoleSession -ne $null) {
                Write-Output "TSEnabled: $($consoleSession.TSEnabled)"
            } else {
                Write-Output "TSEnabled: Not configured"
            }
            
            # Check RDP-TCP session settings for security
            $sessionSecurity = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "fLogonDisabled" -ErrorAction SilentlyContinue
            if ($sessionSecurity -ne $null) {
                Write-Output "fLogonDisabled: $($sessionSecurity.fLogonDisabled)"
            } else {
                Write-Output "fLogonDisabled: Not configured"
            }
            
            # Check session shadowing permissions
            $shadowPermissions = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "Shadow" -ErrorAction SilentlyContinue
            if ($shadowPermissions -ne $null) {
                Write-Output "Shadow: $($shadowPermissions.Shadow)"
            } else {
                Write-Output "Shadow: Not configured"
            }
            
            # Check user rights assignment for RDP
            try {
                $rdpUsers = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue
                if ($rdpUsers) {
                    Write-Output "RemoteDesktopUsers: Found"
                    $rdpUsers | ForEach-Object { Write-Output "RDPUser: $($_.Name)" }
                } else {
                    Write-Output "RemoteDesktopUsers: None found"
                }
            } catch {
                Write-Output "RemoteDesktopUsers: Could not query"
            }
            
            # Check current session information
            try {
                $currentSessions = query session 2>$null
                if ($currentSessions) {
                    Write-Output "QuerySession: Success"
                    $currentSessions | ForEach-Object { Write-Output "SessionInfo: $_" }
                } else {
                    Write-Output "QuerySession: No sessions or access denied"
                }
            } catch {
                Write-Output "QuerySession: Error"
            }
            """
            
            result_data = session.run_ps(ps_script)
            output = result_data.std_out.decode('utf-8', errors='ignore')
            
            # Process the output
            max_connections = None
            single_session_per_user = None
            ts_enabled = None
            logon_disabled = None
            shadow_permissions = None
            rdp_users_found = False
            active_sessions_found = False
            
            issues = []
            
            for line in output.splitlines():
                line = line.strip()
                result['findings'].append(line)
                
                if line.startswith("MaxInstanceCount:"):
                    try:
                        max_connections = int(line.split(":")[1].strip())
                    except (ValueError, IndexError):
                        pass
                        
                if line.startswith("fSingleSessionPerUser:"):
                    try:
                        single_session_per_user = int(line.split(":")[1].strip())
                    except (ValueError, IndexError):
                        pass
                        
                if line.startswith("TSEnabled:"):
                    try:
                        ts_enabled = int(line.split(":")[1].strip())
                    except (ValueError, IndexError):
                        pass
                        
                if line.startswith("fLogonDisabled:"):
                    try:
                        logon_disabled = int(line.split(":")[1].strip())
                    except (ValueError, IndexError):
                        pass
                        
                if line.startswith("Shadow:"):
                    try:
                        shadow_permissions = int(line.split(":")[1].strip())
                    except (ValueError, IndexError):
                        pass
                        
                if line.startswith("RemoteDesktopUsers: Found") or line.startswith("RDPUser:"):
                    rdp_users_found = True
                    
                if line.startswith("QuerySession: Success") or line.startswith("SessionInfo:"):
                    active_sessions_found = True
            
            # Evaluate security based on values
            # MaxInstanceCount: Unlimited (-1) vs limited connections
            if max_connections == -1:
                issues.append("Unlimited RDP connections allowed - increases attack surface")
            elif max_connections and max_connections > 5:
                issues.append(f"High number of simultaneous connections allowed ({max_connections})")
            elif max_connections and max_connections > 0:
                result['findings'].append(f"Connection limit set to {max_connections}")
                
            # fSingleSessionPerUser: 0=Multiple sessions per user, 1=Single session per user (more secure)
            if single_session_per_user == 0:
                issues.append("Multiple sessions per user allowed - potential for session confusion/hijacking")
            elif single_session_per_user == 1:
                result['findings'].append("Single session per user enforced")
                
            # Shadow permissions: 0=No control, 1=Full control, 2=View only, 3=No shadow, 4=Full with user consent
            if shadow_permissions in [0, 1]:
                issues.append("Session shadowing allows control without user consent")
            elif shadow_permissions == 2:
                result['findings'].append("Session shadowing limited to view-only")
            elif shadow_permissions == 3:
                result['findings'].append("Session shadowing disabled")
            elif shadow_permissions == 4:
                result['findings'].append("Session shadowing requires user consent")
                
            if rdp_users_found:
                result['findings'].append("Remote Desktop Users group has members")
                
            if active_sessions_found:
                result['findings'].append("Active RDP sessions detected")
                self.results['findings'].append("Active sessions present - monitor for unauthorized access")
            
            # Determine overall status
            if not issues:
                result['status'] = 'passed'
                result['vulnerable'] = False
                result['findings'].append("Multi-user session controls are properly configured")
                self.results['findings'].append("Multi-user RDP session controls are secure")
            else:
                result['status'] = 'failed'
                result['vulnerable'] = True
                for issue in issues:
                    result['findings'].append(issue)
                    self.results['findings'].append(f"Multi-user control issue: {issue}")
                
                # Add recommendations
                self.results['recommendations'].append("Limit maximum simultaneous RDP connections")
                self.results['recommendations'].append("Enforce single session per user")
                self.results['recommendations'].append("Configure session shadowing with user consent")
                self.results['recommendations'].append("Regularly audit Remote Desktop Users group membership")
                
        except Exception as e:
            logger.error(f"Error testing multi-user session controls: {e}")
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
            self.results['vulnerable_to_hijacking'] = True
            
        # Store test results
        self.results['tests']['multiuser_session_controls'] = result
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
        recommendations = []
        
        # Add general recommendations
        recommendations.extend([
            "Enable Network Level Authentication (NLA) for all RDP connections.",
            "Implement session isolation to prevent session hijacking.",
            "Configure Group Policy to restrict console session access.",
            "Enable Restricted Admin mode for Remote Desktop.",
            "Regularly update and patch all systems to the latest security updates.",
            "Implement account lockout policies to prevent brute force attacks.",
            "Use strong passwords and consider multi-factor authentication.",
            "Monitor RDP logs for suspicious activity."
        ])
        
        # Add specific recommendations based on test results
        for test_name, test_result in self.results.get('tests', {}).items():
            if test_result.get('vulnerable', False):
                if 'console' in test_name.lower():
                    recommendations.append(
                        "Restrict console session access to administrators only."
                    )
                elif 'isolation' in test_name.lower():
                    recommendations.append(
                        "Enable session isolation to prevent session hijacking between users."
                    )
                elif 'multiuser' in test_name.lower():
                    recommendations.append(
                        "Review and restrict multi-user session settings to prevent unauthorized access."
                    )
        
        # Remove duplicates while preserving order
        self.results['recommendations'] = list(dict.fromkeys(recommendations))
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all session hijack tests with comprehensive error handling
        
        Returns:
            Dict: Comprehensive test results
        """
        logger.info(f"Running all RDP session hijack tests against {self.target}:{self.port}")
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
            self._run_test_safely(self.test_console_session_protection, 'console_session_protection')
            self._run_test_safely(self.test_session_isolation, 'session_isolation')
            self._run_test_safely(self.test_multiuser_session_controls, 'multiuser_session_controls')
            
            # Update overall vulnerability status
            self.results['vulnerable_to_hijacking'] = any(
                test.get('vulnerable', False)
                for test in self.results.get('tests', {}).values()
            )
            
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
            status = 'VULNERABLE' if self.results['vulnerable_to_hijacking'] else 'SECURE'
            logger.info(
                f"Completed RDP session hijack tests. Status: {status}. "
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
    
    def _compile_findings(self) -> List[str]:
        """Compile findings from all tests into a single list
        
        Returns:
            List[str]: List of findings
        """
        findings = []
        
        # Add findings from each test
        for test_name, test_result in self.results.get('tests', {}).items():
            if test_result.get('findings'):
                findings.extend(test_result['findings'])
        
        # Add overall status
        if self.results.get('vulnerable_to_hijacking', False):
            findings.insert(0, "System is VULNERABLE to RDP session hijacking attacks")
        else:
            findings.insert(0, "No critical session hijacking vulnerabilities detected")
        
        return findings
    
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
        print(" RDP Session Hijack Test Report")
        print(f" Target: {self.target}:{self.port}")
        print(f" Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*80 + "\n")
        
        summary = self.results['summary']
        vulnerable = self.results.get('vulnerable_to_hijacking', False)
        
        print(f"Session Hijack Vulnerability: {'✗ VULNERABLE' if vulnerable else '✓ SECURE'}")
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
        description='RDP Session Hijack Tester',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python rdp_session_hijack_tester.py 192.168.1.100
  python rdp_session_hijack_tester.py server.example.com -u admin -p password
  python rdp_session_hijack_tester.py 192.168.1.100 -u domain\\user -p password -o report.json
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
    """Main function to run the RDP session hijack tests"""
    # Parse arguments
    args = parse_args()
    
    # Set up logging verbosity
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Banner
    print("="*80)
    print(" RDP Session Hijack Tester")
    print(f" Target: {args.target}:{args.port}")
    print("="*80)
    print()
    
    try:
        # Initialize tester
        tester = RDPSessionHijackTester(
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
            output_file = f"rdp_session_hijack_{args.target}_{timestamp}.json"
            
        tester.generate_report(output_file)
        tester.results['report_file'] = output_file
        
        # Print summary
        tester.print_report_summary()
        
        # Return status code based on vulnerability
        return 1 if results.get('vulnerable_to_hijacking', False) else 0
    
    except KeyboardInterrupt:
        logger.warning("Testing interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Error running session hijack tests: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
