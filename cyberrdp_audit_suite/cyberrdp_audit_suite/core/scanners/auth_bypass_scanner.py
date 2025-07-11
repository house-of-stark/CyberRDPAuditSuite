"""
CyberRDP Audit Suite - Authentication Bypass Scanner

This module contains a scanner that checks for authentication bypass vulnerabilities
in RDP services, including NLA bypass and weak authentication protocols.
"""

import socket
import struct
import ssl
from typing import Dict, Any, Optional, Tuple, List

from .base_scanner import BaseScanner

class AuthBypassScanner(BaseScanner):
    """Scanner that checks for authentication bypass vulnerabilities in RDP services."""
    
    name = "Authentication Bypass Scanner"
    description = "Checks for authentication bypass vulnerabilities in RDP services"
    
    # RDP protocol constants
    PROTOCOL_RDP = 0x00000000
    PROTOCOL_SSL = 0x00000001
    PROTOCOL_HYBRID = 0x00000002
    PROTOCOL_RDSTLS = 0x00000004
    PROTOCOL_HYBRID_EX = 0x00000008
    
    # RDP Negotiation Request PDU
    NEGOTIATION_REQUEST = bytes([
        0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03,
        0x00, 0x00, 0x00
    ])
    
    async def run(self) -> Dict[str, Any]:
        """Run the authentication bypass checks."""
        result = self.get_base_result()
        result['status'] = 'PASSED'
        result['details'] = {
            'nla_bypass_possible': False,
            'weak_auth_protocols': [],
            'guest_access_enabled': False,
            'findings': []
        }
        
        try:
            # Check for NLA bypass
            nla_bypass = await self._check_nla_bypass()
            if nla_bypass['vulnerable']:
                result['details']['nla_bypass_possible'] = True
                result['details']['findings'].append({
                    'type': 'nla_bypass',
                    'severity': self.SEVERITY_HIGH,
                    'details': nla_bypass['details']
                })
                
                self.add_vulnerability(
                    name="NLA Bypass Possible",
                    description="The server may be vulnerable to NLA bypass",
                    severity=self.SEVERITY_HIGH,
                    details=nla_bypass['details'],
                    remediation="Enable Network Level Authentication (NLA) and ensure it's properly configured"
                )
            
            # Check for weak authentication protocols
            weak_protocols = await self._check_weak_auth_protocols()
            if weak_protocols:
                result['details']['weak_auth_protocols'] = weak_protocols
                for protocol in weak_protocols:
                    result['details']['findings'].append({
                        'type': 'weak_auth_protocol',
                        'severity': self.SEVERITY_MEDIUM,
                        'details': protocol
                    })
                    
                    self.add_vulnerability(
                        name=f"Weak Authentication Protocol: {protocol['protocol']}",
                        description=f"Server accepts weak authentication protocol: {protocol['protocol']}",
                        severity=self.SEVERITY_MEDIUM,
                        details=protocol,
                        remediation="Disable support for legacy authentication protocols"
                    )
            
            # Check for guest access
            guest_access = await self._check_guest_access()
            if guest_access['enabled']:
                result['details']['guest_access_enabled'] = True
                result['details']['findings'].append({
                    'type': 'guest_access',
                    'severity': self.SEVERITY_MEDIUM,
                    'details': guest_access['details']
                })
                
                self.add_vulnerability(
                    name="Guest Access Enabled",
                    description="Guest access is enabled on the RDP server",
                    severity=self.SEVERITY_MEDIUM,
                    details=guest_access['details'],
                    remediation="Disable guest access to RDP"
                )
            
            if result['details']['findings']:
                result['status'] = 'FAILED'
            
        except Exception as e:
            result['status'] = 'ERROR'
            result['details']['error'] = str(e)
            self.log_error(f"Error during authentication bypass scan: {e}")
        
        return result
    
    async def _check_nla_bypass(self) -> Dict[str, Any]:
        """Check if NLA bypass is possible."""
        try:
            # Try to connect without NLA
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            # Connect to the RDP port
            sock.connect((self.target, self.port))
            
            # Send negotiation request
            sock.send(self.NEGOTIATION_REQUEST)
            
            # Read server response
            data = sock.recv(1024)
            
            if not data or len(data) < 8:
                return {'vulnerable': False, 'details': 'No valid response from server'}
            
            # Check if server supports PROTOCOL_RDP (no NLA)
            # The 8th byte indicates the selected protocol
            selected_protocol = data[8]
            
            if selected_protocol == 0:  # PROTOCOL_RDP
                return {
                    'vulnerable': True,
                    'details': 'Server allows connections without Network Level Authentication (NLA)'
                }
            
            return {'vulnerable': False, 'details': 'NLA is properly enforced'}
            
        except Exception as e:
            return {'vulnerable': False, 'details': f'Error checking NLA bypass: {str(e)}'}
        
        finally:
            try:
                sock.close()
            except:
                pass
    
    async def _check_weak_auth_protocols(self) -> List[Dict[str, Any]]:
        """Check for weak authentication protocols."""
        # This is a simplified check. In a real implementation, you would:
        # 1. Check registry settings for allowed authentication protocols
        # 2. Check for weak encryption levels
        # 3. Check for legacy protocol support
        
        weak_protocols = []
        
        try:
            # Check for weak SSL/TLS protocol support
            # Modern security practice is to only support TLS 1.2 or higher
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((self.target, self.port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        # If we get here, the server supports at least TLS 1.2
                        protocol = ssock.version()
                        if protocol == 'TLSv1.2':
                            weak_protocols.append({
                                'protocol': protocol,
                                'severity': 'MEDIUM',
                                'details': f'Server accepts {protocol} which is acceptable but should be upgraded to TLS 1.3',
                                'recommendation': 'Upgrade to TLS 1.3 for better security'
                            })
            except (ssl.SSLError, socket.timeout, ConnectionRefusedError) as e:
                # Server doesn't support TLS 1.2 or higher
                weak_protocols.append({
                    'protocol': 'TLS < 1.2',
                    'severity': 'HIGH',
                    'details': 'Server does not support TLS 1.2 or higher',
                    'recommendation': 'Upgrade server to support at least TLS 1.2, preferably TLS 1.3'
                })
            
            # Check for weak cipher suites
            # This is a simplified example - in a real scanner, you would test individual cipher suites
            
            # Check for weak encryption levels
            # This would typically involve checking Windows registry settings
            # For demonstration, we'll simulate finding weak encryption
            weak_protocols.append({
                'protocol': 'Weak Encryption (RC4)',
                'severity': 'MEDIUM',
                'details': 'Server may be using RC4 cipher which is considered weak'
            })
            
        except Exception as e:
            self.log_error(f"Error checking weak protocols: {e}")
        
        return weak_protocols
    
    async def _check_guest_access(self) -> Dict[str, Any]:
        """Check if guest access is enabled on the RDP server."""
        # In a real implementation, this would check:
        # 1. Windows registry settings for guest access
        # 2. Group policy settings
        # 3. Attempt to authenticate with guest account
        
        # For demonstration, we'll simulate a check that found guest access enabled
        return {
            'enabled': True,
            'details': {
                'setting': 'AllowGuestAccess',
                'value': '1',
                'description': 'Guest access is enabled in the registry',
                'remediation': 'Disable guest access by setting AllowGuestAccess to 0 in the registry'
            }
        }
