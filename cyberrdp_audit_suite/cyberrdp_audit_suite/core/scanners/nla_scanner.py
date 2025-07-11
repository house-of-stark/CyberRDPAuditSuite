"""
CyberRDP Audit Suite - NLA Configuration Scanner

This module contains a scanner that checks the Network Level Authentication (NLA)
configuration of RDP services to ensure secure authentication settings.
"""

import socket
import struct
from typing import Dict, Any, List, Optional, Tuple

from .base_scanner import BaseScanner

class NLAScanner(BaseScanner):
    """Scanner that checks the Network Level Authentication (NLA) configuration."""
    
    name = "NLA Configuration Scanner"
    description = "Checks Network Level Authentication (NLA) configuration"
    
    # RDP Negotiation Request PDU with NLA disabled
    NEGOTIATION_REQUEST = bytes([
        0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03,
        0x00, 0x00, 0x00
    ])
    
    # RDP Negotiation Request PDU with NLA enabled
    NEGOTIATION_REQUEST_NLA = bytes([
        0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03,
        0x00, 0x00, 0x02  # Notice the last byte is 0x02 for NLA
    ])
    
    async def run(self) -> Dict[str, Any]:
        """Run the NLA configuration checks."""
        result = self.get_base_result()
        result['status'] = 'PASSED'
        result['details'] = {
            'nla_required': True,
            'nla_enforced': True,
            'findings': []
        }
        
        try:
            # Check if NLA is required
            nla_required = await self._check_nla_required()
            result['details']['nla_required'] = nla_required['required']
            
            if not nla_required['required']:
                result['details']['findings'].append({
                    'type': 'nla_not_required',
                    'severity': self.SEVERITY_HIGH,
                    'details': nla_required['details']
                })
                
                self.add_vulnerability(
                    name="NLA Not Required",
                    description="Network Level Authentication (NLA) is not required",
                    severity=self.SEVERITY_HIGH,
                    details=nla_required['details'],
                    remediation="Enable 'Require Network Level Authentication' in RDP settings"
                )
            
            # Check if NLA is properly enforced
            nla_enforced = await self._check_nla_enforced()
            result['details']['nla_enforced'] = nla_enforced['enforced']
            
            if not nla_enforced['enforced']:
                result['details']['findings'].append({
                    'type': 'nla_not_enforced',
                    'severity': self.SEVERITY_HIGH,
                    'details': nla_enforced['details']
                })
                
                self.add_vulnerability(
                    name="NLA Not Enforced",
                    description="Network Level Authentication (NLA) is not properly enforced",
                    severity=self.SEVERITY_HIGH,
                    details=nla_enforced['details'],
                    remediation="Ensure NLA is properly configured and enforced in Group Policy"
                )
            
            # Check for NLA bypass vulnerabilities
            nla_bypass = await self._check_nla_bypass()
            if nla_bypass['vulnerable']:
                result['details']['findings'].append({
                    'type': 'nla_bypass_possible',
                    'severity': self.SEVERITY_CRITICAL,
                    'details': nla_bypass['details']
                })
                
                self.add_vulnerability(
                    name="NLA Bypass Possible",
                    description="Server may be vulnerable to NLA bypass",
                    severity=self.SEVERITY_CRITICAL,
                    details=nla_bypass['details'],
                    remediation="Apply latest security updates and verify NLA configuration"
                )
            
            if result['details']['findings']:
                result['status'] = 'FAILED'
            
        except Exception as e:
            result['status'] = 'ERROR'
            result['details']['error'] = str(e)
            self.log_error(f"Error during NLA configuration scan: {e}")
        
        return result
    
    async def _check_nla_required(self) -> Dict[str, Any]:
        """Check if NLA is required on the server."""
        # In a real implementation, this would check:
        # 1. Windows registry: HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication
        # 2. Group Policy: Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Security -> Require user authentication for remote connections by using Network Level Authentication
        
        # For demonstration, we'll simulate a check that found NLA not required
        return {
            'required': False,
            'details': {
                'setting': 'UserAuthentication',
                'value': '0',
                'description': 'NLA is not required for RDP connections',
                'recommendation': 'Set UserAuthentication to 1 to require NLA'
            }
        }
    
    async def _check_nla_enforced(self) -> Dict[str, Any]:
        """Check if NLA is properly enforced."""
        # In a real implementation, this would verify that NLA settings are properly applied
        # and cannot be bypassed through registry modifications or other means
        
        # For demonstration, we'll simulate a check that found NLA not properly enforced
        return {
            'enforced': False,
            'details': {
                'issue': 'NLA settings can be bypassed',
                'description': 'NLA is not properly enforced due to insecure configuration',
                'recommendation': 'Review and harden NLA configuration in Group Policy'
            }
        }
    
    async def _check_nla_bypass(self) -> Dict[str, Any]:
        """Check if NLA bypass is possible."""
        try:
            # Try to connect with NLA disabled
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            # Connect to the RDP port
            sock.connect((self.target, self.port))
            
            # Send negotiation request without NLA
            sock.send(self.NEGOTIATION_REQUEST)
            
            # Read server response
            data = sock.recv(1024)
            
            if not data or len(data) < 8:
                return {'vulnerable': False, 'details': 'No valid response from server'}
            
            # Check if server accepts connections without NLA
            # The 8th byte indicates the selected protocol
            selected_protocol = data[8]
            
            if selected_protocol == 0:  # PROTOCOL_RDP (no NLA)
                return {
                    'vulnerable': True,
                    'details': 'Server accepts connections without Network Level Authentication (NLA)'
                }
            
            return {'vulnerable': False, 'details': 'NLA is properly enforced'}
            
        except Exception as e:
            return {'vulnerable': False, 'details': f'Error checking NLA bypass: {str(e)}'}
        
        finally:
            try:
                sock.close()
            except:
                pass
