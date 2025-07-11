"""
CyberRDP Audit Suite - RDP Security Layer Scanner

This module contains a scanner that checks the RDP security layer configuration,
including security protocols and encryption methods.
"""

import socket
import struct
import ssl
from typing import Dict, Any, List, Optional, Tuple

from .base_scanner import BaseScanner

class RDPSecurityScanner(BaseScanner):
    """Scanner that checks RDP security layer configuration."""
    
    name = "RDP Security Layer Scanner"
    description = "Checks RDP security layer configuration and protocols"
    
    # RDP Security Layer constants
    SECURITY_LAYER_NONE = 0x00
    SECURITY_LAYER_SSL = 0x01
    SECURITY_LAYER_RDP = 0x02
    SECURITY_LAYER_NEGO = 0x08
    
    # RDP Negotiation Request PDU
    NEGOTIATION_REQUEST = bytes([
        0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03,
        0x00, 0x00, 0x00
    ])
    
    async def run(self) -> Dict[str, Any]:
        """Run the RDP security layer checks."""
        result = self.get_base_result()
        result['status'] = 'PASSED'
        result['details'] = {
            'security_layer': 'UNKNOWN',
            'encryption_level': 'UNKNOWN',
            'protocols_supported': [],
            'findings': []
        }
        
        try:
            # Check security layer and encryption level
            security_info = await self._check_security_layer()
            result['details'].update(security_info)
            
            # Check for weak security layer
            if security_info.get('security_layer') == 'RDP':
                result['details']['findings'].append({
                    'type': 'weak_security_layer',
                    'severity': self.SEVERITY_HIGH,
                    'details': {
                        'issue': 'Using legacy RDP security layer',
                        'description': 'Server is using the legacy RDP security layer which is considered insecure',
                        'recommendation': 'Upgrade to TLS security layer'
                    }
                })
                
                self.add_vulnerability(
                    name="Insecure RDP Security Layer",
                    description="Server is using the legacy RDP security layer",
                    severity=self.SEVERITY_HIGH,
                    details=security_info,
                    remediation="Configure the server to use TLS security layer"
                )
            
            # Check for weak encryption level
            if security_info.get('encryption_level') == 'LOW':
                result['details']['findings'].append({
                    'type': 'weak_encryption_level',
                    'severity': self.SEVERITY_HIGH,
                    'details': {
                        'issue': 'Low encryption level detected',
                        'description': 'Server is using weak RDP encryption',
                        'recommendation': 'Configure the server to use High or FIPS encryption level'
                    }
                })
                
                self.add_vulnerability(
                    name="Weak RDP Encryption Level",
                    description="Server is using weak RDP encryption",
                    severity=self.SEVERITY_HIGH,
                    details=security_info,
                    remediation="Configure the server to use High or FIPS encryption level"
                )
            
            # Check supported security protocols
            protocols = await self._check_supported_protocols()
            result['details']['protocols_supported'] = protocols
            
            # Check for weak protocols
            weak_protocols = [p for p in protocols if not p.get('secure', True)]
            if weak_protocols:
                for proto in weak_protocols:
                    result['details']['findings'].append({
                        'type': 'weak_rdp_protocol',
                        'severity': self.SEVERITY_MEDIUM,
                        'details': {
                            'protocol': proto['protocol'],
                            'issue': 'Weak RDP protocol supported',
                            'description': f"Server supports weak RDP protocol: {proto['protocol']}",
                            'recommendation': f'Disable support for {proto["protocol"]} protocol'
                        }
                    })
                    
                    self.add_vulnerability(
                        name=f"Weak RDP Protocol: {proto['protocol']}",
                        description=f"Server supports weak RDP protocol: {proto['protocol']}",
                        severity=self.SEVERITY_MEDIUM,
                        details=proto,
                        remediation=f"Disable support for {proto['protocol']} protocol"
                    )
            
            if result['details']['findings']:
                result['status'] = 'FAILED'
            
        except Exception as e:
            result['status'] = 'ERROR'
            result['details']['error'] = str(e)
            self.log_error(f"Error during RDP security layer scan: {e}")
        
        return result
    
    async def _check_security_layer(self) -> Dict[str, Any]:
        """Check the RDP security layer and encryption level."""
        # In a real implementation, this would check:
        # 1. Windows registry: HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\SecurityLayer
        # 2. Windows registry: HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\MinEncryptionLevel
        
        # For demonstration, we'll simulate a check that found RDP security layer with low encryption
        return {
            'security_layer': 'RDP',  # Can be 'RDP', 'SSL', 'NEGO', or 'NONE'
            'encryption_level': 'LOW',  # Can be 'LOW', 'CLIENT_COMPATIBLE', 'HIGH', or 'FIPS'
            'details': {
                'SecurityLayer': '1',  # 0=Negotiate, 1=RDP, 2=SSL/TLS
                'MinEncryptionLevel': '1',  # 1=Low, 2=Client Compatible, 3=High, 4=FIPS
                'description': 'Server is using legacy RDP security layer with low encryption',
                'recommendation': 'Configure the server to use TLS with High or FIPS encryption level'
            }
        }
    
    async def _check_supported_protocols(self) -> List[Dict[str, Any]]:
        """Check which RDP security protocols are supported."""
        # In a real implementation, this would test different RDP protocol versions
        # and security mechanisms to determine what's supported
        
        # For demonstration, we'll return a list of common protocols with their security status
        return [
            {
                'protocol': 'RDP',
                'version': '5.2',
                'secure': False,
                'description': 'Legacy RDP protocol with weak encryption'
            },
            {
                'protocol': 'TLS',
                'version': '1.2',
                'secure': True,
                'description': 'TLS 1.2 with strong cipher suites'
            },
            {
                'protocol': 'NLA',
                'version': '1.0',
                'secure': True,
                'description': 'Network Level Authentication'
            },
            {
                'protocol': 'CredSSP',
                'version': '1.0',
                'secure': True,
                'description': 'Credential Security Support Provider'
            }
        ]
    
    async def _test_protocol(self, protocol: str) -> Dict[str, Any]:
        """Test if a specific RDP protocol is supported."""
        # This would be implemented to test a specific protocol
        # For demonstration, we'll return a mock result
        return {
            'protocol': protocol,
            'supported': True,
            'secure': protocol.upper() in ['TLS', 'NLA', 'CREDSSP']
        }
