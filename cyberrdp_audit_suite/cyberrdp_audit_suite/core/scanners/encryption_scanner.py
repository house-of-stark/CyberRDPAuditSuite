"""
CyberRDP Audit Suite - Encryption Level Scanner

This module contains a scanner that checks for weak encryption settings
in RDP services, including protocol versions and cipher suites.
"""

import socket
import ssl
from typing import Dict, Any, List, Optional, Tuple

from .base_scanner import BaseScanner

class EncryptionScanner(BaseScanner):
    """Scanner that checks for weak encryption settings in RDP services."""
    
    name = "Encryption Level Scanner"
    description = "Checks for weak encryption settings in RDP services"
    
    # Encryption level constants
    ENCRYPTION_LOW = 1
    ENCRYPTION_CLIENT_COMPATIBLE = 2
    ENCRYPTION_HIGH = 3
    ENCRYPTION_FIPS = 4
    
    # Known weak cipher suites
    WEAK_CIPHERS = [
        'RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'MD5', 'RC2', 'PSK',
        'CAMELLIA', 'SEED', 'IDEA', 'CBC', 'CBC3', 'AES-128', 'AES-256'
    ]
    
    # Known strong cipher suites
    STRONG_CIPHERS = [
        'AES-256-GCM', 'AES-128-GCM', 'CHACHA20-POLY1305', 'ECDHE', 'DHE',
        'TLS_AES_256_GCM_SHA384', 'TLS_AES_128_GCM_SHA256'
    ]
    
    async def run(self) -> Dict[str, Any]:
        """Run the encryption level checks."""
        result = self.get_base_result()
        result['status'] = 'PASSED'
        result['details'] = {
            'encryption_level': 'UNKNOWN',
            'protocol_versions': [],
            'cipher_suites': [],
            'findings': []
        }
        
        try:
            # Check SSL/TLS protocol versions
            protocol_versions = await self._check_protocol_versions()
            result['details']['protocol_versions'] = protocol_versions
            
            # Check for weak protocols
            weak_protocols = [p for p in protocol_versions if p.get('secure') is False]
            if weak_protocols:
                for proto in weak_protocols:
                    result['details']['findings'].append({
                        'type': 'weak_protocol',
                        'severity': self.SEVERITY_HIGH,
                        'details': proto
                    })
                    
                    self.add_vulnerability(
                        name=f"Weak Protocol: {proto['protocol']}",
                        description=f"Server accepts weak protocol version: {proto['protocol']}",
                        severity=self.SEVERITY_HIGH,
                        details=proto,
                        remediation=f"Disable {proto['protocol']} and use only TLS 1.2 or higher"
                    )
            
            # Check cipher suites
            cipher_suites = await self._check_cipher_suites()
            result['details']['cipher_suites'] = cipher_suites
            
            # Check for weak ciphers
            weak_ciphers = [c for c in cipher_suites if c.get('secure') is False]
            if weak_ciphers:
                for cipher in weak_ciphers:
                    result['details']['findings'].append({
                        'type': 'weak_cipher',
                        'severity': self.SEVERITY_MEDIUM,
                        'details': cipher
                    })
                    
                    self.add_vulnerability(
                        name=f"Weak Cipher: {cipher['cipher']}",
                        description=f"Server accepts weak cipher: {cipher['cipher']}",
                        severity=self.SEVERITY_MEDIUM,
                        details=cipher,
                        remediation=f"Disable weak cipher: {cipher['cipher']}"
                    )
            
            # Determine overall encryption level
            if any(p.get('protocol') == 'SSL 2.0' or p.get('protocol') == 'SSL 3.0' for p in protocol_versions):
                result['details']['encryption_level'] = 'LOW'
            elif any(p.get('protocol') == 'TLS 1.0' or p.get('protocol') == 'TLS 1.1' for p in protocol_versions):
                result['details']['encryption_level'] = 'MEDIUM'
            elif any(c.get('secure') is False for c in cipher_suites):
                result['details']['encryption_level'] = 'HIGH'
            else:
                result['details']['encryption_level'] = 'FIPS'
            
            if result['details']['findings']:
                result['status'] = 'FAILED'
            
        except Exception as e:
            result['status'] = 'ERROR'
            result['details']['error'] = str(e)
            self.log_error(f"Error during encryption level scan: {e}")
        
        return result
    
    async def _check_protocol_versions(self) -> List[Dict[str, Any]]:
        """Check which SSL/TLS protocol versions are supported."""
        protocols = [
            ('SSL 2.0', ssl.PROTOCOL_SSLv2, False),
            ('SSL 3.0', ssl.PROTOCOL_SSLv3, False),
            ('TLS 1.0', ssl.PROTOCOL_TLSv1, False),
            ('TLS 1.1', ssl.PROTOCOL_TLSv1_1, False),
            ('TLS 1.2', ssl.PROTOCOL_TLSv1_2, True),
            ('TLS 1.3', ssl.PROTOCOL_TLS, True)  # PROTOCOL_TLS selects highest available
        ]
        
        results = []
        
        for name, proto, secure in protocols:
            try:
                # Skip protocols that might not be available
                if not hasattr(ssl, f'PROTOCOL_{name.replace(" ", "").upper()}'):
                    continue
                    
                context = ssl.SSLContext(proto)
                context.verify_mode = ssl.CERT_NONE
                context.check_hostname = False
                
                with socket.create_connection((self.target, self.port)) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        # If we get here, the protocol is supported
                        results.append({
                            'protocol': name,
                            'supported': True,
                            'secure': secure,
                            'selected_protocol': ssock.version()
                        })
            except (ssl.SSLError, socket.error, ConnectionRefusedError) as e:
                # Protocol not supported or connection failed
                results.append({
                    'protocol': name,
                    'supported': False,
                    'secure': secure,
                    'error': str(e)
                })
            except Exception as e:
                self.log_error(f"Error checking protocol {name}: {e}")
                results.append({
                    'protocol': name,
                    'supported': False,
                    'secure': secure,
                    'error': f'Unexpected error: {str(e)}'
                })
        
        return results
    
    async def _check_cipher_suites(self) -> List[Dict[str, Any]]:
        """Check which cipher suites are supported."""
        # This is a simplified check. In a real implementation, you would:
        # 1. Test individual cipher suites
        # 2. Check for weak key exchange algorithms
        # 3. Check for weak MAC algorithms
        
        # For demonstration, we'll check a few common cipher suites
        test_ciphers = [
            ('TLS_RSA_WITH_RC4_128_SHA', False),  # Weak
            ('TLS_RSA_WITH_3DES_EDE_CBC_SHA', False),  # Weak
            ('TLS_RSA_WITH_AES_128_CBC_SHA', False),  # Medium
            ('TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', True),  # Strong
            ('TLS_AES_256_GCM_SHA384', True),  # TLS 1.3
        ]
        
        results = []
        
        for cipher, is_secure in test_ciphers:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.set_ciphers(cipher)
                context.verify_mode = ssl.CERT_NONE
                context.check_hostname = False
                
                with socket.create_connection((self.target, self.port)) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        # If we get here, the cipher is supported
                        results.append({
                            'cipher': cipher,
                            'supported': True,
                            'secure': is_secure,
                            'selected_cipher': ssock.cipher()
                        })
            except ssl.SSLError as e:
                # Cipher not supported
                results.append({
                    'cipher': cipher,
                    'supported': False,
                    'secure': is_secure,
                    'error': str(e)
                })
            except Exception as e:
                self.log_error(f"Error checking cipher {cipher}: {e}")
                results.append({
                    'cipher': cipher,
                    'supported': False,
                    'secure': is_secure,
                    'error': f'Unexpected error: {str(e)}'
                })
        
        return results
    
    def _is_weak_cipher(self, cipher_name: str) -> bool:
        """Check if a cipher name indicates a weak cipher."""
        if not cipher_name:
            return False
            
        cipher_upper = cipher_name.upper()
        return any(weak in cipher_upper for weak in self.WEAK_CIPHERS)
