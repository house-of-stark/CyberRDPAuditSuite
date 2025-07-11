"""
CyberRDP Audit Suite - RDP Port Scanner

This module contains a scanner that checks for open RDP ports and gathers
basic service information.
"""

import socket
import ssl
from typing import Dict, Any, Optional

from .base_scanner import BaseScanner

class PortScanner(BaseScanner):
    """Scanner that checks for open RDP ports and gathers service information."""
    
    name = "RDP Port Scanner"
    description = "Checks for open RDP ports and gathers service information"
    
    async def run(self) -> Dict[str, Any]:
        """Run the port scan and service detection."""
        result = self.get_base_result()
        result['status'] = 'PASSED'
        result['details'] = {
            'port_status': 'closed',
            'service_info': {}
        }
        
        try:
            # Check if port is open
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)  # 5 second timeout
            
            port_status = sock.connect_ex((self.target, self.port))
            
            if port_status != 0:
                result['details']['port_status'] = 'closed'
                result['status'] = 'FAILED'
                self.add_vulnerability(
                    name="RDP Port Closed",
                    description=f"RDP port {self.port} is not open on {self.target}",
                    severity=self.SEVERITY_INFO
                )
                return result
            
            # Port is open, try to get service info
            result['details']['port_status'] = 'open'
            
            # Try to get SSL certificate info if using TLS
            try:
                context = ssl.create_default_context()
                with socket.create_connection((self.target, self.port)) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        cert = ssock.getpeercert()
                        
                        # Extract certificate info
                        cert_info = {
                            'subject': dict(x[0] for x in cert.get('subject', [])),
                            'issuer': dict(x[0] for x in cert.get('issuer', [])),
                            'version': cert.get('version'),
                            'not_before': cert.get('notBefore'),
                            'not_after': cert.get('notAfter'),
                            'serial_number': cert.get('serialNumber'),
                        }
                        
                        result['details']['service_info'] = {
                            'encryption': 'TLS',
                            'protocol': 'RDP over TLS',
                            'certificate': cert_info
                        }
                        
                        # Check certificate expiration
                        self._check_certificate_expiration(cert_info)
                        
            except ssl.SSLError as e:
                # Not using TLS, might be using legacy RDP encryption
                result['details']['service_info'] = {
                    'encryption': 'Legacy',
                    'protocol': 'RDP (legacy encryption)',
                    'error': str(e)
                }
                
                self.add_vulnerability(
                    name="Legacy RDP Encryption",
                    description="RDP server is using legacy encryption",
                    severity=self.SEVERITY_HIGH,
                    remediation="Upgrade to RDP with TLS/SSL encryption"
                )
            
            except Exception as e:
                result['details']['service_info']['error'] = str(e)
                self.log_error(f"Error getting service info: {e}")
            
            self.log_info(f"Port {self.port} is open on {self.target}")
            
        except Exception as e:
            result['status'] = 'ERROR'
            result['details']['error'] = str(e)
            self.log_error(f"Error during port scan: {e}")
        
        return result
    
    def _check_certificate_expiration(self, cert_info: Dict[str, Any]) -> None:
        """Check certificate expiration and add vulnerability if expired or near expiry."""
        from datetime import datetime
        
        try:
            not_after = cert_info.get('not_after')
            if not not_after:
                return
                
            # Parse the date string (format: 'May 25 23:59:59 2023 GMT')
            expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
            days_until_expiry = (expiry_date - datetime.utcnow()).days
            
            if days_until_expiry < 0:
                self.add_vulnerability(
                    name="Expired SSL Certificate",
                    description=f"The SSL certificate expired on {not_after}",
                    severity=self.SEVERITY_HIGH,
                    remediation="Renew the SSL certificate"
                )
            elif days_until_expiry < 30:  # Less than 30 days until expiry
                self.add_vulnerability(
                    name="SSL Certificate Expiring Soon",
                    description=f"The SSL certificate will expire in {days_until_expiry} days on {not_after}",
                    severity=self.SEVERITY_MEDIUM,
                    remediation="Renew the SSL certificate"
                )
                
        except Exception as e:
            self.log_error(f"Error checking certificate expiration: {e}")
