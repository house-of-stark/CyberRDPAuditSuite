"""
RDP Gateway Security Tester

This module tests the security of RDP Gateway implementations.
"""

import logging
import socket
import ssl
import json
from typing import Dict, List, Optional, Tuple
import subprocess
import re
from datetime import datetime

logger = logging.getLogger(__name__)

class RDPGatewayTester:
    """Class to test RDP Gateway security configurations."""
    
    def __init__(self, gateway_address: str, gateway_port: int = 443):
        """Initialize the RDP Gateway tester.
        
        Args:
            gateway_address: IP or hostname of the RDP Gateway
            gateway_port: Port of the RDP Gateway (default: 443)
        """
        self.gateway_address = gateway_address
        self.gateway_port = gateway_port
        self.results = {
            'gateway_address': gateway_address,
            'gateway_port': gateway_port,
            'tests': [],
            'timestamp': datetime.utcnow().isoformat(),
            'findings': []
        }
    
    def test_ssl_configuration(self) -> Dict:
        """Test the SSL/TLS configuration of the RDP Gateway.
        
        Returns:
            Dict containing test results
        """
        test_name = "SSL/TLS Configuration Test"
        result = {
            'test_name': test_name,
            'passed': False,
            'details': {},
            'recommendations': []
        }
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.gateway_address, self.gateway_port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.gateway_address) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate details
                    result['details']['certificate'] = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert.get('version'),
                        'serialNumber': cert.get('serialNumber'),
                        'notBefore': cert.get('notBefore'),
                        'notAfter': cert.get('notAfter'),
                        'subjectAltName': cert.get('subjectAltName', []),
                    }
                    
                    # Check TLS version
                    tls_version = ssock.version()
                    result['details']['tls_version'] = tls_version
                    
                    # Check cipher
                    cipher = ssock.cipher()
                    result['details']['cipher'] = {
                        'name': cipher[0],
                        'protocol': cipher[1],
                        'bits': cipher[2],
                        'description': f"{cipher[0]} {cipher[2]} bits"
                    }
                    
                    # Check for weak protocols
                    weak_protocols = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
                    if any(proto in tls_version for proto in weak_protocols):
                        result['findings'].append({
                            'severity': 'high',
                            'issue': f'Weak protocol version in use: {tls_version}',
                            'recommendation': 'Disable weak protocols and use TLS 1.2 or higher'
                        })
                    
                    # Check for weak ciphers
                    weak_ciphers = ['RC4', 'DES', '3DES', 'CBC', 'MD5', 'SHA1']
                    if any(cipher in cipher[0] for cipher in weak_ciphers):
                        result['findings'].append({
                            'severity': 'high',
                            'issue': f'Weak cipher suite in use: {cipher[0]}',
                            'recommendation': 'Disable weak cipher suites and use strong encryption'
                        })
                    
                    # Check certificate expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.utcnow()).days
                    if days_until_expiry < 30:
                        result['findings'].append({
                            'severity': 'medium',
                            'issue': f'Certificate expires in {days_until_expiry} days',
                            'recommendation': 'Renew the certificate before it expires'
                        })
                    
                    result['passed'] = len(result.get('findings', [])) == 0
                    
        except Exception as e:
            result['error'] = str(e)
            result['findings'].append({
                'severity': 'high',
                'issue': f'Failed to establish SSL/TLS connection: {str(e)}',
                'recommendation': 'Check network connectivity and RDP Gateway configuration'
            })
        
        self.results['tests'].append(result)
        return result
    
    def test_gateway_authentication(self, username: str, password: str) -> Dict:
        """Test RDP Gateway authentication.
        
        Args:
            username: Username for authentication
            password: Password for authentication
            
        Returns:
            Dict containing test results
        """
        test_name = "Gateway Authentication Test"
        result = {
            'test_name': test_name,
            'passed': False,
            'details': {},
            'findings': []
        }
        
        try:
            # Use xfreerdp to test authentication
            cmd = [
                'xfreerdp',
                f'/v:{self.gateway_address}:{self.gateway_port}',
                f'/u:{username}',
                f'/p:{password}',
                '/gd:rdp',
                '/gt:rpc',
                '/sec:tls',
                '/log-level:info',
                '/cert-ignore',
                '/auth-only'
            ]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(timeout=30)
            
            result['details']['exit_code'] = process.returncode
            result['details']['stdout'] = stdout
            result['details']['stderr'] = stderr
            
            if process.returncode == 0:
                result['passed'] = True
                result['details']['status'] = 'Authentication successful'
            else:
                error_msg = stderr or stdout or 'Unknown error'
                result['findings'].append({
                    'severity': 'high',
                    'issue': f'Authentication failed: {error_msg}',
                    'recommendation': 'Verify credentials and authentication configuration'
                })
                
        except subprocess.TimeoutExpired:
            result['error'] = 'Authentication attempt timed out'
            result['findings'].append({
                'severity': 'medium',
                'issue': 'Authentication attempt timed out',
                'recommendation': 'Check network connectivity and RDP Gateway availability'
            })
        except Exception as e:
            result['error'] = str(e)
            result['findings'].append({
                'severity': 'high',
                'issue': f'Authentication test failed: {str(e)}',
                'recommendation': 'Check RDP Gateway configuration and network connectivity'
            })
        
        self.results['tests'].append(result)
        return result
    
    def test_gateway_authorization(self, username: str, password: str, target_host: str) -> Dict:
        """Test RDP Gateway authorization for a specific target.
        
        Args:
            username: Username for authentication
            password: Password for authentication
            target_host: Target host to test authorization for
            
        Returns:
            Dict containing test results
        """
        test_name = f"Gateway Authorization Test for {target_host}"
        result = {
            'test_name': test_name,
            'passed': False,
            'details': {},
            'findings': []
        }
        
        try:
            # Use xfreerdp to test authorization
            cmd = [
                'xfreerdp',
                f'/v:{self.gateway_address}:{self.gateway_port}',
                f'/u:{username}',
                f'/p:{password}',
                f'/d:{target_host}',
                '/gd:rdp',
                '/gt:rpc',
                '/sec:tls',
                '/log-level:info',
                '/cert-ignore',
                '/auth-only'
            ]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(timeout=30)
            
            result['details']['exit_code'] = process.returncode
            result['details']['stdout'] = stdout
            result['details']['stderr'] = stderr
            
            if process.returncode == 0:
                result['passed'] = True
                result['details']['status'] = f'Authorization successful for {target_host}'
            else:
                error_msg = stderr or stdout or 'Unknown error'
                result['findings'].append({
                    'severity': 'high',
                    'issue': f'Authorization failed for {target_host}: {error_msg}',
                    'recommendation': 'Verify authorization policies for the target host'
                })
                
        except subprocess.TimeoutExpired:
            result['error'] = f'Authorization test for {target_host} timed out'
            result['findings'].append({
                'severity': 'medium',
                'issue': f'Authorization test for {target_host} timed out',
                'recommendation': 'Check network connectivity and RDP Gateway availability'
            })
        except Exception as e:
            result['error'] = str(e)
            result['findings'].append({
                'severity': 'high',
                'issue': f'Authorization test failed for {target_host}: {str(e)}',
                'recommendation': 'Check RDP Gateway configuration and authorization policies'
            })
        
        self.results['tests'].append(result)
        return result
    
    def test_gateway_brute_force_protection(self) -> Dict:
        """Test if the RDP Gateway has brute force protection.
        
        Returns:
            Dict containing test results
        """
        test_name = "Brute Force Protection Test"
        result = {
            'test_name': test_name,
            'passed': False,
            'details': {},
            'findings': []
        }
        
        try:
            # Try multiple failed login attempts
            failed_attempts = 0
            max_attempts = 5
            
            for i in range(max_attempts):
                cmd = [
                    'xfreerdp',
                    f'/v:{self.gateway_address}:{self.gateway_port}',
                    '/u:invalid_user',
                    '/p:invalid_password',
                    '/gd:rdp',
                    '/gt:rpc',
                    '/sec:tls',
                    '/log-level:info',
                    '/cert-ignore',
                    '/auth-only'
                ]
                
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                _, stderr = process.communicate(timeout=10)
                
                if process.returncode != 0:
                    failed_attempts += 1
                    # Check if account is locked or rate limited
                    if 'account is locked' in stderr.lower() or \
                       'too many failed attempts' in stderr.lower() or \
                       'rate limit' in stderr.lower():
                        result['details']['protection_triggered'] = True
                        result['details']['attempts_until_trigger'] = i + 1
                        result['details']['message'] = stderr.strip()
                        result['passed'] = True
                        result['details']['status'] = 'Brute force protection is enabled'
                        break
            
            if not result.get('passed', False):
                result['findings'].append({
                    'severity': 'high',
                    'issue': 'No brute force protection detected',
                    'recommendation': 'Enable account lockout or rate limiting after failed login attempts'
                })
                
        except Exception as e:
            result['error'] = str(e)
            result['findings'].append({
                'severity': 'high',
                'issue': f'Brute force protection test failed: {str(e)}',
                'recommendation': 'Manually verify brute force protection settings'
            })
        
        self.results['tests'].append(result)
        return result
    
    def generate_report(self) -> Dict:
        """Generate a summary report of all tests.
        
        Returns:
            Dict containing the test results
        """
        # Calculate overall status
        passed_tests = sum(1 for test in self.results['tests'] if test.get('passed', False))
        total_tests = len(self.results['tests'])
        
        self.results['summary'] = {
            'total_tests': total_tests,
            'passed_tests': passed_tests,
            'failed_tests': total_tests - passed_tests,
            'findings_count': len(self.results.get('findings', [])),
            'critical_findings': sum(1 for f in self.results.get('findings', []) 
                                   if f.get('severity') == 'critical'),
            'high_findings': sum(1 for f in self.results.get('findings', []) 
                               if f.get('severity') == 'high'),
            'medium_findings': sum(1 for f in self.results.get('findings', []) 
                                 if f.get('severity') == 'medium'),
            'low_findings': sum(1 for f in self.results.get('findings', []) 
                              if f.get('severity') == 'low')
        }
        
        return self.results

# Example usage
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Test RDP Gateway security')
    parser.add_argument('gateway', help='RDP Gateway address')
    parser.add_argument('--port', type=int, default=443, help='RDP Gateway port (default: 443)')
    parser.add_argument('--username', help='Username for authentication tests')
    parser.add_argument('--password', help='Password for authentication tests')
    parser.add_argument('--target', help='Target host for authorization test')
    parser.add_argument('-o', '--output', help='Output file for JSON report')
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    tester = RDPGatewayTester(args.gateway, args.port)
    
    # Run tests
    tester.test_ssl_configuration()
    
    if args.username and args.password:
        tester.test_gateway_authentication(args.username, args.password)
        
        if args.target:
            tester.test_gateway_authorization(args.username, args.password, args.target)
    
    tester.test_gateway_brute_force_protection()
    
    # Generate and print report
    report = tester.generate_report()
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))
