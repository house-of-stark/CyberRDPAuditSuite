#!/usr/bin/env python3
"""
RDP Brute-Force Testing Automation
Implements automated credential and session token brute-force resistance testing
"""

import subprocess
import threading
import time
import json
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import random
import string

class RDPBruteForceTest:
    def __init__(self, target_ip, target_port=3389):
        self.target_ip = target_ip
        self.target_port = target_port
        self.results = {
            'test_start': datetime.now().isoformat(),
            'target': f"{target_ip}:{target_port}",
            'credential_tests': [],
            'token_tests': [],
            'vulnerabilities': [],
            'statistics': {}
        }
        
    def generate_common_passwords(self):
        """Generate common password list for testing"""
        common_passwords = [
            'password', '123456', 'admin', 'root', 'guest', 'test',
            'Password1', 'password123', 'admin123', 'P@ssw0rd',
            '12345678', 'qwerty', 'letmein', 'welcome', 'monkey'
        ]
        return common_passwords
    
    def generate_common_usernames(self):
        """Generate common username list for testing"""
        common_usernames = [
            'admin', 'administrator', 'root', 'guest', 'test', 'user',
            'cyberark', 'psm', 'rdp', 'service', 'operator', 'manager'
        ]
        return common_usernames
    
    def test_rdp_connection(self, username, password, timeout=5):
        """Test RDP connection with given credentials"""
        try:
            # Use xfreerdp for connection testing
            cmd = [
                'xfreerdp',
                f'/v:{self.target_ip}:{self.target_port}',
                f'/u:{username}',
                f'/p:{password}',
                '/sec:rdp',
                '/cert-ignore',
                '/timeout:5000',
                '+auth-only'  # Only test authentication
            ]
            
            start_time = time.time()
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=timeout
            )
            end_time = time.time()
            
            response_time = end_time - start_time
            
            # Analyze result
            success = result.returncode == 0
            error_output = result.stderr.lower()
            
            # Check for specific authentication failures vs lockouts
            if 'authentication failure' in error_output:
                status = 'auth_failed'
            elif 'account locked' in error_output or 'locked out' in error_output:
                status = 'account_locked'
            elif 'too many attempts' in error_output:
                status = 'rate_limited'
            elif success:
                status = 'success'
            else:
                status = 'connection_failed'
            
            return {
                'username': username,
                'password': password,
                'status': status,
                'response_time': response_time,
                'error': result.stderr,
                'timestamp': datetime.now().isoformat()
            }
            
        except subprocess.TimeoutExpired:
            return {
                'username': username,
                'password': password,
                'status': 'timeout',
                'response_time': timeout,
                'error': 'Connection timeout',
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'username': username,
                'password': password,
                'status': 'error',
                'response_time': 0,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def test_credential_brute_force(self, max_attempts=50, thread_count=3):
        """Test credential brute-force resistance"""
        print("[INFO] Starting credential brute-force testing...")
        
        usernames = self.generate_common_usernames()
        passwords = self.generate_common_passwords()
        
        # Generate test combinations
        test_combinations = []
        attempts = 0
        
        for username in usernames:
            for password in passwords:
                if attempts >= max_attempts:
                    break
                test_combinations.append((username, password))
                attempts += 1
            if attempts >= max_attempts:
                break
        
        print(f"[INFO] Testing {len(test_combinations)} credential combinations...")
        
        # Threaded testing with rate limiting
        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            futures = []
            for username, password in test_combinations:
                future = executor.submit(self.test_rdp_connection, username, password)
                futures.append(future)
                time.sleep(0.5)  # Rate limiting to avoid overwhelming the target
            
            # Collect results
            for future in futures:
                try:
                    result = future.result(timeout=10)
                    self.results['credential_tests'].append(result)
                    
                    # Check for vulnerabilities
                    if result['status'] == 'success':
                        self.results['vulnerabilities'].append({
                            'type': 'Weak Credentials',
                            'severity': 'Critical',
                            'description': f"Successful login with {result['username']}:{result['password']}",
                            'timestamp': result['timestamp']
                        })
                    elif result['status'] == 'auth_failed' and result['response_time'] < 1.0:
                        # Fast authentication failures might indicate no rate limiting
                        self.results['vulnerabilities'].append({
                            'type': 'No Rate Limiting',
                            'severity': 'Medium',
                            'description': f"Fast authentication failure - possible lack of rate limiting",
                            'response_time': result['response_time']
                        })
                    
                except Exception as e:
                    print(f"[ERROR] Thread execution failed: {e}")
        
        print(f"[INFO] Credential brute-force testing completed. {len(self.results['credential_tests'])} attempts made.")
    
    def test_session_token_brute_force(self, pcap_file=None):
        """Test session token brute-force resistance"""
        print("[INFO] Starting session token brute-force testing...")
        
        if not pcap_file:
            print("[WARN] No PCAP file provided for token analysis")
            return
        
        try:
            # Use tshark to extract potential session tokens
            cmd = [
                'tshark', '-r', pcap_file,
                '-Y', 'rdp or ssl',
                '-T', 'fields',
                '-e', 'tcp.seq',
                '-e', 'tcp.ack',
                '-e', 'rdp.sessionId'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                tokens = set()
                
                for line in lines:
                    if line.strip():
                        parts = line.split('\t')
                        for part in parts:
                            if part and len(part) > 8:  # Potential token
                                tokens.add(part)
                
                print(f"[INFO] Extracted {len(tokens)} potential session tokens")
                
                # Test token manipulation (simulation)
                for i, token in enumerate(list(tokens)[:10]):  # Test first 10
                    # Generate modified tokens
                    modified_tokens = self._generate_token_variants(token)
                    
                    for modified_token in modified_tokens:
                        token_test = {
                            'original_token': token,
                            'modified_token': modified_token,
                            'test_type': 'token_manipulation',
                            'timestamp': datetime.now().isoformat(),
                            'status': 'simulated'  # In real scenario, would test connection
                        }
                        self.results['token_tests'].append(token_test)
                
        except Exception as e:
            print(f"[ERROR] Token brute-force testing failed: {e}")
    
    def _generate_token_variants(self, original_token):
        """Generate token variants for brute-force testing"""
        variants = []
        
        # Increment/decrement variants
        if original_token.isdigit():
            try:
                num = int(original_token)
                variants.extend([str(num + i) for i in range(-5, 6)])
            except:
                pass
        
        # Bit flip variants (for hex tokens)
        if all(c in '0123456789abcdefABCDEF' for c in original_token):
            for i in range(min(len(original_token), 8)):
                variant = list(original_token)
                variant[i] = '0' if variant[i] != '0' else '1'
                variants.append(''.join(variant))
        
        return variants[:20]  # Limit variants
    
    def analyze_brute_force_resistance(self):
        """Analyze brute-force resistance based on test results"""
        stats = {
            'total_credential_attempts': len(self.results['credential_tests']),
            'successful_logins': 0,
            'account_lockouts': 0,
            'rate_limited': 0,
            'average_response_time': 0,
            'vulnerabilities_found': len(self.results['vulnerabilities'])
        }
        
        response_times = []
        
        for test in self.results['credential_tests']:
            if test['status'] == 'success':
                stats['successful_logins'] += 1
            elif test['status'] == 'account_locked':
                stats['account_lockouts'] += 1
            elif test['status'] == 'rate_limited':
                stats['rate_limited'] += 1
            
            response_times.append(test['response_time'])
        
        if response_times:
            stats['average_response_time'] = sum(response_times) / len(response_times)
        
        # Security assessment
        if stats['successful_logins'] > 0:
            self.results['vulnerabilities'].append({
                'type': 'Credential Brute-Force Vulnerability',
                'severity': 'Critical',
                'description': f"{stats['successful_logins']} successful brute-force attempts"
            })
        
        if stats['account_lockouts'] == 0 and stats['rate_limited'] == 0:
            self.results['vulnerabilities'].append({
                'type': 'No Brute-Force Protection',
                'severity': 'High',
                'description': 'No account lockout or rate limiting detected'
            })
        
        if stats['average_response_time'] < 0.5:
            self.results['vulnerabilities'].append({
                'type': 'Fast Authentication Response',
                'severity': 'Medium',
                'description': 'Fast response times may indicate insufficient brute-force protection'
            })
        
        self.results['statistics'] = stats
        
        return stats
    
    def generate_report(self, output_file):
        """Generate brute-force test report"""
        self.results['test_end'] = datetime.now().isoformat()
        
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"[INFO] Brute-force test report saved to: {output_file}")
        
        # Print summary
        stats = self.results['statistics']
        print("\n=== BRUTE-FORCE TEST SUMMARY ===")
        print(f"Target: {self.results['target']}")
        print(f"Total Attempts: {stats['total_credential_attempts']}")
        print(f"Successful Logins: {stats['successful_logins']}")
        print(f"Account Lockouts: {stats['account_lockouts']}")
        print(f"Rate Limited: {stats['rate_limited']}")
        print(f"Average Response Time: {stats['average_response_time']:.2f}s")
        print(f"Vulnerabilities Found: {stats['vulnerabilities_found']}")
        
        if self.results['vulnerabilities']:
            print("\n=== VULNERABILITIES ===")
            for vuln in self.results['vulnerabilities']:
                print(f"[{vuln['severity']}] {vuln['type']}: {vuln['description']}")
    
    def test_bruteforce_protection(self, username=None, password=None, max_attempts=50, thread_count=3, delay=1):
        """
        Test brute-force protection mechanisms
        
        Args:
            username: Optional username to test (if None, will use common usernames)
            password: Optional password to test (if None, will use common passwords)
            max_attempts: Maximum number of login attempts to make
            thread_count: Number of concurrent threads to use
            
        Returns:
            dict: Test results including vulnerabilities found
        """
        try:
            print("[INFO] Starting brute-force protection testing...")
            
            # Run credential brute-force test
            self.test_credential_brute_force(max_attempts, thread_count)
            
            # Analyze results
            stats = self.analyze_brute_force_resistance()
            
            # Prepare results in a format expected by the test runner
            result = {
                'success': True,
                'vulnerabilities_found': stats['vulnerabilities_found'],
                'successful_logins': stats['successful_logins'],
                'account_lockouts': stats['account_lockouts'],
                'rate_limited': stats['rate_limited'],
                'average_response_time': stats['average_response_time'],
                'vulnerabilities': self.results.get('vulnerabilities', [])
            }
            
            return result
            
        except Exception as e:
            print(f"[ERROR] Brute-force protection test failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'vulnerabilities_found': 0
            }

def main():
    parser = argparse.ArgumentParser(description='RDP Brute-Force Testing Tool')
    parser.add_argument('target_ip', help='Target RDP server IP address')
    parser.add_argument('-p', '--port', type=int, default=3389, help='RDP port (default: 3389)')
    parser.add_argument('-a', '--attempts', type=int, default=50, help='Maximum attempts (default: 50)')
    parser.add_argument('-t', '--threads', type=int, default=3, help='Thread count (default: 3)')
    parser.add_argument('-o', '--output', default='bruteforce_results.json', help='Output file')
    parser.add_argument('--pcap', help='PCAP file for token analysis')
    
    args = parser.parse_args()
    
    print(f"[INFO] Starting RDP brute-force testing against {args.target_ip}:{args.port}")
    
    tester = RDPBruteForceTest(args.target_ip, args.port)
    
    # Run credential brute-force test
    tester.test_credential_brute_force(args.attempts, args.threads)
    
    # Run token brute-force test if PCAP provided
    if args.pcap:
        tester.test_session_token_brute_force(args.pcap)
    
    # Analyze results
    tester.analyze_brute_force_resistance()
    
    # Generate report
    tester.generate_report(args.output)

if __name__ == "__main__":
    main()
