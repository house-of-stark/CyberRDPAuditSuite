#!/usr/bin/env python3
"""
RDP UDP Transport Security Tester
This module tests the security of RDP over UDP transport.

The module focuses on:
1. Detecting if UDP transport is enabled
2. Checking UDP transport security settings
3. Testing potential DoS vulnerabilities in UDP implementation
4. Validating encryption of UDP packets
5. Testing fallback mechanisms to TCP
"""

import os
import sys
import json
import time
import socket
import struct
import logging
import subprocess
from typing import Dict, List, Any, Optional, Tuple
import argparse
import ipaddress
from datetime import datetime
import random

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('rdp_udp_tests.log')
    ]
)
logger = logging.getLogger(__name__)

class RDPUDPTester:
    """Tests RDP over UDP security characteristics"""
    
    def __init__(self, target: str, port: int = 3389, username: str = None, 
                 password: str = None, domain: str = "", verbose: bool = False):
        """Initialize the UDP tester with target information"""
        self.target = target
        self.port = port
        self.username = username
        self.password = password
        self.domain = domain
        self.verbose = verbose
        
        # RDP over UDP uses the same port as TCP by default
        self.rdp_udp_port = port
        
        # Results dictionary to store findings
        self.results = {
            'target': target,
            'port': port,
            'timestamp': datetime.utcnow().isoformat(),
            'udp_enabled': False,
            'udp_security_level': None,
            'vulnerabilities': [],
            'recommendations': [],
            'tests': {},
        }
        
        # Initialize counters
        self.tests_run = 0
        self.tests_passed = 0
        self.tests_failed = 0
        
    def detect_udp_transport(self) -> bool:
        """Detect if RDP over UDP transport is enabled on the target
        
        Returns:
            bool: True if UDP transport is enabled, False otherwise
        """
        logger.info(f"Detecting if RDP over UDP is enabled on {self.target}:{self.port}")
        
        try:
            # Create a UDP socket to test if the port is open
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.settimeout(5)
            
            # Send an RDP negotiation request (simplified)
            # In practice, a valid RDP UDP handshake packet would be needed
            # This is a simplified check for UDP port availability
            rdp_udp_probe = bytes.fromhex('030000130ed000001234000200ff0800000000')
            udp_sock.sendto(rdp_udp_probe, (self.target, self.rdp_udp_port))
            
            # Try to receive a response
            try:
                data, _ = udp_sock.recvfrom(1024)
                # If we get a response (even an error), UDP port is likely open
                if data:
                    logger.info(f"Received response from UDP port {self.rdp_udp_port}, likely open")
                    udp_enabled = True
                else:
                    logger.info(f"No response from UDP port {self.rdp_udp_port}")
                    udp_enabled = False
            except socket.timeout:
                # Try an alternative method using xfreerdp with UDP transport flag
                logger.info("Initial UDP probe timed out, trying xfreerdp with UDP flags")
                cmd = [
                    "xfreerdp", "/v:" + self.target, "/port:" + str(self.port),
                    "/transport:udp", "/log-level:trace", "/cert-ignore", 
                    "/timeout:5", "/d:noconnect"
                ]
                
                if self.username and self.password:
                    cmd.extend(["/u:" + self.username, "/p:" + self.password])
                    
                if self.domain:
                    cmd.append("/d:" + self.domain)
                
                # We don't actually need to connect, just check if UDP is detected
                process = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                
                stdout, stderr = process.communicate(timeout=10)
                output = stdout.decode('utf-8', errors='ignore') + stderr.decode('utf-8', errors='ignore')
                
                # Look for indicators that UDP transport was detected
                if "UDP transport detected" in output or "UDP transport negotiated" in output:
                    logger.info("UDP transport detected via xfreerdp")
                    udp_enabled = True
                else:
                    logger.info("UDP transport not detected via xfreerdp")
                    udp_enabled = False
        except Exception as e:
            logger.error(f"Error detecting UDP transport: {e}")
            udp_enabled = False
        
        # Update results
        self.results['udp_enabled'] = udp_enabled
        if udp_enabled:
            self.results['recommendations'].append(
                "If UDP transport is not required, consider disabling it to reduce attack surface"
            )
        
        return udp_enabled
    
    def test_udp_encryption(self) -> Dict:
        """Test if RDP over UDP packets are properly encrypted
        
        Returns:
            Dict: Test results including encryption level and vulnerabilities
        """
        logger.info("Testing RDP over UDP encryption")
        
        if not self.results['udp_enabled']:
            logger.info("Skipping UDP encryption test - UDP transport not enabled")
            return {'skipped': True, 'reason': 'UDP transport not enabled'}
        
        test_result = {
            'name': 'udp_encryption_test',
            'description': 'Tests if RDP over UDP packets are properly encrypted',
            'status': 'unknown',
            'details': {},
            'vulnerabilities': [],
            'recommendations': []
        }
        
        try:
            # Use tcpdump/tshark to capture and analyze UDP packets
            # This would need to be run with sufficient permissions
            
            # Create a temporary capture file
            capture_file = f"rdp_udp_capture_{int(time.time())}.pcap"
            
            # Build the tcpdump command
            tcpdump_cmd = [
                "tcpdump", "-i", "any", 
                f"host {self.target} and port {self.port} and udp",
                "-w", capture_file, "-c", "50"  # Capture up to 50 packets
            ]
            
            # Start the capture in background
            tcpdump_process = subprocess.Popen(
                tcpdump_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            
            # Give tcpdump time to start
            time.sleep(1)
            
            # Now initiate a connection with UDP transport
            # We don't need to fully connect, just start the handshake
            xfreerdp_cmd = [
                "xfreerdp", "/v:" + self.target, "/port:" + str(self.port),
                "/transport:udp", "/cert-ignore", "/timeout:5"
            ]
            
            if self.username and self.password:
                xfreerdp_cmd.extend(["/u:" + self.username, "/p:" + self.password])
                
            if self.domain:
                xfreerdp_cmd.append("/d:" + self.domain)
            
            # Run the command with a timeout
            try:
                xfreerdp_process = subprocess.Popen(
                    xfreerdp_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                
                # Let it run for a few seconds to generate traffic
                time.sleep(5)
                
                # Terminate the connection attempt
                xfreerdp_process.terminate()
            except Exception as e:
                logger.error(f"Error during connection attempt: {e}")
            
            # Wait a bit more for tcpdump to finish capturing
            time.sleep(2)
            tcpdump_process.terminate()
            
            # Now analyze the capture file with tshark
            tshark_cmd = [
                "tshark", "-r", capture_file, 
                "-Y", "rdp or udp", "-T", "fields", 
                "-e", "rdp.encryption_method", "-e", "rdp.security_protocol"
            ]
            
            tshark_process = subprocess.Popen(
                tshark_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            
            stdout, stderr = tshark_process.communicate()
            output = stdout.decode('utf-8', errors='ignore')
            
            # Check for unencrypted data or weak encryption
            if "Standard RDP Security" in output:
                security_level = "Standard RDP Security (weak)"
                test_result['status'] = 'failed'
                test_result['vulnerabilities'].append({
                    'severity': 'High',
                    'description': 'RDP over UDP using weak Standard RDP Security encryption',
                    'impact': 'Data transmitted over UDP could be intercepted and decrypted',
                    'remediation': 'Configure RDP to use TLS encryption for all transport types'
                })
            elif "TLS" in output or "CredSSP" in output:
                security_level = "TLS/CredSSP (strong)"
                test_result['status'] = 'passed'
            else:
                # If we can't determine the encryption method but UDP is enabled
                security_level = "Unknown"
                test_result['status'] = 'warning'
                test_result['vulnerabilities'].append({
                    'severity': 'Medium',
                    'description': 'Unable to determine RDP over UDP encryption method',
                    'impact': 'Unknown encryption posture may indicate unusual configuration',
                    'remediation': 'Verify TLS encryption is configured for all RDP transports'
                })
            
            # Clean up the capture file
            try:
                os.remove(capture_file)
            except Exception as e:
                logger.warning(f"Could not remove capture file: {e}")
            
            # Update test results
            test_result['details'] = {
                'security_level': security_level,
                'encrypted': security_level != "Standard RDP Security (weak)"
            }
            
            self.results['udp_security_level'] = security_level
            
            # Add recommendations
            if test_result['status'] != 'passed':
                test_result['recommendations'].append(
                    "Configure TLS encryption for all RDP transport types including UDP"
                )
                self.results['recommendations'].append(
                    "Configure TLS encryption for all RDP transport types including UDP"
                )
            
            return test_result
            
        except Exception as e:
            logger.error(f"Error during UDP encryption test: {e}")
            test_result['status'] = 'error'
            test_result['details'] = {'error': str(e)}
            return test_result
    
    def test_dos_vulnerability(self) -> Dict:
        """Test if the RDP over UDP implementation is vulnerable to DoS attacks
        
        Returns:
            Dict: Test results including DoS vulnerability findings
        """
        logger.info("Testing UDP DoS vulnerabilities")
        
        if not self.results['udp_enabled']:
            logger.info("Skipping UDP DoS test - UDP transport not enabled")
            return {'skipped': True, 'reason': 'UDP transport not enabled'}
        
        test_result = {
            'name': 'udp_dos_test',
            'description': 'Tests if RDP over UDP is vulnerable to DoS attacks',
            'status': 'unknown',
            'details': {},
            'vulnerabilities': [],
            'recommendations': []
        }
        
        # This is a simulated test - we don't actually perform a DoS attack
        # In practice, this would involve checking for UDP amplification vulnerabilities
        # or rate limiting mechanisms, but those tests can be disruptive
        
        try:
            # Simple port scan to check UDP behavior with invalid packets
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.settimeout(2)
            
            # Track responses to determine predictability
            responses = []
            no_responses = 0
            sample_size = 5
            
            # Send a series of invalid RDP packets to probe response behavior
            for i in range(sample_size):
                # Create an invalid packet with a random payload
                payload = bytes([random.randint(0, 255) for _ in range(64)])
                udp_sock.sendto(payload, (self.target, self.rdp_udp_port))
                
                # Try to receive a response
                try:
                    data, _ = udp_sock.recvfrom(1024)
                    responses.append(data)
                except socket.timeout:
                    no_responses += 1
            
            # Analyze response behavior
            if no_responses == sample_size:
                # No responses at all - good UDP security practice
                test_result['status'] = 'passed'
                test_result['details'] = {
                    'no_response_rate': 100,
                    'unique_responses': 0,
                    'findings': 'Server does not respond to invalid UDP packets'
                }
            else:
                # Some responses received - analyze them
                unique_responses = len(set([r.hex() for r in responses]))
                response_rate = ((sample_size - no_responses) / sample_size) * 100
                
                # If server responds predictably to invalid packets,
                # it might be more vulnerable to DoS or fingerprinting
                if response_rate > 80:
                    test_result['status'] = 'failed'
                    test_result['vulnerabilities'].append({
                        'severity': 'Medium',
                        'description': 'RDP server responds to invalid UDP packets',
                        'impact': 'Potential for UDP-based DoS attacks or server fingerprinting',
                        'remediation': 'Configure RDP to ignore invalid UDP packets'
                    })
                    test_result['details'] = {
                        'no_response_rate': (no_responses / sample_size) * 100,
                        'unique_responses': unique_responses,
                        'findings': 'Server responds to invalid UDP packets'
                    }
                else:
                    test_result['status'] = 'warning'
                    test_result['details'] = {
                        'no_response_rate': (no_responses / sample_size) * 100,
                        'unique_responses': unique_responses,
                        'findings': 'Server occasionally responds to invalid UDP packets'
                    }
            
            # Add recommendations if needed
            if test_result['status'] != 'passed':
                test_result['recommendations'].append(
                    "Configure RDP server to silently drop invalid UDP packets"
                )
                self.results['recommendations'].append(
                    "Configure RDP server to silently drop invalid UDP packets"
                )
            
            # Add test result to overall results
            self.results['tests']['udp_dos_test'] = test_result
            return test_result
            
        except Exception as e:
            logger.error(f"Error during UDP DoS vulnerability test: {e}")
            test_result['status'] = 'error'
            test_result['details'] = {'error': str(e)}
            return test_result
    
    def test_tcp_fallback(self) -> Dict:
        """Test if RDP properly falls back to TCP when UDP is unavailable
        
        Returns:
            Dict: Test results for TCP fallback behavior
        """
        logger.info("Testing TCP fallback capability")
        
        if not self.results['udp_enabled']:
            logger.info("Skipping TCP fallback test - UDP transport not enabled")
            return {'skipped': True, 'reason': 'UDP transport not enabled'}
        
        test_result = {
            'name': 'tcp_fallback_test',
            'description': 'Tests if RDP properly falls back to TCP when UDP is unavailable',
            'status': 'unknown',
            'details': {},
            'vulnerabilities': [],
            'recommendations': []
        }
        
        try:
            # We'll use iptables to temporarily block UDP traffic to the target port
            # This requires root privileges and should be done carefully
            
            # For security reasons in a real environment, this test should be
            # simulated or performed in a controlled test environment
            
            # Instead of actually blocking UDP, we'll simulate the test result
            # In a real implementation, we would:
            # 1. Block UDP to port 3389 with iptables
            # 2. Attempt RDP connection
            # 3. Check if connection succeeds over TCP
            # 4. Remove the iptables rule
            
            # Simulate the test - assume UDP fallback works but advise verification
            test_result['status'] = 'info'
            test_result['details'] = {
                'simulated': True,
                'finding': 'TCP fallback behavior requires manual verification',
                'expected_behavior': 'Connection should fall back to TCP when UDP is blocked',
            }
            
            test_result['recommendations'] = [
                "Manually verify that RDP clients can still connect when UDP is blocked",
                "Ensure RDP is configured to use TCP transport as a fallback"
            ]
            
            # Add to overall results
            self.results['tests']['tcp_fallback_test'] = test_result
            self.results['recommendations'].append(
                "Verify RDP clients can properly fall back to TCP when UDP is unavailable"
            )
            
            return test_result
            
        except Exception as e:
            logger.error(f"Error during TCP fallback test: {e}")
            test_result['status'] = 'error'
            test_result['details'] = {'error': str(e)}
            return test_result
    
    def run_all_tests(self) -> Dict:
        """Run all UDP transport security tests
        
        Returns:
            Dict: Comprehensive test results
        """
        logger.info(f"Starting RDP UDP security tests for {self.target}:{self.port}")
        
        start_time = datetime.utcnow()
        
        # First, check if UDP transport is enabled
        udp_enabled = self.detect_udp_transport()
        
        if udp_enabled:
            logger.info("UDP transport is enabled, running security tests")
            
            # Run encryption test
            encryption_result = self.test_udp_encryption()
            self.results['tests']['udp_encryption'] = encryption_result
            
            # Run DoS vulnerability test
            dos_result = self.test_dos_vulnerability()
            self.results['tests']['udp_dos'] = dos_result
            
            # Run TCP fallback test
            fallback_result = self.test_tcp_fallback()
            self.results['tests']['tcp_fallback'] = fallback_result
            
            # Update counters
            for test in self.results['tests'].values():
                self.tests_run += 1
                if test.get('status') == 'passed':
                    self.tests_passed += 1
                elif test.get('status') == 'failed':
                    self.tests_failed += 1
        else:
            logger.info("UDP transport is not enabled, skipping security tests")
            # Add a note that UDP transport is disabled (which is good for security)
            self.results['recommendations'].append(
                "UDP transport is disabled which reduces attack surface - maintain this configuration"
            )
        
        # Record test completion time
        end_time = datetime.utcnow()
        self.results['start_time'] = start_time.isoformat()
        self.results['end_time'] = end_time.isoformat()
        self.results['duration_seconds'] = (end_time - start_time).total_seconds()
        
        # Add summary stats
        self.results['summary'] = {
            'tests_run': self.tests_run,
            'tests_passed': self.tests_passed,
            'tests_failed': self.tests_failed,
            'vulnerabilities_found': len(self.results['vulnerabilities'])
        }
        
        # Remove duplicates from recommendations
        self.results['recommendations'] = list(set(self.results['recommendations']))
        
        return self.results
    
    def generate_report(self, output_file: str = None) -> Dict:
        """Generate a JSON report of the test results
        
        Args:
            output_file (str, optional): Path to save the JSON report. 
                                       If None, report is returned but not saved.
        
        Returns:
            Dict: Test results and findings
        """
        if not self.results.get('end_time'):
            # Run tests if they haven't been run yet
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


def parse_args():
    """Parse command line arguments
    
    Returns:
        argparse.Namespace: Parsed command-line arguments
    """
    parser = argparse.ArgumentParser(
        description='RDP over UDP Transport Security Tester',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--port', type=int, default=3389,
                      help='RDP port (default: 3389)')
    parser.add_argument('-u', '--username', help='Username for authentication tests')
    parser.add_argument('-P', '--password', help='Password for authentication tests')
    parser.add_argument('-d', '--domain', default="",
                      help='Domain for authentication tests')
    parser.add_argument('-o', '--output', help='Output file for JSON report')
    parser.add_argument('-v', '--verbose', action='store_true',
                      help='Enable verbose output')
    
    return parser.parse_args()


def main():
    """Main function to run the UDP Transport Security tests"""
    # Parse arguments
    args = parse_args()
    
    # Set up logging verbosity
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Banner
    print("="*80)
    print(" RDP over UDP Transport Security Tester")
    print(f" Target: {args.target}:{args.port}")
    print("="*80)
    print()
    
    try:
        # Initialize tester
        tester = RDPUDPTester(
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
            output_file = f"rdp_udp_security_{args.target}_{timestamp}.json"
            
        tester.generate_report(output_file)
        
        # Print summary
        print("\nTest Summary:")
        print(f"UDP Transport Enabled: {results['udp_enabled']}")
        if results['udp_enabled']:
            print(f"UDP Security Level: {results['udp_security_level'] or 'Unknown'}")
        print(f"Tests Run: {results['summary']['tests_run']}")
        print(f"Tests Passed: {results['summary']['tests_passed']}")
        print(f"Tests Failed: {results['summary']['tests_failed']}")
        print(f"Vulnerabilities Found: {results['summary']['vulnerabilities_found']}")
        
        if results['vulnerabilities']:
            print("\nVulnerabilities:")
            for i, vuln in enumerate(results['vulnerabilities'], 1):
                print(f"  {i}. [{vuln.get('severity', 'Unknown')}] {vuln.get('description', 'Unknown vulnerability')}")
        
        if results['recommendations']:
            print("\nRecommendations:")
            for i, rec in enumerate(results['recommendations'], 1):
                print(f"  {i}. {rec}")
                
        print(f"\nFull report saved to: {output_file}")
        return 0
    
    except KeyboardInterrupt:
        logger.warning("Test interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Error running UDP tests: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
