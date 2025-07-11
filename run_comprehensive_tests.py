#!/usr/bin/env python3
"""
CyberRDP Audit Suite - Comprehensive RDP Security Assessment Tool
Performs in-depth security testing of RDP implementations and generates detailed reports

Version: 1.0.0
"""

import os
import sys
import json
import logging
import argparse
import subprocess
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

# Version information
VERSION = "1.0.0"
RELEASE_DATE = "2025-06-24"

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('rdp_security_test.log')
    ]
)
logger = logging.getLogger(__name__)

# Import test modules
try:
    from rdp_bruteforce_tester import RDPBruteForceTest as RDPBruteForceTester
    from mfa_bypass_tester import MFABypassTester
    from burp_suite_integration import BurpSuiteIntegrator as BurpSuiteIntegration
    from rbac_validator import RDPRBACValidator as RBACValidator
    from time_based_attacks import RDPTimeAttackTester
    from clipboard_security import RDPClipboardTester
    from rdp_gateway_tester import RDPGatewayTester
    from virtual_channel_tester import RDPVirtualChannelTester
    from rdp_udp_tester import RDPUDPTester
except ImportError as e:
    logger.error(f"Failed to import required modules: {e}")
    logger.error("Please ensure all test modules are in the same directory")
    sys.exit(1)

class CyberRDPAuditSuite:
    """
    CyberRDP Audit Suite - Comprehensive RDP Security Assessment
    
    Provides end-to-end security testing for RDP implementations including:
    - Authentication security
    - Session security
    - Protocol analysis
    - Vulnerability assessment
    - Compliance validation
    """
    
    def __init__(self, target: str, port: int = 3389, username: str = None, 
                 password: str = None, output_dir: str = 'reports'):
        """Initialize the tester with target information"""
        self.target = target
        self.port = port
        self.username = username
        self.password = password
        self.output_dir = output_dir
        self.report = {
            'metadata': {
                'target': target,
                'port': port,
                'start_time': datetime.utcnow().isoformat(),
                'end_time': None,
                'duration_seconds': None,
                'modules_loaded': []
            },
            'results': {},
            'vulnerabilities': [],
            'summary': {
                'tests_run': 0,
                'tests_passed': 0,
                'tests_failed': 0,
                'vulnerabilities_found': 0,
                'critical_vulnerabilities': 0,
                'high_vulnerabilities': 0,
                'medium_vulnerabilities': 0,
                'low_vulnerabilities': 0
            }
        }
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
    
    def run_bruteforce_test(self) -> Dict:
        """Run brute force testing"""
        logger.info("Starting brute force testing...")
        try:
            tester = RDPBruteForceTester(self.target, self.port)
            result = tester.test_bruteforce_protection(
                username=self.username,
                max_attempts=5,  # Keep it low for testing
                delay=1
            )
            self._add_test_result('bruteforce', result)
            return result
        except Exception as e:
            logger.error(f"Brute force test failed: {e}")
            return {'error': str(e)}
    
    def run_mfa_bypass_test(self) -> Dict:
        """Run MFA bypass testing"""
        logger.info("Starting MFA bypass testing...")
        try:
            tester = MFABypassTester(self.target, self.port)
            result = tester.test_mfa_bypass(
                username=self.username,
                password=self.password,
                valid_code='123456'  # Example valid code
            )
            self._add_test_result('mfa_bypass', result)
            return result
        except Exception as e:
            logger.error(f"MFA bypass test failed: {e}")
            return {'error': str(e)}
    
    def run_burp_suite_tests(self) -> Dict:
        """Run Burp Suite integration tests"""
        logger.info("Starting Burp Suite integration tests...")
        try:
            burp = BurpSuiteIntegration(
                burp_host='127.0.0.1',
                burp_port=8080,
                target_url=f"rdp://{self.target}:{self.port}"
            )
            
            # Configure Burp for RDP testing
            burp.configure_burp()
            
            # Run active scan
            scan_results = burp.run_active_scan()
            
            # Get scan issues
            issues = burp.get_scan_issues()
            
            result = {
                'scan_id': scan_results.get('scan_id'),
                'issues_found': len(issues),
                'issues': issues
            }
            
            self._add_test_result('burp_suite', result)
            return result
            
        except Exception as e:
            logger.error(f"Burp Suite test failed: {e}")
            return {'error': str(e)}
    
    def run_rbac_tests(self) -> Dict:
        """Run RBAC validation tests"""
        logger.info("Starting RBAC validation tests...")
        try:
            tester = RBACValidator(self.target, self.port)
            result = tester.test_rbac_controls(
                username=self.username,
                password=self.password
            )
            self._add_test_result('rbac_validation', result)
            return result
        except Exception as e:
            logger.error(f"RBAC test failed: {e}")
            return {'error': str(e)}
    
    def run_time_based_tests(self) -> Dict:
        """Run time-based attack tests"""
        logger.info("Starting time-based attack tests...")
        try:
            tester = RDPTimeAttackTester(self.target, self.port)
            
            if self.username and self.password:
                # Test login timing
                tester.test_authentication_timing(
                    self.username, 
                    self.password,
                    num_attempts=5
                )
                
                # Test rate limiting
                tester.test_rate_limiting(
                    self.username,
                    self.password,
                    max_attempts=10
                )
            
            # Test token validation (simulated)
            tester.test_session_token_validation(
                "valid_token_123",
                "invalid_token_456"
            )
            
            # Generate report
            report = tester.generate_report()
            self._add_test_result('time_based_attacks', report)
            return report
            
        except Exception as e:
            logger.error(f"Time-based attack test failed: {e}")
            return {'error': str(e)}
    
    def run_clipboard_tests(self) -> Dict:
        """Run clipboard security tests"""
        logger.info("Starting clipboard security tests...")
        try:
            tester = RDPClipboardTester(
                self.target, 
                self.port,
                self.username,
                self.password
            )
            
            # Run all clipboard tests
            tester.run_all_tests()
            
            # Generate report
            report = tester.generate_report()
            self._add_test_result('clipboard_security', report)
            return report
            
        except Exception as e:
            logger.error(f"Clipboard security test failed: {e}")
            return {'error': str(e)}
    
    def run_gateway_tests(self) -> Dict:
        """Run RDP Gateway security tests"""
        logger.info("Starting RDP Gateway security tests...")
        try:
            tester = RDPGatewayTester(
                target=self.target,
                port=self.port,
                username=self.username,
                password=self.password
            )
            
            # Run SSL/TLS tests
            tester.test_ssl_tls_configuration()
            
            # Test authentication and authorization
            if self.username and self.password:
                tester.test_authentication()
                tester.test_authorization()
                tester.test_brute_force_protection()
            else:
                logger.warning("Skipping authentication-based gateway tests - no credentials provided")
            
            # Generate report
            report = tester.generate_report()
            self._add_test_result('gateway_security', report)
            return report
            
        except Exception as e:
            logger.error(f"RDP Gateway security test failed: {e}")
            return {'error': str(e)}
    
    def run_virtual_channel_tests(self) -> Dict:
        """Run RDP virtual channel security tests"""
        logger.info("Starting RDP virtual channel security tests...")
        try:
            tester = RDPVirtualChannelTester(
                target=self.target,
                port=self.port,
                username=self.username,
                password=self.password
            )
            
            # Run all channel tests if credentials are provided
            if self.username and self.password:
                tester.test_all_channels()
            else:
                logger.warning("Skipping virtual channel tests - no credentials provided")
                tester.test_available_channels()
            
            # Generate report
            report = tester.generate_report()
            self._add_test_result('virtual_channel_security', report)
            return report
            
        except Exception as e:
            logger.error(f"RDP virtual channel security test failed: {e}")
            return {'error': str(e)}
            
    def run_udp_transport_tests(self) -> Dict:
        """Run RDP over UDP transport security tests"""
        logger.info("Starting RDP UDP transport security tests...")
        try:
            tester = RDPUDPTester(
                target=self.target,
                port=self.port,
                username=self.username,
                password=self.password
            )
            
            # Run all UDP tests
            results = tester.run_all_tests()
            
            # Add vulnerabilities to main report
            if results.get('vulnerabilities'):
                for vuln in results['vulnerabilities']:
                    self.report['vulnerabilities'].append({
                        'test': 'udp_transport_security',
                        **vuln
                    })
            
            # Add test result to the report
            self._add_test_result('udp_transport_security', results)
            return results
            
        except Exception as e:
            logger.error(f"RDP UDP transport security test failed: {e}")
            return {'error': str(e)}
    
    def _add_test_result(self, test_name: str, result: Dict) -> None:
        """Add test result to the report"""
        self.report['results'][test_name] = result
        
        # Update summary
        self.report['summary']['tests_run'] += 1
        
        # Check for vulnerabilities
        if 'vulnerabilities' in result:
            for vuln in result.get('vulnerabilities', []):
                self.report['vulnerabilities'].append({
                    'test': test_name,
                    **vuln
                })
                
                # Update vulnerability counts
                self.report['summary']['vulnerabilities_found'] += 1
                severity = vuln.get('severity', '').lower()
                if 'critical' in severity:
                    self.report['summary']['critical_vulnerabilities'] += 1
                elif 'high' in severity:
                    self.report['summary']['high_vulnerabilities'] += 1
                elif 'medium' in severity:
                    self.report['summary']['medium_vulnerabilities'] += 1
                elif 'low' in severity:
                    self.report['summary']['low_vulnerabilities'] += 1
    
    def run_all_tests(self) -> Dict:
        """Run all available security tests"""
        start_time = datetime.utcnow()
        
        logger.info(f"Starting comprehensive RDP security testing on {self.target}:{self.port}")
        
        # Run tests
        if self.username and self.password:
            self.run_bruteforce_test()
            self.run_mfa_bypass_test()
            self.run_rbac_tests()
        else:
            logger.warning("Skipping authentication-based tests - no credentials provided")
        
        self.run_burp_suite_tests()
        self.run_time_based_tests()
        self.run_clipboard_tests()
        
        # Run the new gateway, virtual channel, and UDP transport tests
        self.run_gateway_tests()
        self.run_virtual_channel_tests()
        self.run_udp_transport_tests()
        
        # Update report metadata
        end_time = datetime.utcnow()
        self.report['metadata']['end_time'] = end_time.isoformat()
        self.report['metadata']['duration_seconds'] = (end_time - start_time).total_seconds()
        self.report['metadata']['modules_loaded'] = [
            'bruteforce', 'mfa_bypass', 'burp_suite', 
            'rbac_validation', 'time_based_attacks', 'clipboard_security',
            'gateway_security', 'virtual_channel_security', 'udp_transport_security'
        ]
        
        return self.generate_report()
    
    def generate_report(self, output_file: str = None, generate_html: bool = True) -> Tuple[str, str]:
        """Generate comprehensive test reports (JSON and optionally HTML)
        
        Args:
            output_file: Path to save the JSON report. If None, generates a default filename.
            generate_html: Whether to generate an HTML report.
            
        Returns:
            Tuple of (json_report_path, html_report_path or None)
        """
        # Set end time and calculate duration
        end_time = datetime.utcnow()
        start_time = datetime.fromisoformat(self.report['metadata']['start_time'])
        self.report['metadata']['end_time'] = end_time.isoformat()
        self.report['metadata']['duration_seconds'] = (end_time - start_time).total_seconds()
        
        # Generate output filename if not provided
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = os.path.join(
                self.output_dir,
                f'rdp_security_report_{self.target}_{timestamp}.json'
            )
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        # Write JSON report
        with open(output_file, 'w') as f:
            json.dump(self.report, f, indent=2)
        
        html_report_path = None
        if generate_html:
            try:
                # Generate HTML report path from JSON path
                html_report_path = os.path.splitext(output_file)[0] + '.html'
                # Import the HTML report generator
                from enhanced_html_report import generate_html_report
                # Generate the HTML report
                generate_html_report(output_file, html_report_path)
                logger.info(f"HTML report generated: {html_report_path}")
            except Exception as e:
                logger.error(f"Failed to generate HTML report: {e}", exc_info=True)
        
        # Print summary
        self.print_summary()
        
        print(f"\nJSON report: {output_file}")
        if html_report_path:
            print(f"HTML report: {html_report_path}")
            
        return output_file, html_report_path
    
    def _get_recommendations(self, vuln_type: str, severity: str) -> List[str]:
        """Get detailed recommendations for a specific vulnerability type"""
        recommendations = []
        
        # Common security recommendations
        common_recommendations = [
            "Regularly update and patch all systems and software.",
            "Implement the principle of least privilege for all user accounts.",
            "Enable comprehensive logging and monitoring of all security events.",
            "Conduct regular security awareness training for all users.",
            "Perform regular security assessments and penetration testing."
        ]
        
        # Type-specific recommendations
        vuln_recommendations = {
            'bruteforce': [
                "Implement account lockout policies after a defined number of failed attempts.",
                "Enforce strong password policies (minimum length, complexity, expiration).",
                "Implement multi-factor authentication (MFA) for all user accounts.",
                "Use rate limiting to prevent automated brute force attacks.",
                "Monitor and alert on multiple failed login attempts.",
                "Consider implementing IP-based blocking for repeated failed attempts.",
                "Use CAPTCHA or similar mechanisms to prevent automated attacks.",
                "Implement delayed response times after failed login attempts.",
                "Regularly review authentication logs for suspicious patterns.",
                "Consider using passwordless authentication methods where possible."
            ],
            'mfa_bypass': [
                "Implement MFA using time-based one-time passwords (TOTP) or hardware tokens.",
                "Ensure MFA is required for all authentication methods, not just password-based.",
                "Implement step-up authentication for sensitive operations.",
                "Monitor for and block suspicious authentication attempts.",
                "Regularly rotate MFA secrets and tokens.",
                "Implement device fingerprinting to detect unusual devices.",
                "Use FIDO2/WebAuthn standards for phishing-resistant authentication.",
                "Implement conditional access policies based on risk factors.",
                "Monitor for and respond to MFA fatigue attacks.",
                "Regularly audit MFA configuration and usage."
            ],
            'clipboard': [
                "Disable clipboard redirection if not explicitly required.",
                "Implement DLP solutions to monitor and prevent sensitive data exfiltration.",
                "Restrict clipboard formats to only those necessary for business operations.",
                "Implement logging of all clipboard operations in sensitive environments.",
                "Use application whitelisting to prevent unauthorized clipboard access.",
                "Implement virtual desktop infrastructure (VDI) with restricted clipboard access.",
                "Educate users about the risks of copying sensitive data to the clipboard.",
                "Implement session recording for users with access to sensitive data.",
                "Use data classification to enforce clipboard policies based on data sensitivity.",
                "Regularly audit and review clipboard access logs."
            ],
            'rbac': [
                "Implement the principle of least privilege for all user accounts.",
                "Regularly review and update role assignments.",
                "Implement separation of duties to prevent privilege escalation.",
                "Use just-in-time (JIT) access for privileged operations.",
                "Implement privileged access management (PAM) solutions.",
                "Regularly audit permissions and access controls.",
                "Implement time-based access restrictions.",
                "Use attribute-based access control (ABAC) for fine-grained access control.",
                "Implement session recording for privileged accounts.",
                "Regularly review and update RBAC policies based on business needs."
            ],
            'time_based': [
                "Implement constant-time algorithms for security-sensitive operations.",
                "Use secure coding practices to prevent timing attacks.",
                "Implement rate limiting and request throttling.",
                "Use secure comparison functions that don't leak timing information.",
                "Implement proper error handling that doesn't reveal timing differences.",
                "Use hardware security modules (HSMs) for cryptographic operations.",
                "Regularly test for timing vulnerabilities in your applications.",
                "Implement request queuing to normalize response times.",
                "Use secure protocols that protect against timing attacks.",
                "Monitor for unusual patterns in authentication timing."
            ],
            'encryption': [
                "Use strong encryption protocols (TLS 1.2/1.3) for all network communications.",
                "Implement perfect forward secrecy (PFS) for encrypted connections.",
                "Regularly update and rotate encryption keys.",
                "Disable weak cipher suites and protocols.",
                "Implement certificate pinning for critical applications.",
                "Use hardware security modules (HSMs) for key management.",
                "Regularly audit encryption configurations and implementations.",
                "Implement certificate transparency monitoring.",
                "Use strong, industry-standard encryption algorithms.",
                "Regularly test encryption implementations for vulnerabilities."
            ]
        }
        
        # Add common recommendations
        recommendations.extend(common_recommendations)
        
        # Add specific recommendations based on vulnerability type
        for key, recs in vuln_recommendations.items():
            if key in vuln_type.lower():
                recommendations.extend(recs)
                break
        
        # Add severity-specific recommendations
        if 'high' in severity.lower() or 'critical' in severity.lower():
            recommendations.append("This is a high/critical severity finding. Immediate remediation is recommended.")
        
        return recommendations
    
    def print_summary(self) -> None:
        """Print a detailed summary of test results with recommendations"""
        summary = self.report['summary']
        
        print("\n" + "="*50)
        print(f"RDP SECURITY TEST SUMMARY - {self.target}:{self.port}")
        print("="*50)
        print(f"Tests Run: {summary['tests_run']}")
        print(f"Vulnerabilities Found: {summary['vulnerabilities_found']}")
        print(f"  - Critical: {summary['critical_vulnerabilities']}")
        print(f"  - High: {summary['high_vulnerabilities']}")
        print(f"  - Medium: {summary['medium_vulnerabilities']}")
        print(f"  - Low: {summary['low_vulnerabilities']}")
        print("="*50 + "\n")
        
        # Print detailed vulnerability information
        if self.report['vulnerabilities']:
            print("\n" + "="*50)
            print("DETAILED VULNERABILITY FINDINGS")
            print("="*50)
            
            # Group vulnerabilities by severity
            by_severity = {}
            for vuln in self.report['vulnerabilities']:
                severity = vuln.get('severity', 'Unknown').lower()
                if severity not in by_severity:
                    by_severity[severity] = []
                by_severity[severity].append(vuln)
            
            # Print in order of severity
            for severity in ['critical', 'high', 'medium', 'low']:
                if severity in by_severity:
                    print(f"\n{severity.upper()} SEVERITY FINDINGS (Total: {len(by_severity[severity])})")
                    print("-" * 50)
                    
                    for i, vuln in enumerate(by_severity[severity], 1):
                        vuln_type = vuln.get('type', 'Unknown')
                        print(f"\n{i}. {vuln_type.upper()}")
                        print(f"   {'-' * (len(vuln_type) + 3)}")
                        print(f"   Severity: {vuln.get('severity', 'Unknown')}")
                        print(f"   Test: {vuln.get('test', 'N/A')}")
                        print(f"   Description: {vuln.get('description', 'No description provided')}")
                        
                        # Get and print recommendations
                        print("\n   RECOMMENDED REMEDIATION ACTIONS:")
                        recommendations = self._get_recommendations(vuln_type, vuln.get('severity', ''))
                        for j, rec in enumerate(recommendations, 1):
                            print(f"      {j}. {rec}")
                        
                        # Print any additional details
                        if 'details' in vuln:
                            print("\n   ADDITIONAL DETAILS:")
                            for key, value in vuln['details'].items():
                                print(f"      - {key}: {value}")
                        
                        print("\n" + "-" * 50)
            
            print("\n" + "="*50)
            print("SECURITY RECOMMENDATIONS SUMMARY")
            print("="*50)
            
            # Print top 10 overall recommendations
            print("\nTOP 10 SECURITY RECOMMENDATIONS:")
            all_recs = []
            for vuln in self.report['vulnerabilities']:
                vuln_type = vuln.get('type', '').lower()
                severity = vuln.get('severity', '').lower()
                recs = self._get_recommendations(vuln_type, severity)
                all_recs.extend(recs)
            
            # Remove duplicates while preserving order
            seen = set()
            unique_recs = []
            for rec in all_recs:
                if rec not in seen:
                    seen.add(rec)
                    unique_recs.append(rec)
            
            # Print top 10 unique recommendations
            for i, rec in enumerate(unique_recs[:10], 1):
                print(f"{i}. {rec}")
            
            print("\nNote: These are general recommendations. Always tailor security controls")
            print("to your specific environment and compliance requirements.")
        else:
            print("\nNo vulnerabilities found. However, consider these general security recommendations:")

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Run comprehensive RDP security tests')
    
    # Target specification (mutually exclusive with --targets-file)
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('target', nargs='?', help='Single target RDP server IP or hostname')
    target_group.add_argument('--targets-file', help='File containing list of targets (CSV or JSON)')
    
    # Common options
    parser.add_argument('-p', '--port', type=int, default=3389, help='RDP port (default: 3389)')
    parser.add_argument('-u', '--username', help='Username for authentication tests')
    parser.add_argument('-P', '--password', help='Password for authentication tests')
    parser.add_argument('-o', '--output', default='reports', help='Output directory for reports (default: reports)')
    parser.add_argument('--skip-tests', nargs='+', default=[], help='Tests to skip')
    parser.add_argument('--burp-host', help='Burp Suite host (for integration tests)')
    parser.add_argument('--burp-port', type=int, default=8080, help='Burp Suite port (default: 8080)')
    parser.add_argument('--rate-limit-delay', type=float, default=1.0, help='Delay between requests in seconds')
    parser.add_argument('--timing-threshold', type=float, default=0.5, help='Timing threshold in seconds')
    parser.add_argument('--no-html', action='store_true', help='Disable HTML report generation')
    parser.add_argument('--no-summary', action='store_true', help='Disable summary report generation for multiple targets')
    parser.add_argument('--parallel', type=int, default=1, help='Number of parallel scans (default: 1)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    return parser.parse_args()

def load_targets_from_file(file_path: str) -> List[dict]:
    """Load targets from a CSV or JSON file"""
    if not os.path.exists(file_path):
        logger.error(f"Targets file not found: {file_path}")
        return []
    
    try:
        if file_path.lower().endswith('.json'):
            with open(file_path, 'r') as f:
                targets = json.load(f)
                if isinstance(targets, dict):
                    return [targets]  # Single target in JSON object
                return targets  # List of targets
        else:  # Assume CSV
            import csv
            targets = []
            with open(file_path, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    targets.append({k: v for k, v in row.items() if v})  # Remove empty values
            return targets
    except Exception as e:
        logger.error(f"Error loading targets file: {e}")
        return []

def generate_summary_report(report_paths: List[str], output_dir: str) -> Tuple[str, str]:
    """Generate a summary report from multiple scan reports"""
    if not report_paths:
        return None, None
    
    summary_data = {
        'generated_at': datetime.utcnow().isoformat(),
        'total_scans': len(report_paths),
        'targets': [],
        'summary': {
            'total_vulnerabilities': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'tests_run': 0,
            'tests_passed': 0,
            'tests_failed': 0
        }
    }
    
    # Process each report
    for report_path in report_paths:
        try:
            with open(report_path, 'r') as f:
                report = json.load(f)
                
            # Extract relevant data
            target_info = {
                'target': report['metadata']['target'],
                'port': report['metadata'].get('port', 3389),
                'start_time': report['metadata']['start_time'],
                'end_time': report['metadata']['end_time'],
                'report_path': os.path.basename(report_path),
                'html_report': os.path.splitext(os.path.basename(report_path))[0] + '.html',
                'vulnerabilities': len(report.get('vulnerabilities', [])),
                'critical': report['summary'].get('critical_vulnerabilities', 0),
                'high': report['summary'].get('high_vulnerabilities', 0),
                'medium': report['summary'].get('medium_vulnerabilities', 0),
                'low': report['summary'].get('low_vulnerabilities', 0),
                'tests_run': report['summary'].get('tests_run', 0),
                'tests_passed': report['summary'].get('tests_passed', 0),
                'tests_failed': report['summary'].get('tests_failed', 0)
            }
            
            # Update summary
            summary_data['targets'].append(target_info)
            summary_data['summary']['total_vulnerabilities'] += target_info['vulnerabilities']
            summary_data['summary']['critical'] += target_info['critical']
            summary_data['summary']['high'] += target_info['high']
            summary_data['summary']['medium'] += target_info['medium']
            summary_data['summary']['low'] += target_info['low']
            summary_data['summary']['tests_run'] += target_info['tests_run']
            summary_data['summary']['tests_passed'] += target_info['tests_passed']
            summary_data['summary']['tests_failed'] += target_info['tests_failed']
            
        except Exception as e:
            logger.error(f"Error processing report {report_path}: {e}")
    
    # Generate summary report
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    json_path = os.path.join(output_dir, f'rdp_scan_summary_{timestamp}.json')
    html_path = os.path.join(output_dir, f'rdp_scan_summary_{timestamp}.html')
    
    # Save JSON summary
    with open(json_path, 'w') as f:
        json.dump(summary_data, f, indent=2)
    
    # Generate HTML summary if possible
    try:
        from enhanced_html_report import generate_summary_html
        generate_summary_html(summary_data, html_path)
        logger.info(f"Generated summary report: {html_path}")
    except Exception as e:
        logger.error(f"Failed to generate HTML summary: {e}")
        html_path = None
    
    return json_path, html_path

def process_single_target(target: str, port: int, username: str, password: str, 
                         output_dir: str, no_html: bool, **kwargs) -> Tuple[str, str]:
    """Process a single target and return report paths"""
    try:
        tester = RDPComprehensiveTester(
            target=target,
            port=port,
            username=username,
            password=password,
            output_dir=output_dir
        )
        
        # Run tests and generate reports
        json_report, html_report = tester.run_all_tests()
        
        # Generate HTML report unless disabled
        if not no_html and json_report:
            try:
                from enhanced_html_report import generate_html_report
                html_report = os.path.splitext(json_report)[0] + '.html'
                generate_html_report(json_report, html_report)
                logger.info(f"HTML report generated: {html_report}")
            except Exception as e:
                logger.error(f"Failed to generate HTML report: {e}")
        
        return json_report, html_report
    except Exception as e:
        logger.error(f"Error processing target {target}: {e}", exc_info=True)
        return None, None

def main():
    """Main function"""
    args = parse_args()
    
    # Set log level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    try:
        report_paths = []
        
        # Process single target or targets file
        if args.target:
            # Single target mode
            json_report, _ = process_single_target(
                target=args.target,
                port=args.port,
                username=args.username,
                password=args.password,
                output_dir=args.output,
                no_html=args.no_html
            )
            if json_report:
                report_paths.append(json_report)
        else:
            # Multiple targets from file
            targets = load_targets_from_file(args.targets_file)
            if not targets:
                logger.error("No valid targets found in the targets file")
                return 1
                
            logger.info(f"Loaded {len(targets)} targets from {args.targets_file}")
            
            # Process targets sequentially or in parallel
            if args.parallel <= 1:
                # Sequential processing
                for target_info in targets:
                    json_report, _ = process_single_target(
                        target=target_info.get('target', target_info.get('host', '')),
                        port=target_info.get('port', args.port),
                        username=target_info.get('username', args.username),
                        password=target_info.get('password', args.password),
                        output_dir=args.output,
                        no_html=args.no_html
                    )
                    if json_report:
                        report_paths.append(json_report)
            else:
                # Parallel processing
                from concurrent.futures import ThreadPoolExecutor, as_completed
                
                with ThreadPoolExecutor(max_workers=args.parallel) as executor:
                    future_to_target = {}
                    for target_info in targets:
                        future = executor.submit(
                            process_single_target,
                            target=target_info.get('target', target_info.get('host', '')),
                            port=target_info.get('port', args.port),
                            username=target_info.get('username', args.username),
                            password=target_info.get('password', args.password),
                            output_dir=args.output,
                            no_html=args.no_html
                        )
                        future_to_target[future] = target_info.get('target', 'unknown')
                    
                    for future in as_completed(future_to_target):
                        target = future_to_target[future]
                        try:
                            json_report, _ = future.result()
                            if json_report:
                                report_paths.append(json_report)
                        except Exception as e:
                            logger.error(f"Error processing target {target}: {e}")
            
            # Generate summary report for multiple targets
            if len(report_paths) > 1 and not args.no_summary:
                json_summary, html_summary = generate_summary_report(report_paths, args.output)
                if json_summary:
                    logger.info(f"Generated summary report: {json_summary}")
                if html_summary:
                    logger.info(f"Generated HTML summary: {html_summary}")
        
        return 0 if report_paths else 1
    
    except KeyboardInterrupt:
        logger.info("Testing interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Fatal error during testing: {e}", exc_info=args.verbose)
        return 1

if __name__ == "__main__":
    sys.exit(main())
