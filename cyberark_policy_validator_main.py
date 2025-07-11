#!/usr/bin/env python3
"""
CyberRDP Audit Suite - Policy Validation Module
Validates RDP configurations against security policies and compliance requirements.

Part of the CyberRDP Audit Suite for comprehensive RDP security assessment.

Usage:
  python cyberark_policy_validator_main.py [target] --policy [policy_file] --username [username] --password [password]
"""

import os
import sys
import json
import time
import logging
import argparse
import winrm
from datetime import datetime
from typing import Dict, List, Any, Optional

# Import validator components
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from cyberark_policy_validator import CyberRDPPolicyValidator as PolicyValidator
import cyberark_policy_auth_validator as auth_validator
import cyberark_policy_redirection_validator as redirect_validator
import cyberark_policy_session_validator as session_validator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('cyberark_policy_validation.log')
    ]
)
logger = logging.getLogger(__name__)


class CyberRDPPolicyValidator(PolicyValidator):
    """
    CyberRDP Audit Suite - Policy Validation Engine
    
    Validates RDP configurations against security policies and compliance requirements.
    Part of the CyberRDP Audit Suite for comprehensive RDP security assessment.
    """
    
    def __init__(self, target: str, port: int = 3389, username: str = None,
                 password: str = None, domain: str = "", policy_file: str = None,
                 verbose: bool = False):
        """Initialize the full policy validator with all components"""
        super().__init__(target, port, username, password, domain, policy_file, verbose)
        
    def establish_winrm_session(self):
        """Establish a WinRM session to the target
        
        Returns:
            winrm.Session: WinRM session object
        """
        logger.info(f"Establishing WinRM connection to {self.target}")
        
        try:
            session = winrm.Session(
                f'http://{self.target}:5985/wsman',
                auth=(f"{self.domain}\\{self.username}" 
                      if self.domain else self.username, 
                     self.password)
            )
            
            # Test the connection
            ps_script = "Write-Output 'WinRM connection successful'"
            result = session.run_ps(ps_script)
            if result.status_code == 0:
                logger.info("WinRM connection established successfully")
                return session
            else:
                logger.error(f"WinRM connection failed with status code: {result.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Error establishing WinRM connection: {e}")
            return None
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all policy validation tests
        
        Returns:
            Dict: Comprehensive test results
        """
        logger.info(f"Running all CyberArk PAPM policy validation tests on {self.target}")
        
        if not self.username or not self.password:
            logger.warning("Credentials required for policy validation")
            self.results['compliant'] = False
            self.results['violations'].append({
                'severity': 'error',
                'description': 'No credentials provided for policy validation',
                'remediation': 'Provide valid credentials with administrative access'
            })
            return self.results
            
        # Establish WinRM session
        session = self.establish_winrm_session()
        if not session:
            logger.error("Failed to establish WinRM connection, tests cannot proceed")
            self.results['compliant'] = False
            self.results['violations'].append({
                'severity': 'error',
                'description': 'Failed to establish WinRM connection',
                'remediation': 'Ensure WinRM is properly configured and accessible'
            })
            return self.results
            
        test_results = {}
        
        try:
            # 1. Validate encryption level
            encryption_result = self.validate_encryption_level()
            test_results['encryption'] = encryption_result
            
            # 2. Validate authentication settings
            auth_results = {
                'nla': auth_validator.validate_nla_requirement(
                    session, self.target, self.policies.get('nla_required', True)),
                'restricted_admin': auth_validator.validate_restricted_admin_mode(
                    session, self.target, self.policies.get('rdp_restricted_admin', True)),
                'certificate': auth_validator.validate_certificate_validation(
                    session, self.target, self.policies.get('certificate_validation', True)),
                'cyberark_integration': auth_validator.check_cyberark_auth_integration(
                    session, self.target)
            }
            test_results['authentication'] = auth_results
            
            # 3. Validate redirection settings
            redirect_results = redirect_validator.validate_all_redirections(
                session, self.target, self.policies)
            test_results['redirection'] = redirect_results
            
            # 4. Validate session security settings
            session_results = session_validator.validate_session_security(
                session, self.target, self.policies)
            test_results['session_security'] = session_results
            
            # Store all test results
            self.results['tests'] = test_results
            
            # Compile violations and statistics
            self._compile_results(test_results)
            
            logger.info(f"Policy validation completed for {self.target}")
            
        except Exception as e:
            logger.error(f"Error running policy validation tests: {e}")
            self.results['compliant'] = False
            self.results['violations'].append({
                'severity': 'error',
                'description': f'Error running policy validation: {str(e)}',
                'remediation': 'Check the logs for more details'
            })
            
        return self.results
    
    def _compile_results(self, test_results: Dict[str, Any]) -> None:
        """Compile violations and statistics from test results
        
        Args:
            test_results: Dictionary of test results
        """
        all_tests_passed = True
        violations = []
        recommendations = set()
        tests_run = 0
        tests_passed = 0
        tests_failed = 0
        
        # Process direct tests
        for test_name, result in test_results.items():
            if isinstance(result, dict) and 'status' in result:
                tests_run += 1
                if result['status'] == 'passed':
                    tests_passed += 1
                elif result['status'] in ['failed', 'error']:
                    tests_failed += 1
                    all_tests_passed = False
                
                if 'violations' in result and result['violations']:
                    violations.extend(result['violations'])
                    for violation in result['violations']:
                        if 'remediation' in violation:
                            recommendations.add(violation['remediation'])
            
            # Process nested test dictionaries
            elif isinstance(result, dict):
                for subtest_name, subresult in result.items():
                    if isinstance(subresult, dict) and 'status' in subresult:
                        tests_run += 1
                        if subresult['status'] == 'passed':
                            tests_passed += 1
                        elif subresult['status'] in ['failed', 'error']:
                            tests_failed += 1
                            all_tests_passed = False
                        
                        if 'violations' in subresult and subresult['violations']:
                            violations.extend(subresult['violations'])
                            for violation in subresult['violations']:
                                if 'remediation' in violation:
                                    recommendations.add(violation['remediation'])
        
        # Update results
        self.results['compliant'] = all_tests_passed
        self.results['violations'] = violations
        self.results['recommendations'] = list(recommendations)
        
        # Add summary stats
        self.results['summary'] = {
            'tests_run': tests_run,
            'tests_passed': tests_passed,
            'tests_failed': tests_failed,
            'violations_found': len(violations),
            'compliant': all_tests_passed
        }
        
        self.tests_run = tests_run
        self.tests_passed = tests_passed
        self.tests_failed = tests_failed
    
    def generate_report(self, output_file: str = None) -> Dict[str, Any]:
        """Generate a JSON report with test results
        
        Args:
            output_file: Optional path to write JSON report
            
        Returns:
            Dict: Complete test results
        """
        # If we haven't run tests yet, do so
        if 'summary' not in self.results:
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
    
    def print_report_summary(self):
        """Print a summary of the validation results to the console"""
        if 'summary' not in self.results:
            logger.warning("No test results available to print")
            return
        
        print("\n" + "="*80)
        print(" CyberArk PAPM RDP Policy Validation Report")
        print(f" Target: {self.target}:{self.port}")
        print(f" Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*80 + "\n")
        
        summary = self.results['summary']
        compliant = self.results.get('compliant', False)
        
        print(f"Policy Compliance: {'✓ COMPLIANT' if compliant else '✗ NON-COMPLIANT'}")
        print(f"Tests Run: {summary['tests_run']}")
        print(f"Tests Passed: {summary['tests_passed']}")
        print(f"Tests Failed: {summary['tests_failed']}")
        print(f"Violations Found: {summary['violations_found']}")
        
        if self.results.get('violations'):
            print("\nPolicy Violations:")
            
            # Group violations by severity
            severity_violations = {
                'critical': [],
                'high': [],
                'medium': [],
                'low': []
            }
            
            for i, violation in enumerate(self.results['violations'], 1):
                severity = violation.get('severity', 'medium')
                severity_violations[severity].append(violation)
            
            # Print violations by severity (highest first)
            for severity in ['critical', 'high', 'medium', 'low']:
                if severity_violations[severity]:
                    print(f"\n{severity.upper()} Severity Violations:")
                    for i, violation in enumerate(severity_violations[severity], 1):
                        policy = violation.get('policy', 'unknown')
                        expected = violation.get('expected', 'unknown')
                        actual = violation.get('actual', 'unknown')
                        description = violation.get('description', 'No description')
                        
                        print(f"  {i}. [{policy}] {description}")
                        print(f"     Expected: {expected}, Actual: {actual}")
            
        if self.results.get('recommendations'):
            print("\nRemediation Recommendations:")
            for i, rec in enumerate(self.results['recommendations'], 1):
                print(f"  {i}. {rec}")
                
        print(f"\nFull report {'saved to ' + self.results.get('report_file', 'JSON report') if 'report_file' in self.results else 'available in JSON format'}")
        print("\n" + "="*80)


def parse_args():
    """Parse command line arguments
    
    Returns:
        argparse.Namespace: Parsed command-line arguments
    """
    # Create argument parser
    parser = argparse.ArgumentParser(
        description='CyberRDP Audit Suite - Policy Validation Module',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Add command line arguments
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--port', type=int, default=3389, help='RDP port (default: 3389)')
    parser.add_argument('-u', '--username', help='Username for authentication')
    parser.add_argument('-P', '--password', help='Password for authentication')
    parser.add_argument('-d', '--domain', default='', help='Domain for authentication')
    parser.add_argument('-f', '--policy-file', help='Path to policy file (JSON/XML)')
    parser.add_argument('-o', '--output', help='Output file for JSON report')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    # Add examples to help text
    parser.epilog = '''
Examples:
  python cyberark_policy_validator_main.py 192.168.1.100 -u admin -p password
  python cyberark_policy_validator_main.py server.example.com -u domain\\user -p password -P policy.json
  
Policy files can be in JSON or XML format and should contain security policy settings.
If no policy file is provided, default security policies will be used.

Part of the CyberRDP Audit Suite - Comprehensive RDP Security Assessment Tool
'''
    
    return parser.parse_args()


def main():
    """Main function to run CyberRDP Audit Suite policy validation"""
    # Parse arguments
    args = parse_args()
    
    # Set up logging verbosity
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Banner
    print("="*80)
    print(" CyberRDP Audit Suite - Policy Validation Module")
    print(f" Target: {args.target}:{args.port}")
    print("="*80)
    print()
    
    try:
        # Initialize validator
        validator = CyberArkPolicyValidatorRunner(
            target=args.target,
            port=args.port,
            username=args.username,
            password=args.password,
            domain=args.domain,
            policy_file=args.policy_file,
            verbose=args.verbose
        )
        
        # Run all tests
        results = validator.run_all_tests()
        
        # Generate report
        output_file = args.output
        if not output_file:
            # Create default output filename if not specified
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"cyberark_policy_validation_{args.target}_{timestamp}.json"
            
        validator.generate_report(output_file)
        validator.results['report_file'] = output_file
        
        # Print summary
        validator.print_report_summary()
        
        # Return status code based on compliance
        return 0 if results.get('compliant', False) else 1
    
    except KeyboardInterrupt:
        logger.warning("Validation interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Error running policy validation: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
