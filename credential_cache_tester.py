#!/usr/bin/env python3
"""
RDP Credential Caching Tester
Tests for credential caching vulnerabilities in RDP implementations.
"""

import os
import sys
import json
import logging
import platform
import tempfile
import shutil
import winreg
import ctypes
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Union, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('rdp_credential_cache_test.log')
    ]
)
logger = logging.getLogger('CredentialCacheTester')

class CredentialCacheTester:
    """Tests for credential caching vulnerabilities in RDP implementations."""
    
    def __init__(self, target: str, port: int = 3389, username: str = None,
                 password: str = None, domain: str = None, verbose: bool = False):
        """Initialize the credential cache tester.
        
        Args:
            target: Target hostname or IP
            port: RDP port
            username: Username for authentication
            password: Password for authentication
            domain: Domain for authentication
            verbose: Enable verbose output
        """
        self.target = target
        self.port = port
        self.username = username
        self.password = password
        self.domain = domain
        self.verbose = verbose
        
        # Set up result structure
        self.results = {
            'target': target,
            'port': port,
            'timestamp': datetime.now().isoformat(),
            'tests': {},
            'vulnerable_to_credential_caching': False,
            'findings': [],
            'recommendations': []
        }
        
        # Track test statistics
        self.tests_run = 0
        self.tests_passed = 0
        self.tests_failed = 0
        
        if verbose:
            logger.setLevel(logging.DEBUG)
            
        logger.info(f"Initialized Credential Cache Tester for {target}:{port}")
    
    def _add_finding(self, test_name: str, status: str, details: str, 
                    severity: str = 'medium') -> None:
        """Add a test finding to the results.
        
        Args:
            test_name: Name of the test
            status: Test status (passed/failed/warning)
            details: Detailed findings
            severity: Severity level (info/low/medium/high/critical)
        """
        finding = {
            'test': test_name,
            'status': status,
            'severity': severity,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }
        self.results['findings'].append(finding)
        
        if status == 'failed':
            self.results['vulnerable_to_credential_caching'] = True
            
        logger.info(f"{test_name}: {status.upper()} - {details}")
    
    def test_credential_caching_enabled(self) -> Dict[str, Any]:
        """Test if credential caching is enabled on the system."""
        logger.info("Testing if credential caching is enabled...")
        
        result = {
            'test': 'credential_caching_enabled',
            'description': 'Checks if credential caching is enabled on the target system',
            'status': 'unknown',
            'findings': [],
            'recommendations': []
        }
        
        try:
            if platform.system() == 'Windows':
                # Check registry for credential caching settings
                key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
                value_name = "CachedLogonsCount"
                
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ) as key:
                        cached_count = winreg.QueryValueEx(key, value_name)[0]
                        if cached_count > 0:
                            msg = f"Credential caching is enabled with {cached_count} cached logons"
                            result['findings'].append(msg)
                            result['recommendations'].append(
                                "Disable credential caching by setting 'CachedLogonsCount' to 0 in "
                                "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
                            )
                            result['status'] = 'failed'
                            self._add_finding(
                                'Credential Caching Check', 'failed',
                                msg, 'high'
                            )
                        else:
                            result['status'] = 'passed'
                            self._add_finding(
                                'Credential Caching Check', 'passed',
                                "Credential caching is disabled", 'info'
                            )
                except WindowsError:
                    # Key or value doesn't exist, which is good
                    result['status'] = 'passed'
                    self._add_finding(
                        'Credential Caching Check', 'passed',
                        "Credential caching is not configured (default is enabled)", 'info'
                    )
            else:
                # For non-Windows systems, check common RDP client configs
                result['status'] = 'warning'
                self._add_finding(
                    'Credential Caching Check', 'warning',
                    "Credential caching check not implemented for non-Windows systems", 'medium'
                )
                
        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)
            logger.error(f"Error in test_credential_caching_enabled: {str(e)}")
            self._add_finding(
                'Credential Caching Check', 'error',
                f"Error checking credential caching: {str(e)}", 'high'
            )
        
        self.results['tests']['credential_caching_enabled'] = result
        self._update_test_stats(result['status'])
        return result
    
    def test_cached_credential_storage(self) -> Dict[str, Any]:
        """Test for cached credential storage locations."""
        logger.info("Checking for cached credential storage...")
        
        result = {
            'test': 'cached_credential_storage',
            'description': 'Checks for cached credentials in common storage locations',
            'status': 'unknown',
            'findings': [],
            'recommendations': []
        }
        
        try:
            if platform.system() == 'Windows':
                # Check common credential storage locations
                cred_dirs = [
                    os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32', 'config', 'systemprofile', 'AppData', 'Local', 'Microsoft', 'Credentials'),
                    os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Credentials'),
                    os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Microsoft', 'Credentials')
                ]
                
                found_creds = []
                for cred_dir in cred_dirs:
                    if os.path.exists(cred_dir):
                        try:
                            files = os.listdir(cred_dir)
                            if files:
                                found_creds.append(f"{len(files)} files in {cred_dir}")
                        except (OSError, PermissionError) as e:
                            logger.debug(f"Could not access {cred_dir}: {str(e)}")
                            continue
                
                if found_creds:
                    msg = f"Potential credential storage found: {', '.join(found_creds)}"
                    result['findings'].append(msg)
                    result['recommendations'].append(
                        "Review and secure credential storage locations. Consider using Credential Manager "
                        "with appropriate security controls."
                    )
                    result['status'] = 'warning'
                    self._add_finding(
                        'Credential Storage Check', 'warning',
                        msg, 'medium'
                    )
                else:
                    result['status'] = 'passed'
                    self._add_finding(
                        'Credential Storage Check', 'passed',
                        "No obvious credential storage locations found", 'info'
                    )
            else:
                # For non-Windows systems
                result['status'] = 'warning'
                self._add_finding(
                    'Credential Storage Check', 'warning',
                    "Credential storage check not fully implemented for non-Windows systems", 'medium'
                )
                
        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)
            logger.error(f"Error in test_cached_credential_storage: {str(e)}")
            self._add_finding(
                'Credential Storage Check', 'error',
                f"Error checking credential storage: {str(e)}", 'high'
            )
        
        self.results['tests']['cached_credential_storage'] = result
        self._update_test_stats(result['status'])
        return result
    
    def _update_test_stats(self, status: str) -> None:
        """Update test statistics."""
        self.tests_run += 1
        if status == 'passed':
            self.tests_passed += 1
        elif status in ['failed', 'error']:
            self.tests_failed += 1
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all credential caching tests.
        
        Returns:
            Dict containing test results
        """
        logger.info("Starting credential caching tests...")
        
        # Run individual tests
        self.test_credential_caching_enabled()
        self.test_cached_credential_storage()
        
        # Update overall results
        self.results['summary'] = {
            'total_tests': self.tests_run,
            'tests_passed': self.tests_passed,
            'tests_failed': self.tests_failed,
            'tests_warning': self.tests_run - (self.tests_passed + self.tests_failed)
        }
        
        logger.info("Credential caching tests completed.")
        return self.results
    
    def save_results(self, output_file: str = None) -> str:
        """Save test results to a file.
        
        Args:
            output_file: Path to save the results (optional)
            
        Returns:
            Path to the saved results file
        """
        if not output_file:
            output_file = f"credential_cache_test_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2)
            logger.info(f"Results saved to {output_file}")
            return output_file
        except Exception as e:
            logger.error(f"Failed to save results: {str(e)}")
            raise


def main():
    """Main function for command-line usage."""
    parser = argparse.ArgumentParser(description='Test for RDP credential caching vulnerabilities')
    parser.add_argument('target', help='Target hostname or IP address')
    parser.add_argument('-p', '--port', type=int, default=3389, help='RDP port (default: 3389)')
    parser.add_argument('-u', '--username', help='Username for authentication')
    parser.add_argument('-P', '--password', help='Password for authentication')
    parser.add_argument('-d', '--domain', help='Domain for authentication')
    parser.add_argument('-o', '--output', help='Output file for test results (JSON)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    try:
        tester = CredentialCacheTester(
            target=args.target,
            port=args.port,
            username=args.username,
            password=args.password,
            domain=args.domain,
            verbose=args.verbose
        )
        
        results = tester.run_all_tests()
        output_file = tester.save_results(args.output)
        
        # Print summary
        print("\n=== Test Summary ===")
        print(f"Target: {args.target}:{args.port}")
        print(f"Tests Run: {results['summary']['total_tests']}")
        print(f"Passed: {results['summary']['tests_passed']}")
        print(f"Failed: {results['summary']['tests_failed']}")
        print(f"Warnings: {results['summary']['tests_warning']}")
        
        if results['findings']:
            print("\n=== Findings ===")
            for finding in results['findings']:
                print(f"[{finding['severity'].upper()}] {finding['test']}: {finding['details']}")
        
        print(f"\nDetailed results saved to: {output_file}")
        
        return 0 if results['summary']['tests_failed'] == 0 else 1
        
    except Exception as e:
        logger.error(f"Error during testing: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
