#!/usr/bin/env python3
"""
Integration module for RDP Credential Cache Tester
This module integrates the RDP Credential Cache Tester with the comprehensive test runner.
"""

import sys
import os
import logging
from typing import Dict, Any, Optional

# Add the current directory to Python path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from credential_cache_tester import CredentialCacheTester
except ImportError as e:
    print(f"Error importing Credential Cache Tester: {e}")
    sys.exit(1)

logger = logging.getLogger(__name__)


def add_credential_cache_tester_to_runner(test_runner_class):
    """Add credential cache testing capabilities to the test runner
    
    Args:
        test_runner_class: The test runner class to enhance
    """
    
    def run_credential_cache_tests(self, target: str, port: int = 3389, 
                                 username: str = None, password: str = None, 
                                 domain: str = None, verbose: bool = False) -> Dict[str, Any]:
        """Run RDP credential cache tests
        
        Args:
            target: Target hostname or IP
            port: RDP port
            username: Username for authentication
            password: Password for authentication  
            domain: Domain for authentication
            verbose: Enable verbose output
            
        Returns:
            Dict containing test results
        """
        logger.info(f"Running RDP Credential Cache tests on {target}:{port}")
        
        try:
            # Create credential cache tester instance
            tester = CredentialCacheTester(
                target=target,
                port=port,
                username=username,
                password=password,
                domain=domain,
                verbose=verbose
            )
            
            # Run all credential cache tests
            results = tester.run_all_tests()
            
            # Store results in the comprehensive test runner
            if not hasattr(self, 'credential_cache_results'):
                self.credential_cache_results = {}
            
            self.credential_cache_results[f"{target}:{port}"] = results
            
            # Log summary
            if results.get('vulnerable_to_credential_caching', False):
                logger.warning(f"VULNERABLE: {target}:{port} has credential caching vulnerabilities")
                
                # Log critical findings
                for finding in results.get('findings', []):
                    if 'high' in finding.get('severity', '').lower() or \
                       'critical' in finding.get('severity', '').lower():
                        logger.critical(f"Credential Cache Finding: {finding.get('details', 'No details')}")
            else:
                logger.info(f"SECURE: {target}:{port} appears secure against credential caching vulnerabilities")
            
            return results
            
        except Exception as e:
            logger.error(f"Error running credential cache tests on {target}:{port}: {e}")
            return {
                'target': target,
                'port': port,
                'error': str(e),
                'vulnerable_to_credential_caching': False,
                'tests': {},
                'findings': [f"Error running tests: {str(e)}"],
                'recommendations': ["Fix testing environment and retry"]
            }
    
    def generate_credential_cache_report(self, target: str = None, 
                                      output_file: str = None) -> Dict[str, Any]:
        """Generate credential cache test report
        
        Args:
            target: Specific target to report on (optional)
            output_file: Output file path (optional)
            
        Returns:
            Dict containing report data
        """
        if not hasattr(self, 'credential_cache_results'):
            logger.warning("No credential cache test results available")
            return {}
            
        if target and f"{target}:{self.port}" in self.credential_cache_results:
            results = self.credential_cache_results[f"{target}:{self.port}"]
        elif target and target in self.credential_cache_results:
            results = self.credential_cache_results[target]
        else:
            results = self.credential_cache_results
        
        # Generate summary
        report = {
            'report_type': 'credential_cache',
            'timestamp': results.get('timestamp', ''),
            'target': results.get('target', ''),
            'port': results.get('port', 3389),
            'vulnerable': results.get('vulnerable_to_credential_caching', False),
            'findings': results.get('findings', []),
            'recommendations': results.get('recommendations', []),
            'test_results': results.get('tests', {})
        }
        
        # Save to file if requested
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    import json
                    json.dump(report, f, indent=2)
                logger.info(f"Credential cache report saved to {output_file}")
            except Exception as e:
                logger.error(f"Failed to save credential cache report: {e}")
        
        return report
    
    # Add the new methods to the test runner class
    test_runner_class.run_credential_cache_tests = run_credential_cache_tests
    test_runner_class.generate_credential_cache_report = generate_credential_cache_report
    
    # Add a method to check if credential cache testing is available
    test_runner_class.has_credential_cache_tests = lambda self: True
    
    return test_runner_class


def main():
    """Test the integration module"""
    # This is just for testing the module directly
    class TestRunner:
        pass
    
    # Add credential cache testing to the test runner
    TestRunner = add_credential_cache_tester_to_runner(TestRunner)
    runner = TestRunner()
    
    # Example usage
    target = input("Enter target IP or hostname: ")
    port = int(input("Enter RDP port [3389]: ") or "3389")
    username = input("Username (optional): ") or None
    password = input("Password (optional): ") or None
    domain = input("Domain (optional): ") or None
    
    # Run tests
    results = runner.run_credential_cache_tests(
        target=target,
        port=port,
        username=username,
        password=password,
        domain=domain,
        verbose=True
    )
    
    # Generate report
    report = runner.generate_credential_cache_report()
    print("\n=== Credential Cache Test Report ===")
    print(f"Target: {report.get('target')}:{report.get('port')}")
    print(f"Vulnerable: {report.get('vulnerable', False)}")
    
    if report.get('findings'):
        print("\nFindings:")
        for finding in report.get('findings', []):
            print(f"- [{finding.get('severity', 'INFO').upper()}] {finding.get('details', 'No details')}")
    
    if report.get('recommendations'):
        print("\nRecommendations:")
        for rec in report.get('recommendations', []):
            print(f"- {rec}")


if __name__ == '__main__':
    import logging
    logging.basicConfig(level=logging.INFO)
    main()
