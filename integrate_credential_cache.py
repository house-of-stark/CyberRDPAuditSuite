#!/usr/bin/env python3
"""
Credential Cache Tester Integration Module
This module integrates the Credential Cache Tester with the comprehensive test runner.
"""

import os
import sys
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

# Add your modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from credential_cache_tester import CredentialCacheTester

class CredentialCacheTesterIntegration:
    """Integration class for the Credential Cache Tester"""
    
    def __init__(self, test_runner):
        """Initialize the integration module
        
        Args:
            test_runner: Comprehensive test runner instance
        """
        self.test_runner = test_runner
        self.logger = logging.getLogger(__name__)
        
    def run_credential_cache_tests(self, target: str, port: int = 3389, 
                                 username: str = None, password: str = None,
                                 domain: str = "") -> Dict[str, Any]:
        """Run credential cache tests
        
        Args:
            target: Target IP address or hostname
            port: Target RDP port
            username: Username for authentication
            password: Password for authentication
            domain: Domain for authentication
            
        Returns:
            Dict: Test results
        """
        self.logger.info(f"Running Credential Cache tests on {target}:{port}")
        
        try:
            # Create tester instance
            tester = CredentialCacheTester(
                target=target,
                port=port,
                username=username,
                password=password,
                domain=domain,
                verbose=self.test_runner.verbose if hasattr(self.test_runner, 'verbose') else False
            )
            
            # Run all tests
            results = tester.run_all_tests()
            
            # Store results in test runner
            if not hasattr(self.test_runner, 'credential_cache_results'):
                self.test_runner.credential_cache_results = {}
                
            self.test_runner.credential_cache_results[f"{target}:{port}"] = results
            
            # Log summary
            if results.get('vulnerable_to_credential_caching', False):
                self.logger.warning(f"VULNERABLE: {target}:{port} has credential caching vulnerabilities")
                
                # Log critical findings
                for finding in results.get('findings', []):
                    if 'high' in finding.get('severity', '').lower() or \
                       'critical' in finding.get('severity', '').lower():
                        self.logger.critical(f"Credential Cache Finding: {finding.get('details', 'No details')}")
            else:
                self.logger.info(f"SECURE: {target}:{port} appears secure against credential caching vulnerabilities")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error running credential cache tests on {target}:{port}: {e}")
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
            Dict: Report data
        """
        if not hasattr(self.test_runner, 'credential_cache_results'):
            self.logger.warning("No credential cache test results available")
            return {}
            
        if target and f"{target}:{self.test_runner.port}" in self.test_runner.credential_cache_results:
            results = self.test_runner.credential_cache_results[f"{target}:{self.test_runner.port}"]
        elif target and target in self.test_runner.credential_cache_results:
            results = self.test_runner.credential_cache_results[target]
        else:
            results = self.test_runner.credential_cache_results
        
        # Generate summary
        report = {
            'report_type': 'credential_cache',
            'timestamp': results.get('timestamp', datetime.utcnow().isoformat()),
            'target': results.get('target', target or ''),
            'port': results.get('port', self.test_runner.port if hasattr(self.test_runner, 'port') else 3389),
            'vulnerable': results.get('vulnerable_to_credential_caching', False),
            'findings': results.get('findings', []),
            'recommendations': results.get('recommendations', []),
            'test_results': results.get('tests', {})
        }
        
        # Save to file if requested
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    json.dump(report, f, indent=2)
                self.logger.info(f"Credential cache report saved to {output_file}")
            except Exception as e:
                self.logger.error(f"Failed to save credential cache report: {e}")
        
        return report


def integrate_with_test_runner(test_runner):
    """Integrate the Credential Cache Tester with a test runner instance
    
    Args:
        test_runner: Test runner instance to integrate with
    """
    integration = CredentialCacheTesterIntegration(test_runner)
    
    # Add credential cache testing methods to the test runner
    test_runner.run_credential_cache_tests = integration.run_credential_cache_tests
    test_runner.generate_credential_cache_report = integration.generate_credential_cache_report
    
    # Add a method to check if credential cache testing is available
    test_runner.has_credential_cache_tests = lambda: True
    
    return test_runner


if __name__ == "__main__":
    print("Credential Cache Tester Integration Module")
    print("This module should be imported and used by the comprehensive test runner")
