#!/usr/bin/env python3
"""
CyberArk Policy Validator Integration Module
This module integrates the CyberArk PAPM policy validator with the comprehensive test runner.
"""

import os
import sys
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

# Add your modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from cyberark_policy_validator_main import CyberArkPolicyValidatorRunner

class CyberArkPolicyValidatorIntegration:
    """Integration class for the CyberArk PAPM policy validator"""
    
    def __init__(self, test_runner):
        """Initialize the integration module
        
        Args:
            test_runner: Comprehensive test runner instance
        """
        self.test_runner = test_runner
        self.logger = logging.getLogger(__name__)
        
    def run_policy_validation(self, target: str, port: int = 3389, 
                             username: str = None, password: str = None,
                             domain: str = "", policy_file: str = None) -> Dict[str, Any]:
        """Run CyberArk PAPM policy validation
        
        Args:
            target: Target IP address or hostname
            port: Target RDP port
            username: Username for authentication
            password: Password for authentication
            domain: Domain for authentication
            policy_file: Path to policy file
            
        Returns:
            Dict: Test results
        """
        self.logger.info(f"Running CyberArk PAPM policy validation on {target}:{port}")
        
        try:
            # Create validator instance
            validator = CyberArkPolicyValidatorRunner(
                target=target,
                port=port,
                username=username,
                password=password,
                domain=domain,
                policy_file=policy_file,
                verbose=self.test_runner.verbose if hasattr(self.test_runner, 'verbose') else False
            )
            
            # Run tests
            results = validator.run_all_tests()
            
            # Generate report
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_dir = self.test_runner.output_dir if hasattr(self.test_runner, 'output_dir') else "reports"
            os.makedirs(output_dir, exist_ok=True)
            
            output_file = os.path.join(output_dir, f"cyberark_policy_{target}_{timestamp}.json")
            validator.generate_report(output_file)
            
            # Append report details
            results['report_file'] = output_file
            
            # Add to comprehensive test results
            if hasattr(self.test_runner, 'results'):
                if 'cyberark_policy' not in self.test_runner.results:
                    self.test_runner.results['cyberark_policy'] = {}
                    
                self.test_runner.results['cyberark_policy'][target] = {
                    'timestamp': timestamp,
                    'compliant': results.get('compliant', False),
                    'violations': len(results.get('violations', [])),
                    'report_file': output_file,
                    'summary': results.get('summary', {})
                }
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error running CyberArk PAPM policy validation: {e}", exc_info=True)
            return {
                'compliant': False,
                'errors': [str(e)],
                'status': 'error'
            }
    
    def integrate_with_test_runner(self):
        """Integrate the validator with the test runner
        
        This adds the necessary methods to the test runner instance
        """
        def run_cyberark_policy_validation(self, target, port=3389, 
                                          username=None, password=None, 
                                          domain="", policy_file=None):
            """Method to be added to the test runner"""
            validator = CyberArkPolicyValidatorIntegration(self)
            return validator.run_policy_validation(
                target, port, username, password, domain, policy_file
            )
            
        # Add method to test runner (if it doesn't already exist)
        if not hasattr(self.test_runner, 'run_cyberark_policy_validation'):
            self.test_runner.run_cyberark_policy_validation = run_cyberark_policy_validation.__get__(self.test_runner)


def integrate_with_test_runner(test_runner):
    """Function to integrate the validator with a test runner instance
    
    Args:
        test_runner: Test runner instance to integrate with
    """
    integration = CyberArkPolicyValidatorIntegration(test_runner)
    integration.integrate_with_test_runner()
    return integration


if __name__ == "__main__":
    print("CyberArk Policy Validator Integration Module")
    print("This module should be imported and used by the comprehensive test runner")
