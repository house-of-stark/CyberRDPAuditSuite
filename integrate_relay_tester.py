#!/usr/bin/env python3
"""
RDP Relay Attack Tester Integration Module
This module integrates the RDP Relay Attack Tester with the comprehensive test runner.
"""

import os
import sys
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

# Add your modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from rdp_relay_attack_tester import RDPRelayAttackTester

class RelayAttackTesterIntegration:
    """Integration class for the RDP Relay Attack Tester"""
    
    def __init__(self, test_runner):
        """Initialize the integration module
        
        Args:
            test_runner: Comprehensive test runner instance
        """
        self.test_runner = test_runner
        self.logger = logging.getLogger(__name__)
        
    def run_relay_attack_tests(self, target: str, port: int = 3389, 
                              username: str = None, password: str = None,
                              domain: str = None) -> Dict[str, Any]:
        """Run RDP relay attack tests
        
        Args:
            target: Target IP address or hostname
            port: Target RDP port
            username: Username for authentication
            password: Password for authentication
            domain: Domain for authentication
            
        Returns:
            Dict: Test results
        """
        self.logger.info(f"Running RDP relay attack tests on {target}:{port}")
        
        try:
            # Create tester instance
            tester = RDPRelayAttackTester(
                target=target,
                port=port,
                username=username,
                password=password,
                domain=domain,
                verbose=self.test_runner.verbose if hasattr(self.test_runner, 'verbose') else False
            )
            
            # Run tests
            results = tester.run_all_tests()
            
            # Generate report
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_dir = self.test_runner.output_dir if hasattr(self.test_runner, 'output_dir') else "reports"
            os.makedirs(output_dir, exist_ok=True)
            
            output_file = os.path.join(output_dir, f"rdp_relay_attack_{target}_{timestamp}.json")
            tester.generate_report(output_file)
            
            # Append report details
            results['report_file'] = output_file
            
            # Add to comprehensive test results
            if hasattr(self.test_runner, 'results'):
                if 'relay_attack' not in self.test_runner.results:
                    self.test_runner.results['relay_attack'] = {}
                    
                self.test_runner.results['relay_attack'][target] = {
                    'timestamp': timestamp,
                    'vulnerable': results.get('vulnerable_to_relay', False),
                    'report_file': output_file,
                    'summary': results.get('summary', {})
                }
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error running relay attack tests: {e}", exc_info=True)
            return {
                'vulnerable_to_relay': True,  # Assume vulnerable on error
                'errors': [str(e)],
                'status': 'error'
            }
    
    def integrate_with_test_runner(self):
        """Integrate the tester with the test runner
        
        This adds the necessary methods to the test runner instance
        """
        def run_relay_attack_tests(self, target, port=3389, 
                                  username=None, password=None, 
                                  domain=None):
            """Method to be added to the test runner"""
            integration = RelayAttackTesterIntegration(self)
            return integration.run_relay_attack_tests(
                target, port, username, password, domain
            )
            
        # Add method to test runner (if it doesn't already exist)
        if not hasattr(self.test_runner, 'run_relay_attack_tests'):
            self.test_runner.run_relay_attack_tests = run_relay_attack_tests.__get__(self.test_runner)


def integrate_with_test_runner(test_runner):
    """Function to integrate the tester with a test runner instance
    
    Args:
        test_runner: Test runner instance to integrate with
    """
    integration = RelayAttackTesterIntegration(test_runner)
    integration.integrate_with_test_runner()
    return integration


if __name__ == "__main__":
    print("RDP Relay Attack Tester Integration Module")
    print("This module should be imported and used by the comprehensive test runner")
