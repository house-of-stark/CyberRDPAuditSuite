#!/usr/bin/env python3
"""
RDP Session Hijack Tester Integration Module
This module integrates the RDP Session Hijack Tester with the comprehensive test runner.
"""

import os
import sys
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

# Add your modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from rdp_session_hijack_tester import RDPSessionHijackTester

class SessionHijackTesterIntegration:
    """Integration class for the RDP Session Hijack Tester"""
    
    def __init__(self, test_runner):
        """Initialize the integration module
        
        Args:
            test_runner: Comprehensive test runner instance
        """
        self.test_runner = test_runner
        self.logger = logging.getLogger(__name__)
        
    def run_session_hijack_tests(self, target: str, port: int = 3389, 
                                username: str = None, password: str = None,
                                domain: str = None) -> Dict[str, Any]:
        """Run RDP session hijack tests
        
        Args:
            target: Target IP address or hostname
            port: Target RDP port
            username: Username for authentication
            password: Password for authentication
            domain: Domain for authentication
            
        Returns:
            Dict: Test results
        """
        self.logger.info(f"Running RDP session hijack tests on {target}:{port}")
        
        try:
            # Create tester instance
            tester = RDPSessionHijackTester(
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
            
            output_file = os.path.join(output_dir, f"rdp_session_hijack_{target}_{timestamp}.json")
            tester.generate_report(output_file)
            
            # Append report details
            results['report_file'] = output_file
            
            # Add to comprehensive test results
            if hasattr(self.test_runner, 'results'):
                if 'session_hijack' not in self.test_runner.results:
                    self.test_runner.results['session_hijack'] = {}
                    
                self.test_runner.results['session_hijack'][target] = {
                    'timestamp': timestamp,
                    'vulnerable': results.get('vulnerable_to_hijacking', False),
                    'report_file': output_file,
                    'summary': results.get('summary', {})
                }
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error running session hijack tests: {e}", exc_info=True)
            return {
                'vulnerable_to_hijacking': True,  # Assume vulnerable on error
                'errors': [str(e)],
                'status': 'error'
            }
    
    def integrate_with_test_runner(self):
        """Integrate the tester with the test runner
        
        This adds the necessary methods to the test runner instance
        """
        def run_session_hijack_tests(self, target, port=3389, 
                                    username=None, password=None, 
                                    domain=None):
            """Method to be added to the test runner"""
            integration = SessionHijackTesterIntegration(self)
            return integration.run_session_hijack_tests(
                target, port, username, password, domain
            )
            
        # Add method to test runner (if it doesn't already exist)
        if not hasattr(self.test_runner, 'run_session_hijack_tests'):
            self.test_runner.run_session_hijack_tests = run_session_hijack_tests.__get__(self.test_runner)


def integrate_with_test_runner(test_runner):
    """Function to integrate the tester with a test runner instance
    
    Args:
        test_runner: Test runner instance to integrate with
    """
    integration = SessionHijackTesterIntegration(test_runner)
    integration.integrate_with_test_runner()
    return integration


if __name__ == "__main__":
    print("RDP Session Hijack Tester Integration Module")
    print("This module should be imported and used by the comprehensive test runner")
