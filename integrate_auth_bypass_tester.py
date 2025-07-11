#!/usr/bin/env python3
"""
Integration module for RDP Authentication Bypass Tester
This module integrates the RDP Authentication Bypass Tester with the comprehensive test runner.
"""

import sys
import os
import logging
from typing import Dict, Any, Optional

# Add the current directory to Python path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from rdp_auth_bypass_tester import RDPAuthBypassTester
except ImportError as e:
    print(f"Error importing RDP Authentication Bypass Tester: {e}")
    sys.exit(1)

logger = logging.getLogger(__name__)


def add_auth_bypass_tester_to_runner(test_runner_class):
    """Add authentication bypass testing capabilities to the test runner
    
    Args:
        test_runner_class: The test runner class to enhance
    """
    
    def run_auth_bypass_tests(self, target: str, port: int = 3389, 
                             username: str = None, password: str = None, 
                             domain: str = None, verbose: bool = False) -> Dict[str, Any]:
        """Run RDP authentication bypass scenario tests
        
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
        logger.info(f"Running RDP Authentication Bypass tests on {target}:{port}")
        
        try:
            # Create auth bypass tester instance
            tester = RDPAuthBypassTester(
                target=target,
                port=port,
                username=username,
                password=password,
                domain=domain,
                verbose=verbose
            )
            
            # Run all authentication bypass tests
            results = tester.run_all_tests()
            
            # Store results in the comprehensive test runner
            if not hasattr(self, 'auth_bypass_results'):
                self.auth_bypass_results = {}
            
            self.auth_bypass_results[f"{target}:{port}"] = results
            
            # Log summary
            if results.get('vulnerable_to_auth_bypass', False):
                logger.warning(f"VULNERABLE: {target}:{port} is vulnerable to authentication bypass attacks")
                
                # Log critical findings
                for finding in results.get('findings', []):
                    if 'CRITICAL' in finding.upper() or 'VULNERABLE' in finding.upper():
                        logger.critical(f"Auth Bypass Finding: {finding}")
            else:
                logger.info(f"SECURE: {target}:{port} appears secure against authentication bypass attacks")
            
            return results
            
        except Exception as e:
            logger.error(f"Error running authentication bypass tests on {target}:{port}: {e}")
            return {
                'target': target,
                'port': port,
                'error': str(e),
                'vulnerable_to_auth_bypass': False,
                'tests': {},
                'findings': [f"Error running tests: {str(e)}"],
                'recommendations': ["Fix testing environment and retry"]
            }
    
    def generate_auth_bypass_report(self, target: str = None, 
                                  output_file: str = None) -> Dict[str, Any]:
        """Generate authentication bypass test report
        
        Args:
            target: Specific target to report on (optional)
            output_file: Output file path (optional)
            
        Returns:
            Dict containing the report
        """
        if not hasattr(self, 'auth_bypass_results'):
            return {'error': 'No authentication bypass test results available'}
        
        # Filter results by target if specified
        if target:
            filtered_results = {}
            for key, value in self.auth_bypass_results.items():
                if target in key:
                    filtered_results[key] = value
            results_to_report = filtered_results
        else:
            results_to_report = self.auth_bypass_results
        
        # Generate comprehensive report
        report = {
            'report_type': 'rdp_authentication_bypass_security_assessment',
            'timestamp': results_to_report.get(list(results_to_report.keys())[0], {}).get('timestamp', '') if results_to_report else '',
            'targets_tested': len(results_to_report),
            'vulnerable_targets': [],
            'secure_targets': [],
            'overall_findings': [],
            'critical_recommendations': [],
            'detailed_results': results_to_report
        }
        
        # Process results
        for target_key, result in results_to_report.items():
            if result.get('vulnerable_to_auth_bypass', False):
                report['vulnerable_targets'].append({
                    'target': target_key,
                    'findings': result.get('findings', []),
                    'recommendations': result.get('recommendations', [])
                })
                
                # Add to overall findings
                for finding in result.get('findings', []):
                    if finding not in report['overall_findings']:
                        report['overall_findings'].append(finding)
                        
                # Add to critical recommendations
                for rec in result.get('recommendations', []):
                    if rec not in report['critical_recommendations']:
                        report['critical_recommendations'].append(rec)
            else:
                report['secure_targets'].append(target_key)
        
        # Save to file if requested
        if output_file:
            try:
                import json
                with open(output_file, 'w') as f:
                    json.dump(report, f, indent=4)
                logger.info(f"Authentication bypass report saved to {output_file}")
            except Exception as e:
                logger.error(f"Error saving report to {output_file}: {e}")
        
        return report
    
    def print_auth_bypass_summary(self) -> None:
        """Print a summary of authentication bypass test results"""
        if not hasattr(self, 'auth_bypass_results'):
            print("No authentication bypass test results available")
            return
        
        print("\n" + "="*80)
        print("RDP AUTHENTICATION BYPASS SECURITY ASSESSMENT SUMMARY")
        print("="*80)
        
        vulnerable_count = 0
        secure_count = 0
        
        for target_key, result in self.auth_bypass_results.items():
            if result.get('vulnerable_to_auth_bypass', False):
                vulnerable_count += 1
                print(f"\n❌ VULNERABLE: {target_key}")
                
                # Print key findings
                findings = result.get('findings', [])
                critical_findings = [f for f in findings if 'CRITICAL' in f.upper() or 'VULNERABLE' in f.upper()]
                
                if critical_findings:
                    print("   Critical Issues:")
                    for finding in critical_findings[:3]:  # Show top 3
                        print(f"   • {finding}")
                        
                # Print key recommendations
                recommendations = result.get('recommendations', [])
                if recommendations:
                    print("   Priority Actions:")
                    for rec in recommendations[:2]:  # Show top 2
                        print(f"   • {rec}")
            else:
                secure_count += 1
                print(f"\n✅ SECURE: {target_key}")
        
        print(f"\n" + "-"*80)
        print(f"SUMMARY: {vulnerable_count} vulnerable, {secure_count} secure targets")
        
        if vulnerable_count > 0:
            print(f"⚠️  IMMEDIATE ACTION REQUIRED for {vulnerable_count} vulnerable target(s)")
        else:
            print("✅ All targets appear secure against authentication bypass attacks")
        print("="*80)
    
    # Add methods to the test runner class
    test_runner_class.run_auth_bypass_tests = run_auth_bypass_tests
    test_runner_class.generate_auth_bypass_report = generate_auth_bypass_report  
    test_runner_class.print_auth_bypass_summary = print_auth_bypass_summary
    
    return test_runner_class


def main():
    """Test the integration module"""
    print("RDP Authentication Bypass Tester Integration Module")
    print("This module integrates authentication bypass testing with the comprehensive test runner")
    
    # This would typically be called by the main test runner
    print("Integration functions ready for use by test runner")


if __name__ == '__main__':
    main()
