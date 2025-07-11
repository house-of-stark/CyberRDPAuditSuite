#!/usr/bin/env python3
"""
Shadow Session Security Tester Completer
This script completes the shadow_session_tester.py module by adding:
1. test_session_control_security method
2. run_all_tests method
3. generate_report method
4. Command-line interface

Instructions:
1. Copy the content of this file
2. Append it to the end of shadow_session_tester.py
"""

# The following code should be appended to shadow_session_tester.py:

    def test_session_control_security(self) -> Dict[str, Any]:
        """Test RDP session control security settings
        
        Returns:
            Dict: Test results with findings
        """
        logger.info("Testing RDP session control security...")
        self.tests_run += 1
        
        result = {
            'test': 'session_control_security',
            'status': 'unknown',
            'findings': [],
            'vulnerabilities': []
        }
        
        try:
            if not self.admin_username or not self.admin_password:
                logger.warning("Admin credentials required for session control security testing")
                result['status'] = 'skipped'
                result['findings'].append("No admin credentials provided for testing")
                return result
                
            # Connect to WinRM
            session = winrm.Session(f'http://{self.target}:5985/wsman',
                                    auth=(f"{self.admin_domain}\\{self.admin_username}" 
                                          if self.admin_domain else self.admin_username, 
                                         self.admin_password))
            
            # Check session control security settings
            ps_script = """# Check if RDP host has restrictions on who can shadow
                          $shadowGroups = Get-WmiObject -class "Win32_TSPermissionsSetting" -namespace "root\\cimv2\\TerminalServices" -ErrorAction SilentlyContinue | 
                                         Select-Object -ExpandProperty PermissionsSetting | Where-Object { $_.Permission -eq 8 }
                                         
                          if ($shadowGroups -and $shadowGroups.Count -gt 0) {
                              Write-Output "Shadow_Restricted"
                          } else {
                              Write-Output "Shadow_Unrestricted"
                          }
                          
                          # Check if RDP disconnection settings are secure
                          $disconnectTimeoutRegKey = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" -Name "MaxDisconnectionTime" -ErrorAction SilentlyContinue
                          if ($disconnectTimeoutRegKey -and $disconnectTimeoutRegKey.MaxDisconnectionTime -gt 0 -and $disconnectTimeoutRegKey.MaxDisconnectionTime -lt 5400000) {
                              # Less than 1.5 hours (in ms)
                              Write-Output "Disconnect_Timeout_Secure"
                          } else {
                              Write-Output "Disconnect_Timeout_Insecure"
                          }"""
                          
            result_data = session.run_ps(ps_script)
            control_lines = result_data.std_out.decode('utf-8').strip().split('\n')
            
            shadow_restricted = False
            disconnect_secure = False
            
            for line in control_lines:
                if "Shadow_Restricted" in line:
                    shadow_restricted = True
                    result['findings'].append("Shadow permissions are restricted to specific groups")
                elif "Shadow_Unrestricted" in line:
                    result['findings'].append("Shadow permissions are not restricted to specific groups")
                    
                if "Disconnect_Timeout_Secure" in line:
                    disconnect_secure = True
                    result['findings'].append("Disconnected session timeout is set securely")
                elif "Disconnect_Timeout_Insecure" in line:
                    result['findings'].append("Disconnected session timeout is not set or too long")
            
            # Evaluate overall session control security
            if shadow_restricted and disconnect_secure:
                result['status'] = 'passed'
            elif not shadow_restricted and not disconnect_secure:
                result['status'] = 'failed'
                result['vulnerabilities'].extend([
                    {
                        'severity': 'high',
                        'description': 'Shadow permissions not restricted to specific administrative groups',
                        'remediation': 'Configure shadow session permissions to restrict access to specific admin groups'
                    },
                    {
                        'severity': 'medium',
                        'description': 'Disconnected sessions do not have a proper timeout configured',
                        'remediation': 'Set MaxDisconnectionTime to a reasonable value (e.g., 1 hour = 3600000 ms)'
                    }
                ])
            else:
                result['status'] = 'warning'
                if not shadow_restricted:
                    result['vulnerabilities'].append({
                        'severity': 'high',
                        'description': 'Shadow permissions not restricted to specific administrative groups',
                        'remediation': 'Configure shadow session permissions to restrict access to specific admin groups'
                    })
                if not disconnect_secure:
                    result['vulnerabilities'].append({
                        'severity': 'medium',
                        'description': 'Disconnected sessions do not have a proper timeout configured',
                        'remediation': 'Set MaxDisconnectionTime to a reasonable value (e.g., 1 hour = 3600000 ms)'
                    })
            
        except Exception as e:
            logger.error(f"Error testing session control security: {e}")
            result['status'] = 'error'
            result['findings'].append(f"Error: {str(e)}")
        
        if result['status'] == 'passed':
            self.tests_passed += 1
        elif result['status'] in ['failed', 'error']:
            self.tests_failed += 1
            
        return result
        
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all shadow session security tests
        
        Returns:
            Dict: Report containing all test results
        """
        logger.info(f"Running all shadow session security tests on {self.target}...")
        
        # First, determine if shadow sessions are enabled
        shadow_enabled = self.detect_shadow_session_enabled()
        self.results['shadow_enabled'] = shadow_enabled
        
        # If shadow sessions are disabled, no need for further testing
        if shadow_enabled is False:
            logger.info("Shadow sessions are disabled, skipping further tests")
            self.results['recommendations'].append("Shadow sessions are disabled, which is the most secure configuration")
            return self.results
        
        # If shadow sessions are enabled or we couldn't determine, run all tests
        test_results = {
            'shadow_permissions': self.test_shadow_permissions(),
            'notification_settings': self.test_notification_settings(),
            'shadow_auditing': self.test_rdp_shadow_auditing(),
            'session_control': self.test_session_control_security()
        }
        
        # Add test results to the main results
        self.results['tests'] = test_results
        
        # Compile vulnerabilities and recommendations
        for test_name, test_result in test_results.items():
            if 'vulnerabilities' in test_result and test_result['vulnerabilities']:
                self.results['vulnerabilities'].extend(test_result['vulnerabilities'])
                
                # Add general recommendations based on vulnerabilities
                for vuln in test_result['vulnerabilities']:
                    if 'remediation' in vuln and vuln['remediation'] not in self.results['recommendations']:
                        self.results['recommendations'].append(vuln['remediation'])
        
        # Add summary stats
        self.results['summary'] = {
            'tests_run': self.tests_run,
            'tests_passed': self.tests_passed,
            'tests_failed': self.tests_failed,
            'vulnerabilities_found': len(self.results['vulnerabilities'])
        }
        
        # Add general recommendations if shadow sessions are enabled
        if shadow_enabled is True:
            self.results['recommendations'].append("Consider disabling shadow sessions if not required for administrative purposes")
            self.results['recommendations'].append("If shadow sessions are required, ensure they are restricted to specific admin groups and require user permission")
        
        logger.info(f"Shadow session security testing completed. "
                   f"Found {len(self.results['vulnerabilities'])} vulnerabilities")
                   
        return self.results
        
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


def parse_args():
    """Parse command line arguments
    
    Returns:
        argparse.Namespace: Parsed command-line arguments
    """
    parser = argparse.ArgumentParser(
        description='RDP Shadow Session Security Tester',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--port', type=int, default=3389,
                      help='RDP port (default: 3389)')
    parser.add_argument('-u', '--username', help='Username for authentication tests')
    parser.add_argument('-P', '--password', help='Password for authentication tests')
    parser.add_argument('-d', '--domain', default="",
                      help='Domain for authentication tests')
    parser.add_argument('-a', '--admin-username', help='Admin username for shadow tests')
    parser.add_argument('-A', '--admin-password', help='Admin password for shadow tests')
    parser.add_argument('-D', '--admin-domain', default="",
                      help='Admin domain for shadow tests')
    parser.add_argument('-o', '--output', help='Output file for JSON report')
    parser.add_argument('-v', '--verbose', action='store_true',
                      help='Enable verbose output')
    
    return parser.parse_args()


def main():
    """Main function to run shadow session security tests"""
    # Parse arguments
    args = parse_args()
    
    # Set up logging verbosity
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Banner
    print("="*80)
    print(" RDP Shadow Session Security Tester")
    print(f" Target: {args.target}:{args.port}")
    print("="*80)
    print()
    
    try:
        # Initialize tester
        tester = RDPShadowTester(
            target=args.target,
            port=args.port,
            username=args.username,
            password=args.password,
            domain=args.domain,
            admin_username=args.admin_username or args.username,
            admin_password=args.admin_password or args.password,
            admin_domain=args.admin_domain or args.domain,
            verbose=args.verbose
        )
        
        # Run all tests
        results = tester.run_all_tests()
        
        # Generate report
        output_file = args.output
        if not output_file:
            # Create default output filename if not specified
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"rdp_shadow_security_{args.target}_{timestamp}.json"
            
        tester.generate_report(output_file)
        
        # Print summary
        print("\nTest Summary:")
        print(f"Shadow Sessions Enabled: {results.get('shadow_enabled', 'Unknown')}")
        
        # Only show detailed results if shadow sessions are enabled
        if results.get('shadow_enabled') is not False:
            if 'summary' in results:
                print(f"Tests Run: {results['summary']['tests_run']}")
                print(f"Tests Passed: {results['summary']['tests_passed']}")
                print(f"Tests Failed: {results['summary']['tests_failed']}")
                print(f"Vulnerabilities Found: {results['summary']['vulnerabilities_found']}")
            
            if results.get('vulnerabilities'):
                print("\nVulnerabilities:")
                for i, vuln in enumerate(results['vulnerabilities'], 1):
                    print(f"  {i}. [{vuln.get('severity', 'Unknown')}] {vuln.get('description', 'Unknown vulnerability')}")
            
            if results.get('recommendations'):
                print("\nRecommendations:")
                for i, rec in enumerate(results['recommendations'], 1):
                    print(f"  {i}. {rec}")
        else:
            print("Shadow sessions are disabled on the target system - no vulnerabilities found.")
                
        print(f"\nFull report saved to: {output_file}")
        return 0
    
    except KeyboardInterrupt:
        logger.warning("Test interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Error running shadow session tests: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
