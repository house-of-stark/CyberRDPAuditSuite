#!/usr/bin/env python3
"""
Test runner for CyberRDP Audit Suite.

This script runs all tests in the test suite with appropriate configuration.
"""

import sys
import os
import argparse
import subprocess
from pathlib import Path

def run_tests(verbose=False, coverage=False, test_path=None, rdp_server=None, rdp_credentials=None):
    """Run the test suite with the specified options."""
    # Ensure we're running from the project root
    project_root = Path(__file__).parent.absolute()
    os.chdir(project_root)
    
    # Base pytest command
    cmd = [sys.executable, '-m', 'pytest', '-v']
    
    # Add coverage if requested
    if coverage:
        cmd.extend([
            '--cov=cyberrdp_audit_suite',
            '--cov-report=term-missing',
            '--cov-report=html:htmlcov',
            '--cov-report=xml:coverage.xml'
        ])
    
    # Add verbose flag if requested
    if verbose:
        cmd.append('-v')
    
    # Add test path if specified
    if test_path:
        cmd.append(str(test_path))
    
    # Add RDP server configuration if provided
    if rdp_server:
        cmd.extend(['--test-rdp-server', rdp_server])
    if rdp_credentials:
        cmd.extend(['--test-rdp-credentials', rdp_credentials])
    
    # Run the tests
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd)
    return result.returncode

def main():
    """Main entry point for the test runner."""
    parser = argparse.ArgumentParser(description='Run CyberRDP Audit Suite tests')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--coverage', action='store_true', help='Generate coverage report')
    parser.add_argument('test_path', nargs='?', help='Path to specific test file or directory')
    parser.add_argument('--rdp-server', help='Test against a real RDP server (host:port)')
    parser.add_argument('--rdp-credentials', 
                      help='Credentials for RDP server (format: domain\\username:password)')
    
    args = parser.parse_args()
    
    # Run the tests
    return run_tests(
        verbose=args.verbose,
        coverage=args.coverage,
        test_path=args.test_path,
        rdp_server=args.rdp_server,
        rdp_credentials=args.rdp_credentials
    )

if __name__ == '__main__':
    sys.exit(main())
