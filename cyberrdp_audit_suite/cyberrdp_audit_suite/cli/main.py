#!/usr/bin/env python3
"""
CyberRDP Audit Suite - Command Line Interface

Main entry point for the CyberRDP Audit Suite CLI.
"""

import sys
import argparse
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

# Version information
VERSION = "1.0.0"
RELEASE_DATE = "2025-06-24"

def parse_args() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='CyberRDP Audit Suite - Comprehensive RDP Security Assessment Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  cyberrdp-audit 192.168.1.100 -u admin -p password
  cyberrdp-audit --targets-file targets.csv -o /path/to/reports
  cyberrdp-audit 192.168.1.100 --skip-tests "Brute Force" "MFA Bypass"
""")
    
    # Required arguments
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('target', nargs='?', help='Single target RDP server IP or hostname')
    target_group.add_argument('--targets-file', help='File containing list of targets (CSV or JSON)')
    
    # Connection options
    parser.add_argument('-p', '--port', type=int, default=3389, help='RDP port (default: 3389)')
    parser.add_argument('-u', '--username', help='Username for authentication tests')
    parser.add_argument('-P', '--password', help='Password for authentication tests')
    parser.add_argument('-d', '--domain', help='Domain for authentication')
    
    # Output options
    parser.add_argument('-o', '--output', default='reports', 
                      help='Output directory for reports (default: reports)')
    parser.add_argument('--skip-tests', nargs='+', default=[], help='Tests to skip')
    parser.add_argument('--no-html', action='store_true', help='Disable HTML report generation')
    parser.add_argument('--no-summary', action='store_true', 
                       help='Disable summary report generation for multiple targets')
    
    # Advanced options
    parser.add_argument('--burp-host', help='Burp Suite host (for integration tests)')
    parser.add_argument('--burp-port', type=int, default=8080, 
                       help='Burp Suite port (default: 8080)')
    parser.add_argument('--rate-limit-delay', type=float, default=1.0,
                       help='Delay between requests in seconds')
    parser.add_argument('--timing-threshold', type=float, default=5.0,
                       help='Timing threshold in seconds')
    
    # Performance options
    parser.add_argument('--parallel', type=int, default=1,
                      help='Number of parallel scans (default: 1)')
    
    # Info
    parser.add_argument('-v', '--version', action='version', 
                      version=f'CyberRDP Audit Suite v{VERSION} ({RELEASE_DATE})',
                      help='Show version and exit')
    
    return parser.parse_args()

def main() -> int:
    """Main entry point for the CyberRDP Audit Suite CLI"""
    try:
        args = parse_args()
        
        # Import here to avoid circular imports
        from cyberrdp_audit_suite.core.runner import run_audit
        
        # Convert args to dict for passing to the runner
        kwargs = vars(args).copy()
        
        # Run the audit
        success = run_audit(**kwargs)
        
        return 0 if success else 1
        
    except KeyboardInterrupt:
        print("\n[!] Audit interrupted by user")
        return 1
    except Exception as e:
        print(f"[!] Error: {str(e)}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
