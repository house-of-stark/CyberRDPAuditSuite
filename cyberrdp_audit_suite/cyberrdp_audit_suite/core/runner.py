"""
CyberRDP Audit Suite - Core Runner

This module contains the main execution logic for running RDP security audits.
"""

import os
import sys
import json
import logging
import argparse
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Union, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('cyberrdp_audit.log')
    ]
)
logger = logging.getLogger(__name__)

# Version information
VERSION = "1.0.0"
RELEASE_DATE = "2025-06-24"

class AuditResult:
    """Container for audit results and metadata."""
    
    def __init__(self, target: str, port: int = 3389):
        self.target = target
        self.port = port
        self.start_time = datetime.utcnow()
        self.end_time = None
        self.results = {}
        self.vulnerabilities = []
        self.metadata = {
            'version': VERSION,
            'release_date': RELEASE_DATE,
            'target': target,
            'port': port,
            'start_time': self.start_time.isoformat(),
            'end_time': None,
            'duration_seconds': None,
            'modules_executed': []
        }
        
    def add_result(self, module: str, result: Dict[str, Any]):
        """Add a test result from a module."""
        self.results[module] = result
        self.metadata['modules_executed'].append(module)
        
    def add_vulnerability(self, vuln: Dict[str, Any]):
        """Add a vulnerability finding."""
        self.vulnerabilities.append(vuln)
        
    def finalize(self):
        """Finalize the audit results with timing information."""
        self.end_time = datetime.utcnow()
        self.metadata['end_time'] = self.end_time.isoformat()
        self.metadata['duration_seconds'] = (self.end_time - self.start_time).total_seconds()
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert results to a dictionary for serialization."""
        return {
            'metadata': self.metadata,
            'results': self.results,
            'vulnerabilities': self.vulnerabilities,
            'summary': self.get_summary()
        }
        
    def get_summary(self) -> Dict[str, Any]:
        """Generate a summary of the audit results."""
        summary = {
            'tests_run': len(self.results),
            'tests_passed': sum(1 for r in self.results.values() if r.get('status') == 'PASSED'),
            'tests_failed': sum(1 for r in self.results.values() if r.get('status') == 'FAILED'),
            'vulnerabilities_found': len(self.vulnerabilities),
            'critical_vulnerabilities': sum(1 for v in self.vulnerabilities if v.get('severity') == 'CRITICAL'),
            'high_vulnerabilities': sum(1 for v in self.vulnerabilities if v.get('severity') == 'HIGH'),
            'medium_vulnerabilities': sum(1 for v in self.vulnerabilities if v.get('severity') == 'MEDIUM'),
            'low_vulnerabilities': sum(1 for v in self.vulnerabilities if v.get('severity') == 'LOW')
        }
        return summary

async def run_audit(
    target: str,
    port: int = 3389,
    username: str = None,
    password: str = None,
    domain: str = None,
    output_dir: str = 'reports',
    skip_tests: List[str] = None,
    parallel: int = 1,
    scanner_names: List[str] = None,
    **kwargs
) -> bool:
    """
    Run a comprehensive RDP security audit.
    
    Args:
        target: Target RDP server IP or hostname
        port: RDP port (default: 3389)
        username: Username for authentication
        password: Password for authentication
        domain: Domain for authentication
        output_dir: Directory to save reports
        skip_tests: List of test names to skip
        parallel: Number of parallel scans
        **kwargs: Additional scanner-specific arguments
        
    Returns:
        bool: True if audit completed successfully, False otherwise
    """
    # Initialize result container
    result = AuditResult(target, port)
    
    # Import scanners here to avoid circular imports
    from cyberrdp_audit_suite.core.scanners import (
        get_available_scanners,
        initialize_scanners
    )
    
    # Get and initialize scanners
    scanner_classes = get_available_scanners()
    scanners = initialize_scanners(
        scanner_classes,
        target=target,
        port=port,
        username=username,
        password=password,
        domain=domain,
        **kwargs
    )
    
    # Filter out skipped tests
    if skip_tests:
        scanners = [s for s in scanners if s.__class__.__name__ not in skip_tests]
    
    # Check if we have any scanners to run
    if not scanners:
        raise ValueError("No scanners available or all requested scanners are invalid")
        
    try:
        logger.info(f"Starting RDP security audit for {target}:{port}")
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
            
        logger.info(f"Running {len(scanners)} security tests")
        
        # Run scanners
        for scanner in scanners:
            try:
                # Run the scanner's async run method
                scanner_result = await scanner.run()
                result.add_result(scanner.__class__.__name__, scanner_result)
                
                # Add any vulnerabilities found by the scanner
                for vuln in getattr(scanner, 'vulnerabilities', []):
                    result.add_vulnerability(vuln)
                    
            except Exception as e:
                logger.error(f"Error running {scanner.__class__.__name__}: {str(e)}", exc_info=True)
                result.add_result(
                    scanner.__class__.__name__,
                    {'status': 'ERROR', 'error': str(e)}
                )
        
        # Finalize and save results
        result.finalize()
        save_audit_results(result, output_dir)
        
        logger.info(f"Audit completed for {target}:{port}")
        return True
        
    except Exception as e:
        logger.error(f"Fatal error during audit: {str(e)}")
        return False

def save_audit_results(result: AuditResult, output_dir: str):
    """Save audit results to files."""
    try:
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate output filename
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"rdp_audit_{result.target}_{timestamp}"
        
        # Save JSON report
        json_path = os.path.join(output_dir, f"{filename}.json")
        with open(json_path, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)
        
        logger.info(f"Saved JSON report to {json_path}")
        
        # TODO: Add HTML report generation
        
        return True
        
    except Exception as e:
        logger.error(f"Error saving results: {str(e)}")
        return False
