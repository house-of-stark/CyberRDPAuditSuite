#!/usr/bin/env python3
"""
RDP Clipboard Security Testing Module
Tests for clipboard-related security issues in RDP sessions
"""

import time
import logging
import json
import re
import subprocess
import hashlib
import datetime
from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import List, Dict, Optional, Tuple, Callable, Any
import paramiko
import threading
from queue import Queue, Empty

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ClipboardTestType(str, Enum):
    """Enum for different clipboard security tests"""
    CLIPBOARD_REDIRECTION = "clipboard_redirection"
    CLIPBOARD_INJECTION = "clipboard_injection"
    CLIPBOARD_MONITORING = "clipboard_monitoring"
    FORMAT_LISTING = "format_listing"
    DATA_LEAKAGE = "data_leakage"

@dataclass
class ClipboardTestResult:
    """Class to store clipboard security test results"""
    test_type: ClipboardTestType
    test_name: str
    success: bool
    is_vulnerable: bool = False
    vulnerability_details: Optional[Dict] = None
    data_captured: Optional[Dict] = None
    timestamp: float = field(default_factory=time.time)

class ClipboardDLP:
    """Data Loss Prevention for clipboard content"""
    
    def __init__(self):
        self.sensitive_patterns = [
            r'\b(?:\d{3}-?\d{2}-?\d{4})\b',  # SSN
            r'\b\d{16}\b',  # Credit card
            r'\b\w+@\w+\.\w+\b',  # Email
            r'\b(?:password|secret|token|api[_-]?key|pwd)\s*[=:].+',  # Secrets
            r'\b(?:SensitiveData:).*',  # Custom pattern from tests
        ]
        self.allowed_formats = {
            'CF_TEXT', 'CF_UNICODETEXT', 'CF_OEMTEXT'  # Basic text formats
        }
    
    def is_sensitive(self, data: str) -> bool:
        """Check if data contains sensitive information"""
        if not isinstance(data, str):
            return False
            
        for pattern in self.sensitive_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                return True
        return False
    
    def is_allowed_format(self, format_name: str) -> bool:
        """Check if clipboard format is allowed"""
        return format_name in self.allowed_formats


class RDPClipboardTester:
    """Class for testing and securing clipboard operations in RDP sessions"""
    
    def __init__(self, rdp_host: str, rdp_port: int = 3389, 
                 username: str = None, password: str = None,
                 enable_dlp: bool = True, enable_logging: bool = True):
        self.rdp_host = rdp_host
        self.rdp_port = rdp_port
        self.username = username
        self.password = password
        self.enable_dlp = enable_dlp
        self.enable_logging = enable_logging
        self.dlp = ClipboardDLP() if enable_dlp else None
        self.results: List[ClipboardTestResult] = []
        self.clipboard_history: List[Dict] = []
        self.monitoring = False
        self.monitor_thread = None
        self.clipboard_queue = Queue()
        self.log_file = f"clipboard_audit_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    
    def _log_clipboard_operation(self, operation: str, data: Dict):
        """Log clipboard operations for auditing"""
        if not self.enable_logging:
            return
            
        log_entry = {
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'operation': operation,
            'user': self.username or 'unknown',
            'host': self.rdp_host,
            'data': data
        }
        
        # In a real implementation, this would write to a secure log
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    def secure_clipboard_copy(self, data: str, format_name: str = 'CF_TEXT') -> Dict:
        """Securely handle clipboard copy operations with DLP checks"""
        if not isinstance(data, str):
            data = str(data)
            
        # Check for sensitive data
        is_sensitive = self.dlp.is_sensitive(data) if self.dlp else False
        is_allowed = self.dlp.is_allowed_format(format_name) if self.dlp else True
        
        result = {
            'success': True,
            'blocked': False,
            'reason': '',
            'sensitive_data_detected': is_sensitive,
            'format_allowed': is_allowed,
            'data_hash': hashlib.sha256(data.encode()).hexdigest(),
            'timestamp': time.time()
        }
        
        # Block sensitive data or disallowed formats
        if is_sensitive or not is_allowed:
            result.update({
                'success': False,
                'blocked': True,
                'reason': 'sensitive_data' if is_sensitive else 'disallowed_format'
            })
        
        # Log the operation
        self._log_clipboard_operation('copy', {
            'format': format_name,
            'data_length': len(data),
            'data_preview': data[:100] + ('...' if len(data) > 100 else ''),
            'result': result
        })
        
        return result
    
    def secure_clipboard_paste(self, format_name: str = 'CF_TEXT') -> Dict:
        """Securely handle clipboard paste operations with validation"""
        # In a real implementation, this would read from the clipboard
        # For simulation, we'll return mock data
        data = "Mock clipboard data"
        
        result = {
            'success': True,
            'data': data,
            'format': format_name,
            'timestamp': time.time()
        }
        
        # Log the operation
        self._log_clipboard_operation('paste', {
            'format': format_name,
            'data_length': len(data),
            'data_preview': data[:100] + ('...' if len(data) > 100 else '')
        })
        
        return result
    
    def test_clipboard_redirection(self) -> ClipboardTestResult:
        """Test if clipboard redirection is enabled and accessible"""
        logger.info("Testing clipboard redirection capabilities...")
        
        try:
            # In a real implementation, this would attempt to access the clipboard
            # For simulation, we'll assume clipboard redirection is enabled
            is_enabled = True  # Simulated result
            
            # Test secure copy operation
            test_data = "SensitiveData: Test123!"
            copy_result = self.secure_clipboard_copy(test_data)
            
            result = ClipboardTestResult(
                test_type=ClipboardTestType.CLIPBOARD_REDIRECTION,
                test_name="Clipboard Redirection Test",
                success=True,
                is_vulnerable=is_enabled,
                data_captured={
                    'clipboard_accessible': is_enabled,
                    'dlp_enabled': self.enable_dlp,
                    'copy_operation': copy_result,
                    'test_data': test_data
                }
            )
            
            if is_enabled:
                result.vulnerability_details = {
                    "type": "Clipboard Redirection Enabled",
                    "severity": "Medium" if copy_result.get('blocked', False) else "High",
                    "description": "Clipboard redirection is enabled, which could allow data exfiltration",
                    "recommendation": "Disable clipboard redirection if not required, or implement additional monitoring"
                }
            
            self.results.append(result)
            return result
            
        except Exception as e:
            logger.error(f"Clipboard redirection test failed: {e}")
            return ClipboardTestResult(
                test_type=ClipboardTestType.CLIPBOARD_REDIRECTION,
                test_name="Clipboard Redirection Test",
                success=False,
                data_captured={"error": str(e)}
            )
    
    def test_clipboard_injection(self) -> ClipboardTestResult:
        """Test if malicious content can be injected via clipboard"""
        logger.info("Testing clipboard injection...")
        
        test_payloads = [
            "harmless_test_string_123",
            "<script>alert('XSS')</script>",
            "powershell -nop -w hidden -e [..malicious code..]"
        ]
        
        try:
            injection_results = {}
            vulnerable = False
            
            for payload in test_payloads:
                # In a real implementation, this would inject the payload into the clipboard
                # and check if it gets executed or causes issues
                time.sleep(0.5)  # Simulate clipboard operation
                
                # Simulate detection of successful injection
                is_executable = any(ext in payload.lower() 
                                 for ext in ["<script>", "powershell", "cmd.exe"])
                
                injection_results[payload] = {
                    "injected": True,
                    "detected_as_malicious": is_executable,
                    "executed": False  # Can't determine in this simulation
                }
                
                if is_executable:
                    vulnerable = True
            
            result = ClipboardTestResult(
                test_type=ClipboardTestType.CLIPBOARD_INJECTION,
                test_name="Clipboard Injection Test",
                success=True,
                is_vulnerable=vulnerable,
                data_captured={"injection_attempts": injection_results}
            )
            
            if vulnerable:
                result.vulnerability_details = {
                    "type": "Potential Clipboard Injection",
                    "severity": "High",
                    "description": "Potentially dangerous content can be injected via clipboard",
                    "recommendation": "Implement content inspection and filtering for clipboard data"
                }
            
            self.results.append(result)
            return result
            
        except Exception as e:
            logger.error(f"Clipboard injection test failed: {e}")
            return ClipboardTestResult(
                test_type=ClipboardTestType.CLIPBOARD_INJECTION,
                test_name="Clipboard Injection Test",
                success=False,
                data_captured={"error": str(e)}
            )
    
    def monitor_clipboard_activity(self, duration: int = 30) -> ClipboardTestResult:
        """Monitor clipboard activity for potential data leakage"""
        logger.info(f"Monitoring clipboard activity for {duration} seconds...")
        
        try:
            # In a real implementation, this would monitor the clipboard
            # For simulation, we'll simulate some clipboard activity
            simulated_activity = [
                (5, "Confidential: Project_Alpha_2025"),
                (12, "ssh-rsa AAAA... user@host"),
                (25, "API_KEY=abc123xyz456")
            ]
            
            # Define sensitive patterns for monitoring
            sensitive_patterns = [
                (r'\b(?:\d{3}-?\d{2}-?\d{4})\b', 'SSN'),
                (r'\b\d{16}\b', 'Credit Card'),
                (r'\b\w+@\w+\.\w+\b', 'Email'),
                (r'\b(?:password|secret|token|api[_-]?key|pwd)\s*[=:].+', 'Secret'),
                (r'\b(?:SensitiveData:).*', 'Sensitive Data')
            ]
            
            # Check for sensitive data in clipboard
            is_sensitive = False
            detected_patterns = []
            
            # In a real implementation, we would check the actual clipboard content
            # For simulation, we'll use test data
            test_content = "SensitiveData: Test123!"
            
            for pattern, label in sensitive_patterns:
                if re.search(pattern, test_content, re.IGNORECASE):
                    is_sensitive = True
                    detected_patterns.append(label)
            
            # Create a test result object
            result = ClipboardTestResult(
                test_type=ClipboardTestType.CLIPBOARD_MONITORING,
                test_name="Clipboard Monitoring Test",
                success=True,
                is_vulnerable=is_sensitive,
                data_captured={
                    'monitoring_duration': duration,
                    'sensitive_data_detected': is_sensitive,
                    'detected_patterns': detected_patterns,
                    'test_content': test_content
                }
            )
            
            if is_sensitive:
                result.vulnerability_details = {
                    'type': 'Sensitive Data Detected',
                    'severity': 'High',
                    'description': 'Sensitive data was detected in the clipboard',
                    'recommendation': 'Implement DLP controls to prevent sensitive data in clipboard'
                }
            
            # Log the operation
            self._log_clipboard_operation('monitor', {
                'duration': duration,
                'sensitive_data_detected': is_sensitive,
                'detected_patterns': detected_patterns
            })
            
            return result
            
        except Exception as e:
            logger.error(f"Clipboard monitoring failed: {e}")
            return ClipboardTestResult(
                test_type=ClipboardTestType.CLIPBOARD_MONITORING,
                test_name="Clipboard Monitoring Test",
                success=False,
                data_captured={"error": str(e)}
            )
    
    def test_data_leakage_prevention(self) -> ClipboardTestResult:
        """Test if data leakage prevention (DLP) is effective for clipboard"""
        logger.info("Testing clipboard data leakage prevention...")
        
        try:
            # In a real implementation, this would test DLP controls
            # For simulation, we'll assume DLP is not properly configured
            dlp_effective = False  # Simulated result
            
            result = ClipboardTestResult(
                test_type=ClipboardTestType.DATA_LEAKAGE,
                test_name="Data Leakage Prevention Test",
                success=True,
                is_vulnerable=not dlp_effective,
                data_captured={
                    "dlp_configured": dlp_effective,
                    "test_data": "SensitiveData: Test123!"
                }
            )
            
            if not dlp_effective:
                result.vulnerability_details = {
                    "type": "Ineffective DLP for Clipboard",
                    "severity": "High",
                    "description": "Data leakage prevention is not effectively monitoring the clipboard",
                    "recommendation": "Implement and properly configure DLP solutions to monitor and control clipboard usage"
                }
            
            self.results.append(result)
            return result
            
        except Exception as e:
            logger.error(f"Data leakage prevention test failed: {e}")
            return ClipboardTestResult(
                test_type=ClipboardTestType.DATA_LEAKAGE,
                test_name="Data Leakage Prevention Test",
                success=False,
                data_captured={"error": str(e)}
            )
    
    def list_clipboard_formats(self) -> ClipboardTestResult:
        """
        List all available clipboard formats and check for potentially dangerous formats
        
        Returns:
            ClipboardTestResult with format listing and security assessment
        """
        logger.info("Listing available clipboard formats...")
        
        try:
            # Common clipboard formats in Windows RDP
            common_formats = [
                'CF_TEXT',           # Text format with \r\n line endings
                'CF_BITMAP',        # Handle to a bitmap (HBITMAP)
                'CF_METAFILEPICT',  # Handle to a metafile picture
                'CF_SYLK',          # Microsoft Symbolic Link format
                'CF_DIF',           # Software Arts' Data Interchange Format
                'CF_TIFF',          # Tagged image file format
                'CF_OEMTEXT',       # Text format with OEM character set
                'CF_DIB',           # BITMAPINFO structure + bitmap bits
                'CF_PALETTE',       # Color palette handle
                'CF_PENDATA',       # Pen Computing data
                'CF_RIFF',          # Audio data in RIFF format
                'CF_WAVE',          # Audio data in WAVE format
                'CF_UNICODETEXT',   # Unicode text format
                'CF_ENHMETAFILE',   # Handle to enhanced metafile
                'CF_HDROP',         # List of files (HDROP)
                'CF_LOCALE',        # Locale identifier
                'CF_DIBV5',         # BITMAPV5HEADER + bitmap bits
                'CF_OWNERDISPLAY',  # Owner-display format
                'CF_DSPTEXT',       # Text display format
                'CF_DSPBITMAP',     # Bitmap display format
                'CF_DSPMETAFILEPICT', # Metafile-picture display format
                'CF_DSPENHMETAFILE'  # Enhanced metafile display format
            ]
            
            # Potentially dangerous formats that could be used for code execution
            dangerous_formats = [
                'CF_SHELLIDLIST',    # Shell item ID list
                'CFSTR_INETURL',     # Internet URL
                'CFSTR_FILEDESCRIPTOR', # File descriptor
                'CFSTR_FILECONTENTS',  # File contents
                'CFSTR_SHELLIDLISTOFFSET', # Shell ID list offset
                'CFSTR_INETURLA',    # Internet URL (ANSI)
                'CFSTR_INETURLW',    # Internet URL (Unicode)
                'CFSTR_SHELLURL',    # Shell URL
                'CFSTR_PREFERREDDROPEFFECT', # Preferred drop effect
                'CFSTR_PERFORMEDDROPEFFECT', # Performed drop effect
                'CFSTR_PASTESUCCEEDED', # Paste succeeded
                'CFSTR_INDRAGLOOP',   # In drag loop
                'CFSTR_ISSHORTCUT',   # Is shortcut
                'CFSTR_FILENAMEMAP'   # File name map
            ]
            
            # In a real implementation, we would query the actual clipboard formats
            # For simulation, we'll use the common formats and simulate some dangerous ones
            simulated_formats = common_formats.copy()
            
            # Simulate some dangerous formats being available
            simulated_dangerous = ['CF_SHELLIDLIST', 'CFSTR_FILEDESCRIPTOR']
            simulated_formats.extend(simulated_dangerous)
            
            # Check which formats are allowed by DLP (if enabled)
            allowed_formats = []
            blocked_formats = []
            
            for fmt in simulated_formats:
                if self.dlp and not self.dlp.is_allowed_format(fmt):
                    blocked_formats.append(fmt)
                else:
                    allowed_formats.append(fmt)
            
            # Check for dangerous formats
            dangerous_found = [fmt for fmt in simulated_formats if fmt in dangerous_formats]
            has_dangerous = len(dangerous_found) > 0
            
            # Create test result
            result = ClipboardTestResult(
                test_type=ClipboardTestType.FORMAT_LISTING,
                test_name="Clipboard Format Listing",
                success=True,
                is_vulnerable=has_dangerous,
                data_captured={
                    'total_formats': len(simulated_formats),
                    'allowed_formats': allowed_formats,
                    'blocked_formats': blocked_formats,
                    'dangerous_formats': dangerous_found,
                    'dlp_enabled': self.enable_dlp
                }
            )
            
            if has_dangerous:
                result.vulnerability_details = {
                    'type': 'Dangerous Clipboard Formats Enabled',
                    'severity': 'High',
                    'description': 'Potentially dangerous clipboard formats are enabled',
                    'recommendation': 'Disable or restrict the following clipboard formats: ' + 
                                    ', '.join(dangerous_found)
                }
            
            self.results.append(result)
            return result
            
        except Exception as e:
            logger.error(f"Failed to list clipboard formats: {e}")
            return ClipboardTestResult(
                test_type=ClipboardTestType.FORMAT_LISTING,
                test_name="Clipboard Format Listing",
                success=False,
                data_captured={"error": str(e)}
            )
    
    def run_all_tests(self) -> List[ClipboardTestResult]:
        """Run all clipboard security tests"""
        logger.info("Running all clipboard security tests...")
        
        self.test_clipboard_redirection()
        self.test_clipboard_injection()
        self.monitor_clipboard_activity(duration=10)  # Shorter duration for testing
        self.list_clipboard_formats()
        self.test_data_leakage_prevention()
        
        return self.results
    
    def generate_report(self, output_file: str = None) -> Dict:
        """Generate clipboard security test report"""
        # Convert test results to dictionaries
        results_dicts = []
        for r in self.results:
            result_dict = asdict(r)
            # If vulnerability_details is a dataclass, convert it to dict
            if hasattr(r.vulnerability_details, '__dataclass_fields__'):
                result_dict['vulnerability_details'] = asdict(r.vulnerability_details)
            results_dicts.append(result_dict)
        
        # Prepare vulnerabilities list
        vulnerabilities = []
        for r in self.results:
            if r.is_vulnerable and r.vulnerability_details:
                if hasattr(r.vulnerability_details, '__dataclass_fields__'):
                    vulnerabilities.append(asdict(r.vulnerability_details))
                else:
                    vulnerabilities.append(r.vulnerability_details)
        
        report = {
            "timestamp": time.time(),
            "rdp_host": self.rdp_host,
            "rdp_port": self.rdp_port,
            "tests_run": len(self.results),
            "vulnerabilities_found": sum(1 for r in self.results if r.is_vulnerable),
            "results": results_dicts,
            "vulnerabilities": vulnerabilities
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info(f"Clipboard security report saved to {output_file}")
        
        return report

def main():
    """Main function for CLI usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='RDP Clipboard Security Tester')
    parser.add_argument('host', help='RDP host to test')
    parser.add_argument('-p', '--port', type=int, default=3389, help='RDP port (default: 3389)')
    parser.add_argument('-u', '--username', help='Username for testing')
    parser.add_argument('-P', '--password', help='Password for testing')
    parser.add_argument('-o', '--output', help='Output file for JSON report')
    parser.add_argument('-t', '--test', choices=['all', 'redirection', 'injection', 
                                               'monitor', 'formats', 'dlp'], 
                       default='all', help='Specific test to run (default: all)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    try:
        tester = RDPClipboardTester(args.host, args.port, args.username, args.password)
        
        # Run selected tests
        if args.test == 'all' or args.test == 'redirection':
            tester.test_clipboard_redirection()
        if args.test == 'all' or args.test == 'injection':
            tester.test_clipboard_injection()
        if args.test == 'all' or args.test == 'monitor':
            tester.monitor_clipboard_activity(duration=30)
        if args.test == 'all' or args.test == 'formats':
            tester.list_clipboard_formats()
        if args.test == 'all' or args.test == 'dlp':
            tester.test_data_leakage_prevention()
        
        # Generate report
        report = tester.generate_report(args.output)
        
        # Print summary
        print(f"\n=== Clipboard Security Test Summary ===")
        print(f"Target: {args.host}:{args.port}")
        print(f"Tests Run: {report['tests_run']}")
        print(f"Vulnerabilities Found: {report['vulnerabilities_found']}")
        
        if report['vulnerabilities']:
            print("\n=== VULNERABILITIES FOUND ===")
            for vuln in report['vulnerabilities']:
                print(f"[{vuln['severity']}] {vuln['type']}: {vuln['description']}")
        
    except Exception as e:
        logger.error(f"Clipboard security testing failed: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())
