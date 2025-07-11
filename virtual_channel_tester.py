#!/usr/bin/env python3
"""
RDP Virtual Channel Security Tester

Tests the security configuration of RDP virtual channels including:
- Clipboard redirection
- Drive redirection
- Printer redirection
- Device redirection
- Smart card redirection
- Audio/video redirection
"""

import os
import sys
import json
import logging
import subprocess
import time
from enum import Enum
from dataclasses import dataclass
from typing import Dict, List, Any, Optional, Union

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('virtual_channel_test.log')
    ]
)
logger = logging.getLogger('virtual_channel_tester')

class SecurityLevel(Enum):
    """Security levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class RDPVirtualChannelTester:
    """Tests security of RDP virtual channels."""
    
    def __init__(self, target: str, port: int = 3389, username: str = None, password: str = None,
                 domain: str = None, output_file: Optional[str] = None):
        """Initialize the RDP Virtual Channel Tester.
        
        Args:
            target: Target RDP server hostname or IP
            port: RDP port number (default: 3389)
            username: Username for RDP authentication
            password: Password for RDP authentication
            domain: Domain for RDP authentication
            output_file: Path to save JSON results
        """
        self.target = target
        self.port = port
        self.username = username or "test"
        self.password = password or "test"
        self.domain = domain
        self.output_file = output_file
        
        self.results = {
            "metadata": {
                "target": target,
                "port": port,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            },
            "channel_tests": [],
            "summary": {
                "total_channels_tested": 0,
                "insecure_channels": 0,
                "secure_channels": 0,
                "findings": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0
                }
            }
        }
        
    def test_all_channels(self) -> Dict[str, Any]:
        """Run tests on all virtual channels.
        
        Returns:
            Dict containing test results
        """
        logger.info(f"Testing RDP virtual channels on {self.target}:{self.port}")
        
        # Test each channel type
        self.test_clipboard_channel()
        self.test_drive_channel()
        self.test_printer_channel()
        self.test_smartcard_channel()
        self.test_audio_channel()
        self.test_usb_channel()
        self.test_dynamic_virtual_channels()
        
        # Update summary statistics
        self._update_summary()
        
        # Save results if output file specified
        if self.output_file:
            self._save_results()
            
        return self.results
    
    def _update_summary(self) -> None:
        """Update the summary statistics based on test results."""
        # Count channels
        self.results["summary"]["total_channels_tested"] = len(self.results["channel_tests"])
        self.results["summary"]["secure_channels"] = sum(
            1 for test in self.results["channel_tests"] if test.get("is_secure", False)
        )
        self.results["summary"]["insecure_channels"] = sum(
            1 for test in self.results["channel_tests"] if not test.get("is_secure", False)
        )
        
        # Count findings by severity
        for test in self.results["channel_tests"]:
            for finding in test.get("findings", []):
                severity = finding.get("severity", "").lower()
                if severity in self.results["summary"]["findings"]:
                    self.results["summary"]["findings"][severity] += 1
    
    def _save_results(self) -> None:
        """Save results to output file."""
        try:
            with open(self.output_file, 'w') as f:
                json.dump(self.results, f, indent=2)
            logger.info(f"Results saved to {self.output_file}")
        except Exception as e:
            logger.error(f"Error saving results: {e}")
    
    def _run_command(self, command: List[str], timeout: int = 15) -> tuple:
        """Run a command and return stdout, stderr and return code.
        
        Args:
            command: Command list to execute
            timeout: Command timeout in seconds
            
        Returns:
            Tuple of (stdout, stderr, return_code)
        """
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(timeout=timeout)
            return stdout, stderr, process.returncode
        except subprocess.TimeoutExpired:
            process.kill()
            return "", "Command timed out", -1
        except Exception as e:
            return "", str(e), -2
    
    def _test_channel(self, channel_name: str, channel_args: List[str]) -> Dict[str, Any]:
        """Test a specific virtual channel.
        
        Args:
            channel_name: Name of the channel being tested
            channel_args: FreeRDP arguments to enable the channel
            
        Returns:
            Dict containing test results for the channel
        """
        logger.info(f"Testing {channel_name} channel")
        
        result = {
            "channel": channel_name,
            "is_enabled": False,
            "is_secure": True,
            "findings": [],
            "details": {}
        }
        
        try:
            # Construct the FreeRDP command
            cmd = [
                'xfreerdp',
                f'/v:{self.target}:{self.port}',
                f'/u:{self.username}',
                f'/p:{self.password}'
            ]
            
            # Add domain if provided
            if self.domain:
                cmd.append(f'/d:{self.domain}')
            
            # Add channel-specific arguments
            cmd.extend(channel_args)
            
            # Add common arguments
            cmd.extend([
                '/cert-ignore',
                '/auth-only',
                '/log-level:info'
            ])
            
            # Run the command
            stdout, stderr, returncode = self._run_command(cmd)
            
            # Check if channel is enabled based on output
            if returncode == 0:
                result["is_enabled"] = True
                result["details"]["status"] = "Channel enabled"
                
                # If the channel is enabled, it's potentially insecure
                result["is_secure"] = False
                result["findings"].append({
                    "severity": "medium",
                    "description": f"{channel_name} channel is enabled",
                    "recommendation": f"Disable {channel_name} channel if not required",
                    "details": "Enabled channels can be exploited for data exfiltration or other attacks"
                })
            else:
                if "denied" in stderr.lower() or "disabled" in stderr.lower():
                    result["is_enabled"] = False
                    result["details"]["status"] = "Channel disabled by policy"
                    result["findings"].append({
                        "severity": "info",
                        "description": f"{channel_name} channel is properly disabled",
                        "recommendation": "No action needed",
                        "details": "This is a secure configuration"
                    })
                else:
                    result["details"]["status"] = "Channel test inconclusive"
                    result["details"]["error"] = stderr
        except Exception as e:
            logger.error(f"Error testing {channel_name} channel: {e}")
            result["details"]["error"] = str(e)
            result["findings"].append({
                "severity": "high",
                "description": f"Error testing {channel_name} channel",
                "recommendation": "Manually verify channel configuration",
                "details": str(e)
            })
            result["is_secure"] = False
        
        # Add the result to the channel tests
        self.results["channel_tests"].append(result)
        return result
    
    def test_clipboard_channel(self) -> Dict[str, Any]:
        """Test clipboard redirection channel security.
        
        Returns:
            Dict containing test results
        """
        return self._test_channel("clipboard", ["/clipboard"])
    
    def test_drive_channel(self) -> Dict[str, Any]:
        """Test drive redirection channel security.
        
        Returns:
            Dict containing test results
        """
        # Create a temporary test directory
        test_dir = "/tmp/rdp_test"
        os.makedirs(test_dir, exist_ok=True)
        
        try:
            result = self._test_channel("drive", [f"/drive:test,{test_dir}"])
            
            # Add drive-specific recommendations
            if result["is_enabled"]:
                result["findings"].append({
                    "severity": "high",
                    "description": "Drive redirection is enabled",
                    "recommendation": "Disable drive redirection or restrict it to specific users",
                    "details": "Drive redirection can be used to exfiltrate data or introduce malware"
                })
            
            return result
        finally:
            # Clean up
            try:
                os.rmdir(test_dir)
            except:
                pass
    
    def test_printer_channel(self) -> Dict[str, Any]:
        """Test printer redirection channel security.
        
        Returns:
            Dict containing test results
        """
        result = self._test_channel("printer", ["/printer"])
        
        # Add printer-specific recommendations
        if result["is_enabled"]:
            result["findings"].append({
                "severity": "medium",
                "description": "Printer redirection is enabled",
                "recommendation": "Disable printer redirection if not required",
                "details": "Printer redirection can be used for data exfiltration"
            })
        
        return result
    
    def test_smartcard_channel(self) -> Dict[str, Any]:
        """Test smart card redirection channel security.
        
        Returns:
            Dict containing test results
        """
        result = self._test_channel("smartcard", ["/smartcard"])
        
        # Add smartcard-specific recommendations
        if result["is_enabled"]:
            result["findings"].append({
                "severity": "medium",
                "description": "Smart card redirection is enabled",
                "recommendation": "Only enable smart card redirection when needed for authentication",
                "details": "Smart card redirection can expose credential material"
            })
        
        return result
    
    def test_audio_channel(self) -> Dict[str, Any]:
        """Test audio redirection channel security.
        
        Returns:
            Dict containing test results
        """
        result = self._test_channel("audio", ["/sound"])
        
        # Add audio-specific recommendations
        if result["is_enabled"]:
            result["findings"].append({
                "severity": "low",
                "description": "Audio redirection is enabled",
                "recommendation": "Disable audio redirection if not required",
                "details": "Audio redirection can be used for covert data exfiltration"
            })
        
        return result
    
    def test_usb_channel(self) -> Dict[str, Any]:
        """Test USB redirection channel security.
        
        Returns:
            Dict containing test results
        """
        result = self._test_channel("usb", ["/usb"])
        
        # Add USB-specific recommendations
        if result["is_enabled"]:
            result["findings"].append({
                "severity": "critical",
                "description": "USB redirection is enabled",
                "recommendation": "Disable USB redirection",
                "details": "USB redirection can be used to bypass security controls, introduce malware, and exfiltrate data"
            })
        
        return result
    
    def test_dynamic_virtual_channels(self) -> Dict[str, Any]:
        """Test dynamic virtual channel (DVC) security.
        
        Returns:
            Dict containing test results
        """
        result = self._test_channel("dynamic_virtual_channels", ["/dvc:test"])
        
        # Add DVC-specific recommendations
        if result["is_enabled"]:
            result["findings"].append({
                "severity": "high",
                "description": "Dynamic virtual channels are enabled",
                "recommendation": "Restrict dynamic virtual channels to only required functionality",
                "details": "Dynamic virtual channels can be used for custom malicious implementations"
            })
        
        return result
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate a comprehensive report with findings and recommendations.
        
        Returns:
            Dict containing the full report
        """
        # Generate executive summary
        critical_count = self.results["summary"]["findings"]["critical"]
        high_count = self.results["summary"]["findings"]["high"]
        medium_count = self.results["summary"]["findings"]["medium"]
        
        if critical_count > 0:
            risk_rating = "Critical"
        elif high_count > 0:
            risk_rating = "High"
        elif medium_count > 0:
            risk_rating = "Medium"
        else:
            risk_rating = "Low"
            
        self.results["executive_summary"] = {
            "risk_rating": risk_rating,
            "overview": f"RDP virtual channel security assessment for {self.target}:{self.port}",
            "key_findings": f"Found {critical_count} critical, {high_count} high, and {medium_count} medium severity issues",
            "recommendation_summary": "Review and restrict enabled virtual channels to minimize attack surface"
        }
        
        # Generate recommendations
        self.results["recommendations"] = []
        
        for test in self.results["channel_tests"]:
            for finding in test.get("findings", []):
                if "recommendation" in finding and finding["severity"] != "info":
                    self.results["recommendations"].append({
                        "channel": test["channel"],
                        "severity": finding["severity"],
                        "recommendation": finding["recommendation"]
                    })
        
        # Sort recommendations by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        self.results["recommendations"].sort(key=lambda x: severity_order.get(x["severity"], 5))
        
        return self.results

def parse_arguments():
    """Parse command line arguments."""
    import argparse
    
    parser = argparse.ArgumentParser(description='RDP Virtual Channel Security Tester')
    parser.add_argument('target', help='Target RDP server hostname or IP')
    parser.add_argument('-p', '--port', type=int, default=3389, help='RDP port (default: 3389)')
    parser.add_argument('-u', '--username', help='RDP username')
    parser.add_argument('-P', '--password', help='RDP password')
    parser.add_argument('-d', '--domain', help='RDP domain')
    parser.add_argument('-o', '--output', help='Output file for JSON results')
    
    return parser.parse_args()

def main():
    """Main entry point."""
    args = parse_arguments()
    
    tester = RDPVirtualChannelTester(
        target=args.target,
        port=args.port,
        username=args.username,
        password=args.password,
        domain=args.domain,
        output_file=args.output
    )
    
    # Run all tests
    tester.test_all_channels()
    
    # Generate and print report
    report = tester.generate_report()
    
    # Output results
    if args.output:
        # Results already saved in test_all_channels if output file specified
        print(f"Results saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))
    
    # Return 0 if no high or critical issues, 1 otherwise
    critical = report["summary"]["findings"]["critical"]
    high = report["summary"]["findings"]["high"]
    
    return 0 if critical == 0 and high == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
