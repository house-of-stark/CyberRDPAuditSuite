#!/usr/bin/env python3
"""
CyberRDP Audit Suite - Policy Validation Core
Validates RDP configurations against security policies and compliance requirements.

Key Features:
1. Validates RDP configurations against security baselines
2. Checks for compliance with security policies
3. Verifies secure RDP session parameters
4. Validates endpoint protection measures
5. Provides detailed remediation guidance

Part of the CyberRDP Audit Suite for comprehensive RDP security assessment.
"""

import os
import sys
import json
import time
import socket
import logging
import subprocess
import argparse
import winrm
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('cyberark_policy_validation.log')
    ]
)
logger = logging.getLogger(__name__)

class CyberRDPPolicyValidator:
    """
    Core policy validation engine for the CyberRDP Audit Suite.
    
    This class provides comprehensive validation of RDP configurations against
    security policies and compliance requirements. It serves as the foundation
    for all policy validation functionality in the CyberRDP Audit Suite.
    """
    
    # CyberArk PAPM policy baseline defaults
    # These would normally be loaded from a policy file but are hardcoded here for demonstration
    DEFAULT_POLICIES = {
        "minimum_encryption_level": "high",  # Required min encryption (client/server)
        "nla_required": True,                # Network Level Authentication required
        "rdp_restricted_admin": True,        # Restricted Admin mode should be enabled
        "certificate_validation": True,      # Server certificate validation required
        "allowed_client_versions": ["10.0", "8.1"], # Allowed RDP client versions
        "max_idle_time": 600,               # Maximum session idle time (seconds)
        "max_session_time": 28800,          # Maximum session duration (seconds) - 8 hours
        "clipboard_redirection": False,      # Clipboard redirection should be disabled
        "drive_redirection": False,          # Drive redirection should be disabled
        "device_redirection": False,         # Device redirection should be disabled
        "printer_redirection": False,        # Printer redirection should be disabled
        "remote_credential_guard": True,     # Remote Credential Guard should be enabled
        "restricted_admin_connections": True, # Only allow restricted admin connections
        "session_shadowing": "secure_only",  # Shadowing mode: none, secure_only, any
        "rdp_shortpath": False,              # RDP Shortpath should be disabled for security
        "rdp_multitransport": False,         # RDP MultiTransport should be disabled
        "allowed_auth_methods": ["nla", "psk", "smartcard"] # Allowed authentication methods
    }
    
    def __init__(self, target: str, port: int = 3389, username: str = None,
                 password: str = None, domain: str = "", policy_file: str = None,
                 verbose: bool = False):
        """Initialize the CyberArk policy validator with target information
        
        Args:
            target: Target hostname or IP
            port: RDP port
            username: Username for authentication
            password: Password for authentication
            domain: Domain for authentication
            policy_file: Path to policy file (JSON/XML format)
            verbose: Enable verbose output
        """
        self.target = target
        self.port = port
        self.username = username
        self.password = password
        self.domain = domain
        self.policy_file = policy_file
        self.verbose = verbose
        
        # Load policy configuration
        self.policies = self._load_policies(policy_file) if policy_file else self.DEFAULT_POLICIES
        
        # Results dictionary to store findings
        self.results = {
            'target': target,
            'port': port,
            'timestamp': datetime.utcnow().isoformat(),
            'policy_file': policy_file,
            'compliant': None,
            'violations': [],
            'recommendations': [],
            'tests': {},
        }
        
        # Initialize counters
        self.tests_run = 0
        self.tests_passed = 0
        self.tests_failed = 0
        
    def _load_policies(self, policy_file: str) -> Dict[str, Any]:
        """Load CyberArk PAPM policies from configuration file
        
        Args:
            policy_file: Path to policy file (JSON/XML)
            
        Returns:
            Dict containing policy settings
        """
        logger.info(f"Loading CyberArk PAPM policies from {policy_file}")
        
        policies = {}
        
        try:
            if policy_file.lower().endswith('.json'):
                with open(policy_file, 'r') as f:
                    policies = json.load(f)
            elif policy_file.lower().endswith('.xml'):
                tree = ET.parse(policy_file)
                root = tree.getroot()
                # Convert XML to dictionary
                for setting in root.findall('./policy/setting'):
                    name = setting.get('name')
                    if name:
                        value_elem = setting.find('value')
                        if value_elem is not None:
                            value = value_elem.text
                            # Convert string values to appropriate types
                            if value.lower() in ['true', 'false']:
                                value = value.lower() == 'true'
                            elif value.isdigit():
                                value = int(value)
                            elif value.startswith('[') and value.endswith(']'):
                                # Handle arrays
                                value = [item.strip(' "\'') for item in value[1:-1].split(',')]
                            policies[name] = value
            else:
                logger.error(f"Unsupported policy file format: {policy_file}")
                # Fall back to default policies
                policies = self.DEFAULT_POLICIES
                
            logger.info(f"Loaded {len(policies)} policy settings")
            
        except Exception as e:
            logger.error(f"Error loading policy file: {e}")
            # Fall back to default policies
            policies = self.DEFAULT_POLICIES
            
        return policies
    
    def validate_encryption_level(self) -> Dict[str, Any]:
        """Validate RDP encryption level against CyberArk PAPM policy
        
        Returns:
            Dict: Test results with findings
        """
        logger.info(f"Validating RDP encryption level on {self.target}...")
        self.tests_run += 1
        
        result = {
            'test': 'encryption_level',
            'status': 'unknown',
            'findings': [],
            'violations': []
        }
        
        required_level = self.policies.get('minimum_encryption_level', 'high').lower()
        
        try:
            if not self.username or not self.password:
                logger.warning("Credentials required for encryption level validation")
                result['status'] = 'skipped'
                result['findings'].append("No credentials provided for testing")
                return result
                
            # Connect to WinRM to query settings
            session = winrm.Session(f'http://{self.target}:5985/wsman',
                                    auth=(f"{self.domain}\\{self.username}" 
                                          if self.domain else self.username, 
                                         self.password))
            
            # Query RDP encryption level from registry
            ps_script = """$minEncryption = Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue
                          if ($minEncryption) {
                              switch ($minEncryption.MinEncryptionLevel) {
                                  1 { Write-Output "low" }
                                  2 { Write-Output "client_compatible" }
                                  3 { Write-Output "high" }
                                  4 { Write-Output "fips" }
                                  default { Write-Output "unknown" }
                              }
                          } else {
                              Write-Output "not_found"
                          }"""
            
            result_data = session.run_ps(ps_script)
            actual_level = result_data.std_out.decode('utf-8').strip().lower()
            
            # Map encryption levels to numeric values for comparison
            level_map = {
                "low": 1,
                "client_compatible": 2,
                "high": 3,
                "fips": 4
            }
            
            if actual_level == "not_found":
                result['status'] = 'failed'
                result['findings'].append("RDP encryption level setting not found")
                result['violations'].append({
                    'policy': 'minimum_encryption_level',
                    'expected': required_level,
                    'actual': 'unknown',
                    'severity': 'high',
                    'description': 'Unable to determine RDP encryption level setting',
                    'remediation': f'Configure MinEncryptionLevel to {required_level} or higher'
                })
            elif actual_level == "unknown":
                result['status'] = 'warning'
                result['findings'].append("RDP encryption level is set to an unknown value")
            else:
                result['findings'].append(f"RDP encryption level is set to: {actual_level}")
                
                # Check if actual level meets or exceeds required level
                if level_map.get(actual_level, 0) >= level_map.get(required_level, 0):
                    result['status'] = 'passed'
                    result['findings'].append(f"Encryption level meets or exceeds required level: {required_level}")
                else:
                    result['status'] = 'failed'
                    result['findings'].append(f"Encryption level below required level: {required_level}")
                    result['violations'].append({
                        'policy': 'minimum_encryption_level',
                        'expected': required_level,
                        'actual': actual_level,
                        'severity': 'high',
                        'description': f'RDP encryption level ({actual_level}) is below CyberArk PAPM required level ({required_level})',
                        'remediation': f'Increase MinEncryptionLevel to {required_level} or higher'
                    })
                    
        except Exception as e:
            logger.error(f"Error validating encryption level: {e}")
            result['status'] = 'error'
            result['findings'].append(f"Error: {str(e)}")
        
        if result['status'] == 'passed':
            self.tests_passed += 1
        elif result['status'] in ['failed', 'error']:
            self.tests_failed += 1
            
        return result
