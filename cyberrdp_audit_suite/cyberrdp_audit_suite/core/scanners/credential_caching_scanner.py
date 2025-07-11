"""
Credential Caching Scanner for RDP Security Audit

This module provides functionality to detect and analyze cached credentials
that might be stored by RDP clients on the system.
"""

import os
import sys
import json
import logging
from typing import Dict, List, Any, Optional

# Common Windows credential store locations
WINDOWS_CREDENTIAL_STORE_PATHS = [
    os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Credentials'),
    os.path.join(os.environ.get('USERPROFILE', ''), 'AppData', 'Local', 'Microsoft', 'Credentials'),
    os.path.join(os.environ.get('USERPROFILE', ''), '.rdp'),
    os.path.join(os.environ.get('USERPROFILE', ''), 'Documents', 'Default.rdp')
]

# Common Linux credential store locations
LINUX_CREDENTIAL_STORE_PATHS = [
    os.path.expanduser('~/.config/remmina/'),
    os.path.expanduser('~/.local/share/remmina/'),
    os.path.expanduser('~/.freerdp/known_hosts'),
    os.path.expanduser('~/.config/freerdp/known_hosts')
]

from ..scanners import ScannerRegistry
from .base_scanner import BaseScanner

@ScannerRegistry.register
class CredentialCachingScanner(BaseScanner):
    """Scanner that checks for cached RDP credentials on the system."""
    
    NAME = "Credential Caching Scanner"
    DESCRIPTION = "Checks for cached RDP credentials on the system"
    
    def __init__(self, target: str, port: int = 3389):
        """Initialize the scanner with target information.
        
        Args:
            target: The target hostname or IP address
            port: The target RDP port (default: 3389)
        """
        self.target = target
        self.port = port
        self.vulnerabilities = []
        self.logger = logging.getLogger(__name__)
    
    async def run(self) -> Dict[str, Any]:
        """Run the credential caching checks.
        
        Returns:
            Dict containing scan results and findings
        """
        self.logger.info("Starting credential caching scan for %s:%s", self.target, self.port)
        
        try:
            cached_creds = await self._check_credential_stores()
            
            if cached_creds:
                self._add_vulnerability(
                    "Cached Credentials Found",
                    "MEDIUM",
                    "Cached RDP credentials were found on the system",
                    "Review and remove cached credentials if not needed, or ensure they are properly secured"
                )
                return {
                    'status': 'WARNING',
                    'details': {
                        'message': 'Cached credentials found',
                        'cached_credentials': cached_creds
                    }
                }
            else:
                return {
                    'status': 'PASSED',
                    'details': {
                        'message': 'No cached credentials found in common locations'
                    }
                }
                
        except Exception as e:
            self.logger.error("Error during credential caching scan: %s", str(e))
            return {
                'status': 'ERROR',
                'details': {
                    'error': str(e)
                }
            }
    
    async def _check_credential_stores(self) -> List[Dict[str, str]]:
        """Check common credential store locations for cached RDP credentials.
        
        Returns:
            List of dictionaries containing information about found credentials
        """
        credential_stores = []
        
        # Check Windows credential stores
        if sys.platform == 'win32':
            for path in WINDOWS_CREDENTIAL_STORE_PATHS:
                if os.path.exists(path):
                    if os.path.isfile(path):
                        credential_stores.append({
                            'path': path,
                            'type': 'file',
                            'os': 'windows'
                        })
                    elif os.path.isdir(path):
                        try:
                            for root, _, files in os.walk(path):
                                for file in files:
                                    credential_stores.append({
                                        'path': os.path.join(root, file),
                                        'type': 'file',
                                        'os': 'windows'
                                    })
                        except Exception as e:
                            self.logger.warning("Error scanning directory %s: %s", path, str(e))
        
        # Check Linux credential stores
        else:
            for path in LINUX_CREDENTIAL_STORE_PATHS:
                if os.path.exists(path):
                    if os.path.isfile(path):
                        credential_stores.append({
                            'path': path,
                            'type': 'file',
                            'os': 'linux'
                        })
                    elif os.path.isdir(path):
                        try:
                            for root, _, files in os.walk(path):
                                for file in files:
                                    if file.endswith(('.rdp', '.remmina', '.rdp~')):
                                        credential_stores.append({
                                            'path': os.path.join(root, file),
                                            'type': 'file',
                                            'os': 'linux'
                                        })
                        except Exception as e:
                            self.logger.warning("Error scanning directory %s: %s", path, str(e))
        
        return credential_stores
    
    def _add_vulnerability(
        self,
        name: str,
        severity: str,
        details: str,
        recommendation: str
    ) -> None:
        """Add a vulnerability finding to the scanner's results.
        
        Args:
            name: Short name/title of the vulnerability
            severity: Severity level (e.g., 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
            details: Detailed description of the finding
            recommendation: Recommended remediation steps
        """
        self.vulnerabilities.append({
            'name': name,
            'severity': severity,
            'details': details,
            'recommendation': recommendation
        })
