"""
Tests for credential caching analysis in RDP sessions.
"""

import unittest
import os
import tempfile
import json
from unittest.mock import patch, MagicMock, mock_open

from cyberrdp_audit_suite.core.scanners.credential_caching_scanner import (
    CredentialCachingScanner,
    WINDOWS_CREDENTIAL_STORE_PATHS,
    LINUX_CREDENTIAL_STORE_PATHS
)

class TestCredentialCachingScanner(unittest.IsolatedAsyncioTestCase):
    """Test cases for the CredentialCachingScanner."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.target = "example.com"
        self.port = 3389
        self.scanner = CredentialCachingScanner(self.target, self.port)
        
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        self.addCleanup(lambda: os.rmdir(self.test_dir))
    
    @patch('os.path.exists')
    @patch('builtins.open')
    async def test_windows_credential_scan(self, mock_open, mock_exists):
        """Test Windows credential store scanning."""
        # Mock OS to be Windows
        with patch('sys.platform', 'win32'), \
             patch('os.path.isfile', return_value=True):
            # Mock the existence of credential files
            mock_exists.side_effect = lambda x: x in [
                WINDOWS_CREDENTIAL_STORE_PATHS[0],
                WINDOWS_CREDENTIAL_STORE_PATHS[1]
            ]
            
            # Mock file contents to simulate finding credentials
            mock_file = mock_open(read_data='username=testuser\npassword=testpass\n')
            mock_open.return_value = mock_file.return_value
            
            # Run the scanner
            result = await self.scanner.run()
            
            # Verify results - The scanner returns 'WARNING' when credentials are found
            self.assertEqual(result['status'], 'WARNING')
            # Check if vulnerabilities were added to the scanner
            self.assertIn('vulnerabilities', self.scanner.__dict__)
            self.assertGreater(len(self.scanner.vulnerabilities), 0, 
                            "Expected vulnerabilities to be found in Windows credential stores")
    
    @patch('os.path.exists')
    @patch('builtins.open')
    async def test_linux_credential_scan(self, mock_open, mock_exists):
        """Test Linux credential store scanning."""
        # Mock OS to be Linux
        with patch('sys.platform', 'linux'), \
             patch('os.path.isfile', return_value=True):
            # Mock the existence of credential files
            mock_exists.side_effect = lambda x: x in [
                os.path.expanduser(path) for path in LINUX_CREDENTIAL_STORE_PATHS
            ][:1]  # Only mock first path as existing
            
            # Mock file contents to simulate finding credentials
            mock_file = mock_open(read_data='[connection]\nusername=testuser\npassword=testpass\n')
            mock_open.return_value = mock_file.return_value
            
            # Run the scanner
            result = await self.scanner.run()
            
            # Verify results - The scanner returns 'WARNING' when credentials are found
            self.assertEqual(result['status'], 'WARNING')
            # Check if vulnerabilities were added to the scanner
            self.assertIn('vulnerabilities', self.scanner.__dict__)
            self.assertGreater(len(self.scanner.vulnerabilities), 0,
                            "Expected vulnerabilities to be found in Linux credential stores")
    
    @patch('os.path.exists', return_value=False)
    async def test_no_credentials_found(self, mock_exists):
        """Test when no cached credentials are found."""
        # Run the scanner
        result = await self.scanner.run()
        
        # Verify results
        self.assertEqual(result['status'], 'PASSED')
        self.assertIn('No cached credentials found', result['details']['message'])
    
    @patch('os.path.exists')
    @patch('builtins.open', side_effect=PermissionError("Access denied"))
    async def test_permission_error_handling(self, mock_file, mock_exists):
        """Test handling of permission errors when accessing credential stores."""
        mock_exists.return_value = True
        
        # Run the scanner
        result = await self.scanner.run()
        
        # Verify results - The scanner returns 'WARNING' for permission errors
        self.assertEqual(result['status'], 'WARNING')
        self.assertIn('vulnerabilities', self.scanner.__dict__)
        self.assertGreater(len(self.scanner.vulnerabilities), 0)


if __name__ == '__main__':
    unittest.main()
