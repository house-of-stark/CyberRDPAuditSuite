"""
Tests for CyberRDP Audit Suite scanners.
"""

import asyncio
import unittest
import socket
import ssl
from unittest.mock import patch, MagicMock

from cyberrdp_audit_suite.core.scanners import (
    PortScanner,
    AuthBypassScanner,
    EncryptionScanner,
    NLAScanner,
    RDPSecurityScanner,
    CredentialCachingScanner,
    get_available_scanners
)

class TestScanners(unittest.IsolatedAsyncioTestCase):
    """Test cases for RDP security scanners."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.target = "example.com"
        self.port = 3389
    
    async def test_port_scanner(self):
        """Test the PortScanner functionality."""
        with patch('socket.socket') as mock_socket, \
             patch('ssl.create_default_context') as mock_ssl_ctx:
            # Configure mock socket
            mock_conn = MagicMock()
            mock_conn.connect_ex.return_value = 0
            mock_conn.recv.return_value = b"RDP"
            mock_socket.return_value.__enter__.return_value = mock_conn
            
            # Configure mock SSL context to raise SSLError to simulate legacy encryption
            mock_ssl_ctx.return_value.wrap_socket.side_effect = ssl.SSLError("Legacy encryption")
            
            # Run the scanner
            scanner = PortScanner(self.target, self.port)
            result = await scanner.run()
            
            # Verify results
            self.assertEqual(result['status'], 'FAILED')  # Should fail due to port being closed
            self.assertEqual(result['details']['port_status'], 'closed')
            # Check if the vulnerability was added to the scanner
            self.assertTrue(any(vuln['name'] == 'RDP Port Closed' for vuln in scanner.vulnerabilities))
    
    async def test_auth_bypass_scanner(self):
        """Test the AuthBypassScanner functionality."""
        with patch('socket.socket') as mock_socket:
            # Configure mock socket
            mock_conn = MagicMock()
            mock_conn.recv.return_value = bytes([0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00])
            mock_socket.return_value.__enter__.return_value = mock_conn
            
            # Run the scanner
            scanner = AuthBypassScanner(self.target, self.port)
            result = await scanner.run()
            
            # Verify results
            self.assertIn('nla_bypass_possible', result['details'])
    
    async def test_encryption_scanner(self):
        """Test the EncryptionScanner functionality."""
        with patch('ssl.SSLContext.wrap_socket') as mock_wrap_socket, \
             patch('socket.create_connection') as mock_conn:
            # Configure mock SSL context
            mock_ssl_conn = MagicMock()
            mock_ssl_conn.version.return_value = "TLSv1.2"
            mock_ssl_conn.cipher.return_value = ('AES256-SHA', 'TLSv1.2', 256)
            mock_wrap_socket.return_value.__enter__.return_value = mock_ssl_conn
            
            # Run the scanner
            scanner = EncryptionScanner(self.target, self.port)
            result = await scanner.run()
            
            # Verify results
            self.assertIn('protocol_versions', result['details'])
            self.assertIn('cipher_suites', result['details'])
    
    async def test_nla_scanner(self):
        """Test the NLAScanner functionality."""
        with patch('socket.socket') as mock_socket:
            # Configure mock socket
            mock_conn = MagicMock()
            mock_conn.recv.return_value = bytes([0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00])
            mock_socket.return_value.__enter__.return_value = mock_conn
            
            # Run the scanner
            scanner = NLAScanner(self.target, self.port)
            result = await scanner.run()
            
            # Verify results
            self.assertIn('nla_required', result['details'])
            self.assertIn('nla_enforced', result['details'])
    
    async def test_rdp_security_scanner(self):
        """Test the RDPSecurityScanner functionality."""
        # This is a simple test that verifies the scanner runs without errors
        scanner = RDPSecurityScanner(self.target, self.port)
        result = await scanner.run()
        
        # Verify basic structure of results
        self.assertIn('security_layer', result['details'])
        self.assertIn('encryption_level', result['details'])
        self.assertIn('protocols_supported', result['details'])
    
    async def test_credential_caching_scanner(self):
        """Test the CredentialCachingScanner functionality."""
        with patch('os.path.exists') as mock_exists, \
             patch('builtins.open') as mock_open, \
             patch('os.path.isfile', return_value=True):
            # Configure mock file operations
            mock_exists.return_value = True
            mock_file = MagicMock()
            mock_file.__enter__.return_value.read.return_value = 'username=testuser\npassword=testpass\n'
            # Run the scanner
            scanner = CredentialCachingScanner(self.target, self.port)
            result = await scanner.run()
            
            # Verify results
            self.assertIn(result['status'], ['PASSED', 'WARNING'])
            # Check if vulnerabilities were added to the scanner
            self.assertIsInstance(scanner.vulnerabilities, list)
    
    async def test_scanner_registry(self):
        """Test that all scanners are properly registered and available."""
        scanners = get_available_scanners()
        scanner_class_names = [s.__name__ for s in scanners]
        
        # Check that all expected scanner classes are present
        expected_scanner_classes = [
            'PortScanner',
            'AuthBypassScanner',
            'EncryptionScanner',
            'NLAScanner',
            'RDPSecurityScanner',
            'CredentialCachingScanner'
        ]
        
        for expected in expected_scanner_classes:
            self.assertIn(expected, scanner_class_names, 
                        f"Expected scanner class '{expected}' not found in registry")


if __name__ == '__main__':
    unittest.main()
