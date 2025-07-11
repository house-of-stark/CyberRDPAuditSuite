"""
Integration tests for CyberRDP Audit Suite.
"""

import asyncio
import pytest
import json
from pathlib import Path
from unittest.mock import patch, MagicMock, ANY, AsyncMock

# Import the actual modules to test
from cyberrdp_audit_suite.core.runner import run_audit, AuditResult
from cyberrdp_audit_suite.core.scanners import (
    get_available_scanners,
    initialize_scanners as real_initialize_scanners,
    ScannerRegistry
)

# Add async test marker
pytestmark = pytest.mark.asyncio

class TestIntegration:
    """Integration tests for the CyberRDP Audit Suite."""
    
    async def test_run_audit_with_all_scanners(self, mocker):
        """Test running the audit with all available scanners."""
        # Setup mock results
        mock_results = {
            'PortScanner': {'status': 'PASSED', 'details': {'port_status': 'open'}},
            'AuthBypassScanner': {'status': 'PASSED', 'details': {}},
            'EncryptionScanner': {'status': 'FAILED', 'details': {'error': 'Test error'}},
        }
        
        # Mock the scanner classes and their run methods
        mock_scanners = []
        for scanner_name, result in mock_results.items():
            mock_scanner = mocker.MagicMock()
            mock_scanner.NAME = scanner_name
            mock_scanner.run = AsyncMock(return_value=result)
            mock_scanner.vulnerabilities = []
            mock_scanners.append(mock_scanner)
        
        # Mock get_available_scanners and initialize_scanners
        mocker.patch(
            'cyberrdp_audit_suite.core.scanners.get_available_scanners',
            return_value=[type(scanner.NAME, (), {'__name__': scanner.NAME}) for scanner in mock_scanners]
        )
        mocker.patch(
            'cyberrdp_audit_suite.core.scanners.initialize_scanners',
            return_value=mock_scanners
        )
        
        # Run the audit
        result = await run_audit(target="test.example.com", port=3389)

        # Verify results
        assert result is True  # Should return True if all scanners ran
        for scanner in mock_scanners:
            scanner.run.assert_awaited_once()
            
        # Verify the results were processed correctly
        # (This would require checking the audit results, which are currently not returned)
    
    async def test_run_audit_with_specific_scanners(self, mocker):
        """Test running the audit with specific scanners."""
        # Setup mock results
        mock_results = {
            'PortScanner': {'status': 'PASSED', 'details': {'port_status': 'open'}},
            'AuthBypassScanner': {'status': 'FAILED', 'details': {'error': 'Test error'}},
        }
        
        # Mock the scanner classes and their run methods
        mock_scanners = []
        for scanner_name, result in mock_results.items():
            mock_scanner = mocker.MagicMock()
            mock_scanner.NAME = scanner_name
            mock_scanner.run = AsyncMock(return_value=result)
            mock_scanner.vulnerabilities = []
            mock_scanners.append(mock_scanner)
        
        # Mock get_available_scanners and initialize_scanners
        mocker.patch(
            'cyberrdp_audit_suite.core.scanners.get_available_scanners',
            return_value=[type(scanner.NAME, (), {'__name__': scanner.NAME}) for scanner in mock_scanners]
        )
        mocker.patch(
            'cyberrdp_audit_suite.core.scanners.initialize_scanners',
            return_value=[s for s in mock_scanners if s.NAME in ['PortScanner']]  # Only return PortScanner
        )

        # Run the audit with only PortScanner
        result = await run_audit(
            target="test.example.com",
            port=3389,
            scanner_names=['PortScanner']
        )

        # Verify results
        assert result is True
        mock_scanners[0].run.assert_awaited_once()  # PortScanner should have run
        mock_scanners[1].run.assert_not_awaited()  # AuthBypassScanner should not have run
    
    @pytest.mark.asyncio
    async def test_audit_result_serialization(self):
        """Test that audit results can be serialized to JSON."""
        # Create a test result
        result = AuditResult(target="test.example.com", port=3389)
        
        # Add a scanner result
        result.add_result('PortScanner', {'status': 'PASSED', 'details': {'port_status': 'open'}})
        
        # Add a vulnerability
        result.add_vulnerability({
            'name': 'Test Vulnerability',
            'severity': 'HIGH',
            'description': 'Test description',
            'remediation': 'Test remediation'
        })
        
        # Finalize the result
        result.finalize()
        
        # Serialize to JSON and back
        result_dict = result.to_dict()
        json_str = json.dumps(result_dict)
        deserialized = json.loads(json_str)
        
        # Verify the structure
        assert deserialized['metadata']['target'] == "test.example.com"
        assert deserialized['metadata']['port'] == 3389
        assert 'PortScanner' in deserialized['results']
        assert len(deserialized['vulnerabilities']) == 1
        assert deserialized['vulnerabilities'][0]['name'] == 'Test Vulnerability'
    
    async def test_audit_with_invalid_scanner(self, mocker):
        """Test that specifying an invalid scanner name raises an error."""
        # Mock the scanner registry and its methods
        mock_scanner = mocker.MagicMock()
        mock_scanner.__name__ = 'MockScanner'
        
        # Mock the get_available_scanners function to return an empty list
        mocker.patch(
            'cyberrdp_audit_suite.core.scanners.get_available_scanners',
            return_value=[]
        )
        
        # Import here to ensure mocks are in place
        from cyberrdp_audit_suite.core.runner import run_audit
        
        # Patch the initialize_scanners to return an empty list
        mocker.patch(
            'cyberrdp_audit_suite.core.scanners.initialize_scanners',
            return_value=[]
        )
        
        # Test with an invalid scanner
        with pytest.raises(ValueError, match="No scanners available or all requested scanners are invalid"):
            await run_audit(
                target="test.example.com",
                port=3389,
                scanner_names=['PortScanner', 'InvalidScanner']
            )
    
    @pytest.mark.asyncio
    @pytest.mark.skipif(True, reason="Requires manual configuration of a test RDP server")
    async def test_against_real_rdp_server(self, test_rdp_server, test_rdp_credentials):
        """Test against a real RDP server (requires --test-rdp-server and --test-rdp-credentials)."""
        if not test_rdp_server or not test_rdp_credentials:
            pytest.skip("Test RDP server and credentials not provided")
        
        # Run the audit with all scanners
        result = await run_audit(
            target=test_rdp_server['host'],
            port=test_rdp_server['port'],
            credentials=test_rdp_credentials
        )
        
        # Basic validation of the result
        assert isinstance(result, AuditResult)
        assert result.target == test_rdp_server['host']
        assert result.port == test_rdp_server['port']
        assert result.scanner_results  # Should have some results
        
        # Save the result for inspection
        output_dir = Path("test_reports")
        output_dir.mkdir(exist_ok=True)
        output_file = output_dir / f"rdp_audit_{test_rdp_server['host']}.json"
        
        with open(output_file, 'w') as f:
            json.dump(result.to_dict(), f, indent=2, default=str)
        
        print(f"\nTest report saved to: {output_file}")
