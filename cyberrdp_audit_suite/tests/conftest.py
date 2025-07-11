"""
Test configuration for CyberRDP Audit Suite.
"""

import pytest
from unittest.mock import MagicMock, patch

# Test configurations for different RDP server scenarios
RDP_TEST_CONFIGS = {
    'secure': {
        'port': 3389,
        'nla_enabled': True,
        'encryption': 'high',
        'security_layer': 'tls',
    },
    'insecure': {
        'port': 3389,
        'nla_enabled': False,
        'encryption': 'low',
        'security_layer': 'rdp',
    },
    'misconfigured': {
        'port': 3389,
        'nla_enabled': True,  # NLA enabled but with weak encryption
        'encryption': 'low',
        'security_layer': 'tls',
    },
}

@pytest.fixture(params=RDP_TEST_CONFIGS.keys())
def rdp_server_config(request):
    """Fixture providing different RDP server configurations for testing."""
    return RDP_TEST_CONFIGS[request.param]

@pytest.fixture
def mock_socket():
    """Fixture providing a mock socket for testing network operations."""
    with patch('socket.socket') as mock_socket:
        yield mock_socket

@pytest.fixture
def mock_ssl_context():
    """Fixture providing a mock SSL context for testing TLS/SSL operations."""
    with patch('ssl.SSLContext') as mock_ssl_ctx:
        mock_ssl = MagicMock()
        mock_ssl.version.return_value = "TLSv1.2"
        mock_ssl.cipher.return_value = ('AES256-SHA', 'TLSv1.2', 256)
        mock_ssl_ctx.return_value.wrap_socket.return_value.__enter__.return_value = mock_ssl
        yield mock_ssl_ctx

@pytest.fixture
def all_scanners():
    """Fixture providing all available scanner classes."""
    from cyberrdp_audit_suite.core.scanners import get_available_scanners
    return get_available_scanners()

@pytest.fixture
def base_scanner_args():
    """Fixture providing base arguments for initializing scanners."""
    return {
        'target': 'test.example.com',
        'port': 3389,
    }

# Add command line options for test configuration
def pytest_addoption(parser):
    """Add custom command line options for pytest."""
    parser.addoption(
        "--test-rdp-server",
        action="store",
        default=None,
        help="Run tests against a real RDP server (provide host:port)",
    )
    parser.addoption(
        "--test-rdp-credentials",
        action="store",
        default=None,
        help="Credentials for RDP server (format: domain\\username:password)",
    )

@pytest.fixture(scope="session")
def test_rdp_server(request):
    """Fixture providing an optional real RDP server for integration testing."""
    server = request.config.getoption("--test-rdp-server")
    if server:
        host, port = server.split(':', 1) if ':' in server else (server, '3389')
        return {'host': host, 'port': int(port)}
    return None

@pytest.fixture(scope="session")
def test_rdp_credentials(request):
    """Fixture providing credentials for the test RDP server."""
    creds = request.config.getoption("--test-rdp-credentials")
    if creds:
        if '\\' in creds:
            domain, rest = creds.split('\\', 1)
            username, password = rest.split(':', 1)
            return {'domain': domain, 'username': username, 'password': password}
        else:
            username, password = creds.split(':', 1)
            return {'username': username, 'password': password}
    return None
