# CyberRDP Audit Suite

[![PyPI Version](https://img.shields.io/pypi/v/cyberrdp-audit-suite.svg)](https://pypi.org/project/cyberrdp-audit-suite/)
[![Python Versions](https://img.shields.io/pypi/pyversions/cyberrdp-audit-suite.svg)](https://pypi.org/project/cyberrdp-audit-suite/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://github.com/yourusername/cyberrdp-audit-suite/actions/workflows/tests.yml/badge.svg)](https://github.com/yourusername/cyberrdp-audit-suite/actions)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A comprehensive security assessment tool for Remote Desktop Protocol (RDP) services. The CyberRDP Audit Suite helps identify security misconfigurations, vulnerabilities, and potential attack vectors in RDP implementations.

## Features

- **Port Scanning**: Detect open RDP ports and gather service information
- **Authentication Bypass Testing**: Check for NLA bypass and weak authentication mechanisms
- **Encryption Analysis**: Evaluate supported SSL/TLS protocols and cipher suites
- **NLA Configuration**: Verify Network Level Authentication settings
- **Security Layer Assessment**: Check RDP security layer configurations
- **Comprehensive Reporting**: Generate detailed security reports in multiple formats
- **Modular Architecture**: Easily extensible with custom security checks

## Installation

### Prerequisites

- Python 3.8 or higher
- OpenSSL development libraries (for some cryptographic operations)

### Using pip (Recommended)

```bash
pip install cyberrdp-audit-suite
```

### From Source

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/cyberrdp-audit-suite.git
   cd cyberrdp-audit-suite
   ```

2. Install in development mode:
   ```bash
   pip install -e .
   ```

## Usage

### Basic Scan

Run a comprehensive security scan of an RDP server:

```bash
cyberrdp-audit scan example.com
```

### Advanced Options

```bash
# Scan with specific port
cyberrdp-audit scan example.com --port 3389

# Run specific security checks only
cyberrdp-audit scan example.com --scanners port,auth,encryption

# Save results to a file
cyberrdp-audit scan example.com --output report.json

# Increase verbosity
cyberrdp-audit scan example.com -v

# Show debug output
cyberrdp-audit scan example.com -vv
```

### Available Commands

- `scan`: Run security scans against RDP servers
- `list-scanners`: List all available security scanners
- `version`: Show version information

## Available Scanners

- **PortScanner**: Checks if RDP port is open and gathers service information
- **AuthBypassScanner**: Tests for authentication bypass vulnerabilities
- **EncryptionScanner**: Analyzes SSL/TLS configuration and encryption settings
- **NLAScanner**: Verifies Network Level Authentication configuration
- **RDPSecurityScanner**: Checks RDP security layer settings

## Report Format

Scan results are available in multiple formats:

- **Console**: Human-readable output with color coding
- **JSON**: Structured data for programmatic processing
- **HTML**: Interactive HTML report (coming soon)

## Development

### Setting Up the Development Environment

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/cyberrdp-audit-suite.git
   cd cyberrdp-audit-suite
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

### Running Tests

```bash
# Run all tests
pytest

# Run tests with coverage report
pytest --cov=cyberrdp_audit_suite --cov-report=term-missing

# Run a specific test file
pytest tests/test_scanners.py -v
```

### Code Style

This project uses:
- **Black** for code formatting
- **isort** for import sorting
- **flake8** for linting
- **mypy** for type checking

Run the following commands before committing:

```bash
black .
isort .
flake8
mypy .
```

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) for details on how to submit pull requests, report issues, or suggest enhancements.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- The development team
- Open-source security tools that inspired this project
- The security research community

## Disclaimer

This tool is intended for security assessment and educational purposes only. Use only on systems you own or have explicit permission to test. The developers are not responsible for any misuse or damage caused by this software.
