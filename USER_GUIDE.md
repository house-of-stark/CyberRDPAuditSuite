# RDP Security Testing Framework - User Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Test Modules](#test-modules)
5. [Running Tests](#running-tests)
6. [Interpreting Results](#interpreting-results)
7. [Advanced Usage](#advanced-usage)
8. [Troubleshooting](#troubleshooting)
9. [FAQs](#faqs)

## Introduction

The RDP Security Testing Framework is a comprehensive tool for testing and validating the security of Remote Desktop Protocol (RDP) implementations. It includes modules for testing authentication, session security, network security, and compliance with security best practices.

## Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Required system dependencies (see below)

### System Dependencies
```bash
# On Debian/Ubuntu
sudo apt update
sudo apt install -y python3-pip python3-venv nmap tshark

# On RHEL/CentOS
sudo yum install -y python3-pip nmap wireshark
```

### Setup
1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd RDP-Security-Scanner
   ```

2. Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Quick Start

### Basic Scan
```bash
# Run all security tests
python run_comprehensive_tests.py --target 192.168.1.100 --username testuser --password 'P@ssw0rd!'

# Generate HTML report
python enhanced_html_report.py --input test_results.json --output report.html
```

### Command Line Options
```
--target       Target hostname or IP address
--port         RDP port (default: 3389)
--username     Username for authentication
--password     Password for authentication
--domain       Domain for authentication
--output       Output directory for reports
--verbose      Enable verbose output
--debug        Enable debug mode
```

## Test Modules

### Authentication Tests
- **Credential Caching**: Tests for insecure credential storage in Windows Credential Manager, RDP connection files (.rdp), and Linux credential stores (Remmina, FreeRDP)
  - Windows: Checks `%APPDATA%\Microsoft\Credentials`, `%USERPROFILE%\AppData\Local\Microsoft\Credentials`, and `.rdp` files
  - Linux: Checks `~/.config/remmina/`, `~/.local/share/remmina/`, and FreeRDP known hosts
- **NTLM/Kerberos**: Validates authentication protocol security
- **MFA Bypass**: Tests for MFA implementation weaknesses

### Session Security Tests
- **Session Isolation**: Validates user session separation
- **Clipboard Security**: Tests clipboard access controls
- **Session Timeout**: Verifies session expiration

### Network Security Tests
- **RDP Gateway**: Tests gateway security controls
- **UDP Security**: Validates UDP protocol security
- **Virtual Channels**: Tests virtual channel security

### Attack Simulation
- **Relay Attacks**: Tests for credential relay vulnerabilities
- **Session Hijacking**: Validates session protection
- **BlueKeep**: Tests for CVE-2019-0708 vulnerability

## Running Tests

### Running the Credential Caching Scanner

To specifically run the Credential Caching Scanner:

```bash
# Run only the credential caching tests
python run_comprehensive_tests.py --target 192.168.1.100 --scanners credential_caching

# Run with verbose output
python run_comprehensive_tests.py --target 192.168.1.100 --scanners credential_caching -v
```

### Interpreting Credential Caching Results

The Credential Caching Scanner will generate a report with the following details:
- List of credential stores checked
- Any cached credentials found
- Location of credential files
- Risk level (High, Medium, Low)
- Recommended remediation steps

### Running Specific Tests
```bash
# Run authentication tests only
python run_comprehensive_tests.py --category authentication --target 192.168.1.100

# Run a specific test case
python run_comprehensive_tests.py --test TC-AUTH-001 --target 192.168.1.100

# Run tests from a targets file
python run_comprehensive_tests.py --targets targets.csv
```

### Batch Testing
Create a CSV file (`targets.csv`) with the following format:
```csv
target,port,username,password,domain
192.168.1.100,3389,user1,pass123,domain.local
192.168.1.101,3389,user2,pass456,domain.local
```

## Interpreting Results

### Report Types
- **HTML Report**: Comprehensive report with visualizations
- **JSON Report**: Machine-readable format for automation
- **Console Output**: Real-time test progress and results

### Understanding Severity Levels
- **Critical**: Immediate action required
- **High**: Address as soon as possible
- **Medium**: Address in next update cycle
- **Low**: Consider addressing in future updates
- **Info**: Informational findings only

## Advanced Usage

### Custom Test Configuration
Create a `config.ini` file to customize test parameters:
```ini
[authentication]
max_attempts = 3
timeout = 30

[network]
scan_ports = 3389,3390,3391

[reporting]
output_format = html,json
verbosity = detailed
```

### Integration with CI/CD
```yaml
# Example GitHub Actions workflow
name: RDP Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.9'
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
    - name: Run security tests
      run: |
        python run_comprehensive_tests.py --target ${{ secrets.TARGET_IP }} \
          --username ${{ secrets.RDP_USER }} \
          --password ${{ secrets.RDP_PASS }} \
          --output test_results
    - name: Upload results
      uses: actions/upload-artifact@v2
      with:
        name: security-report
        path: test_results/
```

## Troubleshooting

### Common Issues
1. **Connection Refused**
   - Verify the target is running RDP
   - Check firewall settings
   - Ensure the RDP service is running

2. **Authentication Failed**
   - Verify credentials
   - Check account lockout policies
   - Ensure the account has RDP access

3. **Missing Dependencies**
   - Run `pip install -r requirements.txt`
   - Install system dependencies

### Debugging
```bash
# Enable debug logging
python run_comprehensive_tests.py --debug --target 192.168.1.100

# View detailed logs
cat rdp_security_test.log
```

## FAQs

### Q: Is this tool safe to run in production?
A: Yes, but with caution. The tool performs active security testing which may impact system performance. Run during maintenance windows.

### Q: What permissions do I need to run the tests?
A: You need network access to the target RDP server and valid credentials with appropriate permissions.

### Q: How often should I run these tests?
A: Regular testing is recommended. Consider:
- Monthly for critical systems
- Quarterly for standard systems
- After any significant changes to RDP configuration

### Q: Can I automate these tests?
A: Yes, the tool supports automation through command-line interfaces and provides machine-readable output formats.

## Support
For support, please contact:
- Email: [your-email@example.com](mailto:your-email@example.com)
- Issue Tracker: [GitHub Issues](https://github.com/your-repo/issues)

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

*Last Updated: 2025-06-24*
