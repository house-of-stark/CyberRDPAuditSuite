# CyberRDP Audit Suite

<!-- NAVIGATION_START -->

A comprehensive security assessment tool for identifying misconfigurations, vulnerabilities, and potential attack vectors in Remote Desktop Protocol (RDP) services.

## Related Tools

This tool is part of a comprehensive RDP security testing suite. For passive RDP traffic analysis, check out the [RDP Tunnel Traffic Analyzer](../RDP%20Tunnel%20Traffic%20Analyzer/README.md).

For a detailed comparison of both tools and their complementary capabilities, see [TOOL_COMPARISON.md](../TOOL_COMPARISON.md).

## Features

- **Comprehensive RDP Security Scanning**
  - Port scanning and service detection
  - Authentication mechanism analysis
  - SSL/TLS configuration assessment
  - Network Level Authentication (NLA) verification
  - Security layer configuration checks

- **Advanced Security Checks**
  - **Credential Caching Scanner**: Detects cached RDP credentials in Windows and Linux systems
  - Authentication bypass detection (NLA bypass, weak auth)
  - Weak protocol detection (TLS 1.0/1.1, SSL 3.0)
  - Insecure cipher suite identification
  - Guest account and anonymous access checks

- **Reporting & Output**
  - Color-coded console output
  - JSON report generation
  - Detailed vulnerability information
  - Risk assessment and severity ratings
  - Remediation recommendations

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Quick Start

```bash
# Install from PyPI
pip install cyberrdp-audit-suite

# Verify installation
cyberrdp-audit --version
```

For detailed installation instructions, see [INSTALL.md](INSTALL.md).

## Usage

### Basic Scan

```bash
cyberrdp-audit scan example.com
```

### Advanced Options

```bash
# Run specific scanners
cyberrdp-audit scan example.com --scanners port,auth_bypass,encryption

# Generate JSON report
cyberrdp-audit scan example.com --output report.json

# Specify custom port
cyberrdp-audit scan example.com --port 3389

# Run with increased verbosity
cyberrdp-audit scan example.com -v
```

### List Available Scanners

```bash
cyberrdp-audit scanners list
```

## Documentation

- [User Guide](USER_GUIDE.md) - Detailed usage instructions and examples
- [Test Cases](TEST_CASES.md) - Description of test cases and scenarios
- [Compliance Mapping](COMPLIANCE_MAPPING.md) - Mapping to security standards and frameworks
- [Release Notes](RELEASE_NOTES.md) - Version history and changes
- [Contributing](CONTRIBUTING.md) - How to contribute to the project
- [Code of Conduct](CODE_OF_CONDUCT.md) - Community guidelines

## Examples

### Basic Vulnerability Scan

```bash
cyberrdp-audit scan vulnerable-server.example.com
```

### Comprehensive Security Assessment

```bash
cyberrdp-audit scan secure-server.example.com \
  --scanners all \
  --output security_report.json \
  --timeout 30 \
  --threads 5
```

## Output Example

```
[+] Starting CyberRDP Audit Suite v1.0.0
[+] Target: example.com:3389
[+] Loaded 5 security scanners

[•] Running Port Scanner...
    ✓ Port 3389/tcp is open

[•] Running Authentication Bypass Scanner...
    ⚠️  NLA bypass possible (CVE-2019-0708)
    ⚠️  Weak authentication protocols detected

[•] Running Encryption Scanner...
    ✓ Strong encryption detected
    ⚠️  Weak cipher suites found (3)

[•] Running NLA Scanner...
    ✓ Network Level Authentication is enabled

[•] Running RDP Security Scanner...
    ✓ Security layer is properly configured

[+] Scan completed in 12.45 seconds
[+] 2 vulnerabilities found (1 critical, 1 warning)
[+] Report saved to: rdp_audit_example.com_20250624_120000.json
```

## Contributing

Contributions are welcome! Please see our [Contributing Guidelines](CONTRIBUTING.md) for more information on how to get involved.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- The security research community for their work on RDP vulnerabilities
- Open-source tools that made this project possible
- All contributors who helped improve this tool

## Support

For support, please open an issue on our [GitHub repository](https://github.com/yourusername/cyberrdp-audit-suite/issues).

## Overview

CyberRDP Audit Suite is a comprehensive security assessment and auditing tool for Remote Desktop Protocol (RDP) environments. It provides in-depth security testing, vulnerability assessment, and compliance validation for RDP implementations.

## Table of Contents

- [🎯 Active Security Testing Features](#-active-security-testing-features)
  - [**Authentication & Access Control**](#authentication--access-control)
  - [**Session Security**](#session-security)
  - [**Reporting & Analysis**](#reporting--analysis)
  - [**Core Modules**](#core-modules)
- [📋 Prerequisites](#-prerequisites)
  - [System Requirements](#system-requirements)
  - [Required Tools](#required-tools)
  - [Credentials Needed](#credentials-needed)
- [🚀 Installation & Setup](#-installation--setup)
  - [1. Install System Dependencies](#1-install-system-dependencies)
  - [2. Clone the Repository](#2-clone-the-repository)
  - [3. Configure the Scanner](#3-configure-the-scanner)
  - [4. Make Scripts Executable](#4-make-scripts-executable)
- [🛠 Usage](#-usage)
  - [Basic Usage](#basic-usage)
  - [Batch Scanning](#batch-scanning)
  - [Advanced Options](#advanced-options)
  - [Targets File Format](#targets-file-format)
- [📊 Report Generation](#-report-generation)
- [🛠️ Core Component](#-core-component)
  - [**Comprehensive Test Runner** (`run_comprehensive_tests.py`)](#comprehensive-test-runner-run_comprehensive_testspy)
    - [**Usage Examples**](#usage-examples)
    - [**Reporting Features**](#reporting-features)
    - [**Example Report Structure**](#example-report-structure)
    - [**Key Features**](#key-features)
  - [2. **Enhanced RDP Analyzer** (`enhanced_rdp_analyzer.py`)](#2-enhanced-rdp-analyzer-enhanced_rdp_analyzerpy)
  - [3. **Time-Based Attack Testing** (`time_based_attacks.py`) ⭐ **NEW**](#3-time-based-attack-testing-time_based_attackspy--new)
  - [4. **Clipboard Security Testing**](#4-clipboard-security-testing)
    - [**Usage with Comprehensive Test Runner**](#usage-with-comprehensive-test-runner)
  - [5. **RBAC Validation**](#5-rbac-validation)
    - [**Usage with Comprehensive Test Runner**](#usage-with-comprehensive-test-runner)
  - [6. **MFA Bypass Testing**](#6-mfa-bypass-testing)
    - [**Usage with Comprehensive Test Runner**](#usage-with-comprehensive-test-runner)
  - [7. **RDP Relay Attack Tester** (`rdp_relay_attack_tester.py`)](#7-rdp-relay-attack-tester-rdp_relay_attack_testerpy)
  - [8. **Session Hijack Tester** (`session_hijack_tester.py`)](#8-session-hijack-tester-session_hijack_testerpy)
  - [9. **BlueKeep Tester** (`bluekeep_tester.py`)](#9-bluekeep-tester-bluekeep_testerpy)
  - [10. **Authentication Bypass Tester** (`auth_bypass_tester.py`)](#10-authentication-bypass-tester-auth_bypass_testerpy)
  - [11. **UDP Security Tester** (`udp_security_tester.py`)](#11-udp-security-tester-udp_security_testerpy)
  - [12. **Shadow Session Tester** (`shadow_session_tester.py`)](#12-shadow-session-tester-shadow_session_testerpy)
  - [13. **CyberArk PAPM Policy Validator** (`cyberark_papm_validator.py`)](#13-cyberark-papm-policy-validator-cyberark_papm_validatorpy)
  - [14. **Gateway Tester** (`gateway_tester.py`)](#14-gateway-tester-gateway_testerpy)
  - [15. **Virtual Channel Tester** (`virtual_channel_tester.py`)](#15-virtual-channel-tester-virtual_channel_testerpy)
  - [3. **Enhanced HTML Report Generator** (`enhanced_html_report.py`) ⭐ **NEW**](#3-enhanced-html-report-generator-enhanced_html_reportpy--new)
  - [4. **Legacy Tools** (Still Available)](#4-legacy-tools-still-available)
    - [RDP MITM Proxy (`rdp_mitm_proxy.sh`)](#rdp-mitm-proxy-rdp_mitm_proxysh)
    - [Security Test Runner (`run_security_tests.sh`)](#security-test-runner-run_security_testssh)
    - [HTML Report Generator (`generate_html_report.py`)](#html-report-generator-generate_html_reportpy)
- [🎯 Quick Start Guide](#-quick-start-guide)
  - [**Comprehensive Security Testing** (Recommended)](#comprehensive-security-testing-recommended)
- [📊 Test Categories](#-test-categories)
  - [**1. Authentication Testing**](#1-authentication-testing)
  - [**2. Privilege Escalation Testing**](#2-privilege-escalation-testing)
  - [**3. Session Security Testing**](#3-session-security-testing)
  - [**4. Attack Simulation**](#4-attack-simulation)
- [📈 Output and Reporting](#-output-and-reporting)
  - [**Report Structure**](#report-structure)
- [🔧 Configuration](#-configuration)
  - [**Environment Variables**](#environment-variables)
  - [**Configuration File**](#configuration-file)
- [📈 Output Structure](#-output-structure)
- [🔧 Configuration](#-configuration)
  - [Environment Variables](#environment-variables)
- [🔍 Security Focus Areas](#-security-focus-areas)
- [⚠️ Legal Notice](#-legal-notice)
- [🚨 Troubleshooting](#-troubleshooting)
  - [Common Issues](#common-issues)
  - [Debug Mode](#debug-mode)
- [🔄 Migration from Legacy Tools](#-migration-from-legacy-tools)
- [📚 Documentation](#-documentation)

---

<!-- NAVIGATION_END -->


*Last updated: 2025-06-20*
> **Active Security Testing Tool** - This tool actively connects to RDP servers using provided credentials to test and validate security settings, authentication mechanisms, and session configurations.

**Key Differentiator**: Unlike passive traffic analysis tools, this tool performs active testing by establishing real RDP connections to identify security issues in the RDP service configuration and authentication mechanisms.

## 🌟 Key Features
### **Authentication & Access Control**
- **Credential-based Testing**: Actively tests authentication using provided credentials
- **MFA Bypass Testing**: Identifies weaknesses in multi-factor authentication implementations
- **Account Lockout Testing**: Verifies proper account lockout policies and thresholds
- **RBAC Validation**: Tests role-based access control implementations
- **Privilege Escalation**: Identifies potential privilege escalation vectors

### **Session Security**
- **Encryption Level Testing**: Verifies supported encryption protocols and ciphers
- **Security Layer Validation**: Tests RDP security layer implementations
- **Session Isolation**: Verifies session isolation between users
- **Clipboard Security**: Tests clipboard redirection security controls
- **Drive Redirection**: Validates secure handling of drive redirections

### **Reporting & Analysis**
- **Detailed Security Reports**: Comprehensive HTML reports with findings
- **Remediation Guidance**: Actionable recommendations for identified issues
- **Compliance Mapping**: Maps findings to security standards and best practices
- **Executive Summary**: High-level overview of security posture

### **Core Modules**
- **Brute Force Testing**: Tests resistance against credential stuffing and account lockout attacks
- **MFA Bypass Testing**: Identifies weaknesses in multi-factor authentication
- **RBAC Validation**: Verifies proper implementation of role-based access controls
- **Burp Suite Integration**: Leverages Burp Suite for advanced web-based RDP security testing
- **Time-Based Attack Testing**: Detects timing vulnerabilities in authentication flows
- **Clipboard Security Analysis**: Tests for clipboard-related security issues
- **Passive Traffic Capture**: Enables MITM analysis of RDP traffic without active interference
- **Comprehensive Test Runner**: Unified interface for running all security tests

### **Enhanced Authentication Bypass Testing**
The RDP Authentication Bypass Tester has been enhanced with robust error handling and comprehensive testing capabilities:

#### Key Features
- **Automated Test Execution** with detailed error handling and recovery
- **Comprehensive Logging** of all test activities and results
- **Detailed Reporting** with actionable recommendations
- **Graceful Degradation** - continues testing even if individual tests fail

#### Error Handling Improvements
- **Test Isolation**: Each test runs in isolation to prevent cascading failures
- **Detailed Error Reporting**: Captures and reports detailed error information
- **Resource Cleanup**: Ensures proper cleanup of resources (sockets, files, etc.)
- **Timeout Handling**: Implements configurable timeouts for all operations
- **Retry Logic**: Automatic retries for transient failures

#### Usage Examples
```bash
# Basic usage with error reporting
python3 rdp_auth_bypass_tester.py -t 192.168.1.100 -u admin -p password

# Enable verbose error output
python3 rdp_auth_bypass_tester.py -t 192.168.1.100 -v

# Save detailed JSON report
python3 rdp_auth_bypass_tester.py -t 192.168.1.100 -o report.json

# Run specific tests only
python3 rdp_auth_bypass_tester.py -t 192.168.1.100 --tests nla_bypass,guest_access
```

#### Integration with Comprehensive Test Runner
The Authentication Bypass Tester is fully integrated with the comprehensive test runner:
```bash
# Run all tests including authentication bypass checks
python3 run_comprehensive_tests.py -t 192.168.1.100 --include-tests auth_bypass

# Generate HTML report with authentication bypass results
python3 run_comprehensive_tests.py -t 192.168.1.100 -o report.html --format html
```

#### Error Codes and Troubleshooting
| Code | Description | Recommended Action |
|------|-------------|-------------------|
| 1001 | Connection refused | Verify target is online and RDP port is open |
| 1002 | Authentication failed | Check credentials and account status |
| 1003 | Test timeout | Check network connectivity and target responsiveness |
| 1004 | Missing dependency | Install required dependencies (e.g., xfreerdp) |
| 1005 | Permission denied | Run with appropriate privileges |

For additional assistance, enable debug mode with `-v` or `--verbose` flag.

## 📋 Prerequisites
### System Requirements
- **Operating System**: Linux (Kali Linux, Ubuntu, or similar)
- **Python**: 3.6 or higher
- **Root Access**: Required for certain tests and configurations
- **Network Access**: Direct connectivity to target RDP servers

### Required Tools
- **xfreerdp**: For RDP client testing and validation
- **Impacket**: For various network protocol testing
- **CrackMapExec**: For credential validation and testing
- **Nmap**: For service discovery and enumeration
- **Hydra/Medusa**: For brute force testing (optional)

### Credentials Needed
- Valid RDP user credentials for testing
- Administrative credentials (for certain tests)
- Test account credentials (for privilege testing)

## 🚀 Installation & Setup
### 1. Install System Dependencies
```bash
# Update package lists and install required tools
sudo apt-get update
sudo apt-get install -y freerdp2-x11 python3-pip crackmapexec nmap

# Install additional security testing tools
sudo apt-get install -y impacket-scripts seclists wordlists

# Install Python dependencies
pip3 install impacket python-nmap paramiko colorama
```

### 2. Clone the Repository
```bash
git clone https://github.com/your-org/rdp-security-scanner.git
cd rdp-security-scanner
```

### 3. Configure the Scanner
Edit the `config.ini` file to set up your testing parameters:
```ini
[credentials]
username = testuser
password = YourSecurePassword
domain = CORP

[targets]
targets_file = targets.txt
single_target = 192.168.1.100

[scanning]
nmap_timing = T4
ports = 3389,3390,3391
```

### 4. Make Scripts Executable
```bash
chmod +x *.sh
chmod +x scripts/*.py
```

## 🛠 Usage
### Basic Usage
Run a comprehensive security test against a single target:

```bash
python3 run_comprehensive_tests.py <target> -p <port> -u <username> -P <password> -o reports/
```

### Batch Scanning
Scan multiple targets from a CSV or JSON file:

```bash
# Using CSV file
python3 run_comprehensive_tests.py --targets-file targets_example.csv -o reports/

# Using JSON file
python3 run_comprehensive_tests.py --targets-file targets_example.json -o reports/
```

### Advanced Options
```bash
# Run with parallel processing (up to 4 targets at once)
python3 run_comprehensive_tests.py --targets-file targets.csv --parallel 4 -o reports/

# Skip specific tests
python3 run_comprehensive_tests.py <target> --skip-tests bruteforce mfa

# Disable HTML report generation
python3 run_comprehensive_tests.py <target> --no-html

# Disable summary report (for batch scans)
python3 run_comprehensive_tests.py --targets-file targets.csv --no-summary

# Enable verbose output
python3 run_comprehensive_tests.py <target> -v
```

### Targets File Format
**CSV Format:**
```csv
target,port,username,password
192.168.1.100,3389,admin,password123
192.168.1.101,3389,user1,password456
```

**JSON Format:**
```json
[
  {
    "target": "192.168.1.100",
    "port": 3389,
    "username": "admin",
    "password": "password123"
  },
  {
    "target": "192.168.1.101",
    "port": 3389,
    "username": "user1",
    "password": "password456"
  }
]
```

## 📊 Report Generation
The tool generates two types of reports:

1. **Individual Reports**: Detailed HTML and JSON reports for each target
2. **Summary Report**: Consolidated report showing results across all scanned targets (only generated for batch scans)

Reports are saved in the specified output directory (default: `reports/`). The summary report is named `rdp_scan_summary_<timestamp>.html`.

## 🛠️ Core Component
### **Comprehensive Test Runner** (`run_comprehensive_tests.py`)
**The complete security testing suite implementing all MITM Test Criteria requirements with enhanced reporting.**

#### **Usage Examples**
**Basic Scan**

```bash
# Run all security tests
python run_comprehensive_tests.py --target 192.168.1.100 --username testuser --password 'P@ssw0rd!'

# Run only credential caching check
python run_comprehensive_tests.py --target 192.168.1.100 --scanners credential_caching
```

**Selective Testing:**
```bash
# Skip specific tests
python3 run_comprehensive_tests.py <target_ip> --no-bruteforce --no-mfa

# Run only clipboard security tests
python3 run_comprehensive_tests.py <target_ip> --no-bruteforce --no-mfa --no-rbac --no-time
```

**Advanced Options:**
```bash
# Custom port and output file
python3 run_comprehensive_tests.py <target_ip> -p 3389 -u <username> -P <password> -o ./custom_reports

# Generate JSON report for automation
python3 run_comprehensive_tests.py <target_ip> -u <username> -P <password> --json
```

#### **Reporting Features**
**1. Vulnerability Analysis**
- Detailed breakdown by severity (Critical, High, Medium, Low)
- Risk scoring and prioritization
- Technical details and impact assessment
- Affected components and systems

**2. Remediation Guidance**
- Step-by-step remediation instructions
- Security control mappings (NIST, CIS, MITRE ATT&CK)
- Implementation examples and code snippets
- Verification steps for each fix

**3. Executive Summary**
- Security posture overview
- Risk heatmap
- Compliance status
- Top-priority action items

**4. Technical Appendices**
- Raw test results
- Network capture analysis
- Authentication flow diagrams
- Security control effectiveness metrics

#### **Example Report Structure**
```
report_<timestamp>/
├── executive_summary.html
├── detailed_findings/
│   ├── critical_findings.md
│   ├── high_risk_findings.md
│   ├── medium_risk_findings.md
│   └── low_risk_findings.md
├── remediation/
│   ├── immediate_actions.md
│   ├── short_term_recommendations.md
│   └── long_term_strategy.md
└── technical_appendix/
    ├── raw_test_results.json
    ├── network_capture.pcapng
    └── authentication_flow.png
```

#### **Key Features**
- **Authentication Testing**
  - ✅ Credential caching analysis
  - ✅ NTLM/Kerberos ticket analysis
  - ✅ MFA bypass testing
  - ✅ Session token security evaluation
  - ✅ Brute force resistance testing

- **Privilege Escalation Testing**
  - ✅ JIT privilege assignment monitoring
  - ✅ RBAC validation testing
  - ✅ Temporary credential lifecycle tracking
  - ✅ Time-based attack detection

- **Session Security Testing**
  - ✅ Encryption strength analysis
  - ✅ Certificate validation testing
  - ✅ Session hijacking vector detection
  - ✅ Clipboard redirection security
  - ✅ Time-based attack detection

- **Attack Simulation**
  - ✅ MITM attack pattern detection
  - ✅ Replay attack vulnerability assessment
  - ✅ DoS attack resistance testing
  - ✅ Clipboard injection testing
  - ✅ Rate limiting bypass testing

### 2. **Enhanced RDP Analyzer** (`enhanced_rdp_analyzer.py`)
**Advanced PCAP analysis with comprehensive security assessment.**

**Usage:**
```bash
python3 enhanced_rdp_analyzer.py capture.pcap -o detailed_analysis.json -v
```

### 3. **Time-Based Attack Testing** (`time_based_attacks.py`) ⭐ **NEW**
**Detects timing vulnerabilities in RDP authentication and session handling.**

**Usage:**
```bash
# Test login timing differences
python3 time_based_attacks.py <target_ip> -u <username> -P <password> --test auth

# Test rate limiting
python3 time_based_attacks.py <target_ip> -u <username> --test rate
```

### 4. **Clipboard Security Testing**
**Comprehensive clipboard security analysis for RDP sessions, including clipboard monitoring and injection testing.**

#### **Usage with Comprehensive Test Runner**
```bash
# Run clipboard security tests with authentication
python3 run_comprehensive_tests.py <target_ip> -u <username> -P <password> --no-bruteforce --no-mfa --no-rbac --no-time

# Run only clipboard tests with custom monitoring duration (seconds)
python3 run_comprehensive_tests.py <target_ip> -u <username> -P <password> --test clipboard --clipboard-duration 60
```

### 5. **RBAC Validation**
**Comprehensive testing of Role-Based Access Control implementation in RDP environments, including role permission validation and privilege escalation detection.**

#### **Usage with Comprehensive Test Runner**
```bash
# Run RBAC validation tests with authentication
python3 run_comprehensive_tests.py <target_ip> -u <username> -P <password> --no-bruteforce --no-mfa --no-time --no-clipboard

# Run only RBAC tests with specific role validation
python3 run_comprehensive_tests.py <target_ip> -u <username> -P <password> --test rbac --role admin
```

**Capabilities:**
- Role permission validation
- Privilege escalation detection
- Session access control testing
- User role verification
- Access policy enforcement testing

### 6. **MFA Bypass Testing**
**Comprehensive testing for vulnerabilities in MFA implementations, including code replay, token reuse, and session fixation.**

#### **Usage with Comprehensive Test Runner**
```bash
# Run MFA bypass tests with authentication
python3 run_comprehensive_tests.py <target_ip> -u <username> -P <password> --no-bruteforce --no-rbac --no-time --no-clipboard

# Run only MFA bypass tests with specific code validation
python3 run_comprehensive_tests.py <target_ip> -u <username> -P <password> --test mfa --valid-code 123456
```

**Capabilities:**
- MFA code replay testing
- Token reuse detection
- Time-based code prediction
- Response manipulation
- Session fixation testing

### 7. **RDP Relay Attack Tester** (`rdp_relay_attack_tester.py`)
**Simulates RDP relay attacks to test defenses.**

**Usage:**
```bash
python3 rdp_relay_attack_tester.py <target_ip> -u <username> -P <password>
```

### 8. **Session Hijack Tester** (`session_hijack_tester.py`)
**Simulates session hijacking attacks to test defenses.**

**Usage:**
```bash
python3 session_hijack_tester.py <target_ip> -u <username> -P <password>
```

### 9. **BlueKeep Tester** (`bluekeep_tester.py`)
**Simulates BlueKeep attacks to test defenses.**

**Usage:**
```bash
python3 bluekeep_tester.py <target_ip> -u <username> -P <password>
```

### 10. **Authentication Bypass Tester** (`auth_bypass_tester.py`)
**Simulates authentication bypass attacks to test defenses.**

**Usage:**
```bash
python3 auth_bypass_tester.py <target_ip> -u <username> -P <password>
```

### 11. **UDP Security Tester** (`udp_security_tester.py`)
**Simulates UDP-based attacks to test defenses.**

**Usage:**
```bash
python3 udp_security_tester.py <target_ip> -u <username> -P <password>
```

### 12. **Shadow Session Tester** (`shadow_session_tester.py`)
**Simulates shadow session attacks to test defenses.**

**Usage:**
```bash
python3 shadow_session_tester.py <target_ip> -u <username> -P <password>
```

### 13. **CyberArk PAPM Policy Validator** (`cyberark_papm_validator.py`)
**Validates CyberArk PAPM policies.**

**Usage:**
```bash
python3 cyberark_papm_validator.py <target_ip> -u <username> -P <password>
```

### 14. **Gateway Tester** (`gateway_tester.py`)
**Simulates gateway attacks to test defenses.**

**Usage:**
```bash
python3 gateway_tester.py <target_ip> -u <username> -P <password>
```

### 15. **Virtual Channel Tester** (`virtual_channel_tester.py`)
**Simulates virtual channel attacks to test defenses.**

**Usage:**
```bash
python3 virtual_channel_tester.py <target_ip> -u <username> -P <password>
```

### 3. **Enhanced HTML Report Generator** (`enhanced_html_report.py`) ⭐ **NEW**
**Professional HTML report generation with security metrics.**

**Usage:**
```bash
python3 enhanced_html_report.py analysis.json -o security_report.html
```

### 4. **Legacy Tools** (Still Available)
#### RDP MITM Proxy (`rdp_mitm_proxy.sh`)
Basic transparent proxy for RDP traffic capture.

#### Security Test Runner (`run_security_tests.sh`)
Automated testing suite for basic security checks.

#### HTML Report Generator (`generate_html_report.py`)
Basic HTML report generation.

## 🎯 Quick Start Guide
### **Comprehensive Security Testing** (Recommended)
1. **Install dependencies:**
```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y tshark socat freerdp2-x11 python3-pip wireshark-common tcpdump iptables

# Install Python dependencies
pip3 install pyshark scapy paramiko
```

2. **Run comprehensive tests:**
```bash
# Run all tests with authentication
python3 run_comprehensive_tests.py your.rdp.server.ip -u username -P password

# For more options
python3 run_comprehensive_tests.py --help
```

3. **Review results:**
- JSON reports are saved in the `reports` directory by default
- Detailed logs are available in the console output
- HTML reports can be generated from the JSON output

4. **Analyze specific areas:**
```bash
# Test for timing vulnerabilities
python3 time_based_attacks.py your.rdp.server.ip -u username -P password

# Test clipboard security
python3 clipboard_security.py your.rdp.server.ip -u username -P password
```

## 📊 Test Categories
### **1. Authentication Testing**
- **Credential Caching Analysis**: Detects improper credential storage
- **NTLM/Kerberos Analysis**: Evaluates authentication protocol security
- **MFA Bypass Testing**: Identifies weaknesses in multi-factor authentication
- **Brute Force Resistance**: Tests protection against credential stuffing
- **Session Token Security**: Validates token generation and handling

### **2. Privilege Escalation Testing**
- **JIT Privilege Assignment**: Monitors CyberArk JIT privilege packets
- **RBAC Validation**: Tests role-based access control enforcement
- **Credential Lifecycle**: Tracks temporary credential management
- **Time-Based Controls**: Evaluates time-constrained access

### **3. Session Security Testing**
- **Encryption Strength**: Validates cipher suites and key lengths
- **Certificate Validation**: Tests SSL/TLS certificate handling
- **Session Hijacking**: Identifies TCP sequence vulnerabilities
- **Clipboard Security**: Analyzes clipboard redirection safety
- **Time-Based Attacks**: Detects timing vulnerabilities in authentication

### **4. Attack Simulation**
- **MITM Detection**: Identifies man-in-the-middle attack patterns
- **Replay Analysis**: Detects packet replay vulnerabilities
- **DoS Resistance**: Tests denial-of-service attack resilience
- **Clipboard Injection**: Tests for malicious content injection
- **Rate Limiting Bypass**: Tests effectiveness of rate limiting controls

## 📈 Output and Reporting
The test suite generates comprehensive reports in multiple formats:

### **Report Structure**
```
reports/
├── rdp_security_report_<target>_<timestamp>.json  # Complete JSON report
├── logs/                                         # Detailed logs
│   ├── bruteforce.log
│   ├── mfa_bypass.log
│   └── clipboard_analysis.log
└── findings/                                     # Individual test results
    ├── time_based_attacks.json
    ├── clipboard_security.json
    ├── rbac_validation.json
```

## 🔧 Configuration
### **Environment Variables**
```bash
# For Burp Suite integration
export BURP_HOST=127.0.0.1
export BURP_PORT=8080

# For rate limiting tests
export RATE_LIMIT_DELAY=1  # seconds between requests

# For time-based attack tests
export TIMING_THRESHOLD=0.1  # seconds to consider timing significant
```

### **Configuration File**
Create a `config.json` file to customize test parameters:
```json
{
    "target": "your.rdp.server.ip",
    "port": 3389,
    "username": "testuser",
    "password": "testpass",
    "tests": {
        "bruteforce": {
            "enabled": true,
            "max_attempts": 5,
            "delay": 1
        },
        "mfa_bypass": {
            "enabled": true,
            "valid_code": "123456"
        },
        "clipboard": {
            "monitor_duration": 60
        }
    }
}
```

Then run with:
```bash
python3 run_comprehensive_tests.py --config config.json
```

## 📈 Output Structure
```
rdp_security_test_YYYYMMDD_HHMMSS/
├── session_TIMESTAMP.log                # Execution log
├── security_report_TIMESTAMP.md         # Summary report
├── security_report_TIMESTAMP.json       # JSON report
└── logs/                               # System logs
```

## 🔧 Configuration
### Environment Variables
```bash
export TARGET_RDP_IP="192.168.1.100"    # Required: Target RDP server
export PROXY_PORT="8080"                # Optional: Proxy port (default: 8080)
export LOG_DIR="./custom_logs"          # Optional: Log directory
export DEBUG="1"                        # Optional: Enable debug mode
```

## 🔍 Security Focus Areas
This suite specifically addresses **CyberArk JIT DPA** security requirements:

1. **Just-In-Time Access**: Monitors privilege assignment and revocation
2. **Dynamic Privilege Management**: Tracks privilege escalation attempts
3. **Session Security**: Validates encryption and authentication
4. **Credential Security**: Analyzes credential caching and lifecycle
5. **Attack Resistance**: Tests against common RDP attacks

## ⚠️ Legal Notice
**This tool is for authorized security testing only.** Ensure proper authorization before testing any systems. Unauthorized access is illegal.

## 🚨 Troubleshooting
### Common Issues
1. **Permission Denied**
   ```bash
sudo ./rdp_comprehensive_security_test.sh
```

2. **Target IP Not Set**
   ```bash
export TARGET_RDP_IP="your.server.ip"
```

3. **Missing Dependencies**
   ```bash
sudo apt-get install wireshark-common tshark socat
   pip3 install pyshark scapy
```

4. **No Traffic Captured**
   - Verify RDP client connects through the proxy
   - Check iptables rules: `sudo iptables -t nat -L`
   - Ensure target IP is reachable

### Debug Mode
```bash
export DEBUG=1
sudo ./rdp_comprehensive_security_test.sh
```

## 🔄 Migration from Legacy Tools
If upgrading from previous versions:

1. **Use comprehensive testing**: `rdp_comprehensive_security_test.sh` instead of `rdp_mitm_proxy.sh`
2. **Enhanced analysis**: `enhanced_rdp_analyzer.py` instead of basic analysis
3. **Better reports**: `enhanced_html_report.py` for professional formatting

Legacy tools remain available for compatibility.

## 📚 Documentation
- `MITM Test Criteria.md`: Complete testing requirements and methodologies
- Individual script headers: Detailed usage and configuration options

---

**Status: ✅ Fully Implements MITM Test Criteria Requirements**
