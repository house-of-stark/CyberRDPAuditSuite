# CyberRDP Audit Suite Installation Guide

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Git (optional, for development installation)

## Installation Methods

### Method 1: Install from PyPI (Recommended)


```bash
pip install cyberrdp-audit-suite
```

### Method 2: Install from Source

1. Download the latest release from the [releases page](https://github.com/yourusername/cyberrdp-audit-suite/releases)
2. Extract the archive
3. Navigate to the extracted directory
4. Run the following command:

```bash
pip install .
```

### Method 3: Development Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/cyberrdp-audit-suite.git
cd cyberrdp-audit-suite
```

2. Install in development mode:

```bash
pip install -e .[dev]
```

## Verify Installation

After installation, verify that the package is installed correctly by running:

```bash
cyberrdp-audit --version
```

You should see output similar to:
```
CyberRDP Audit Suite v1.0.0 (2025-06-24)
```

## Running Tests (Optional)

To run the test suite:

```bash
pytest tests/
```

## Basic Usage

```bash
# Run a basic scan
cyberrdp-audit scan example.com

# Run with specific scanners
cyberrdp-audit scan example.com --scanners port,auth_bypass

# Generate a JSON report
cyberrdp-audit scan example.com --output report.json

# List all available scanners
cyberrdp-audit scanners list
```

## Uninstallation

To uninstall the CyberRDP Audit Suite:

```bash
pip uninstall cyberrdp-audit-suite
```

## Troubleshooting

If you encounter any issues during installation or usage, please check the following:

1. Ensure you have Python 3.8 or higher installed
2. Verify that pip is up to date: `pip install --upgrade pip`
3. Check that all dependencies are installed correctly
4. Review the [Troubleshooting Guide](TROUBLESHOOTING.md) for common issues

## Support

For additional help, please open an issue on the [GitHub repository](https://github.com/yourusername/cyberrdp-audit-suite/issues).
