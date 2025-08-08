# CyberRDP Audit Suite Analyzers

This directory contains the core analysis modules for the CyberRDP Audit Suite. These analyzers are responsible for examining different aspects of RDP security.

## Available Analyzers

### RDP Configuration Analyzer
- **File**: `rdp_config_analyzer.py`
- **Purpose**: Analyzes RDP service configurations and security settings
- **Features**:
  - Checks encryption levels
  - Validates authentication methods
  - Reviews security layer configurations

### GPO Security Analyzer
- **File**: `gpo_security_analyzer.py`
- **Purpose**: Analyzes Group Policy Objects related to RDP security
- **Features**:
  - Parses GPO backup files
  - Validates security settings against benchmarks
  - Identifies misconfigurations

### Session Security Analyzer
- **File**: `session_security_analyzer.py`
- **Purpose**: Analyzes active RDP sessions for security issues
- **Features**:
  - Detects weak session encryption
  - Identifies unusual session patterns
  - Monitors for suspicious activities

## Usage

### Basic Usage
```python
from analyzers.rdp_config_analyzer import RDPConfigAnalyzer

# Initialize analyzer
analyzer = RDPConfigAnalyzer()

# Analyze configuration
results = analyzer.analyze(rdp_config)

# Get security assessment
assessment = analyzer.get_security_assessment()
```

### Running All Analyzers
```bash
# Run all analyzers and generate reports
python -m analyzers.run_all_analyzers -c config.ini -o results/
```

## Dependencies

- Python 3.8+
- Required packages are listed in `requirements.txt`

## Adding New Analyzers

1. Create a new Python file in this directory
2. Create a class that implements the `BaseAnalyzer` interface
3. Implement the required analysis methods
4. Add your analyzer to `__init__.py`
5. Update the documentation

## Testing

Run the test suite with:
```bash
pytest tests/analyzers/
```

## Contributing

Please follow the coding standards and documentation guidelines when contributing new analyzers.
