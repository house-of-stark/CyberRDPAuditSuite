# Detection Rules

This directory contains detection rules and signatures used by the CyberRDP Audit Suite to identify security issues and misconfigurations in RDP environments.

## Directory Structure

- `gpo/` - Group Policy detection rules
- `rdp/` - RDP-specific detection rules
- `security/` - General security detection rules
- `templates/` - Rule templates for creating custom detections

## Available Rule Sets

### RDP Configuration Rules
- `rdp/encryption.rules` - Rules for detecting weak encryption settings
- `rdp/authentication.rules` - Rules for authentication method validation
- `rdp/network_level_auth.rules` - Rules for NLA configuration checks

### GPO Security Rules
- `gpo/account_policies.rules` - Account policy validations
- `gpo/audit_policies.rules` - Audit policy configurations
- `gpo/user_rights.rules` - User rights assignment rules

## Rule Format

Rules are defined in YAML format with the following structure:

```yaml
rule_id: RDP-001
title: "Weak RDP Encryption Detected"
severity: high
description: "RDP is configured to use weak encryption (RSA 56-bit)"
condition: |
  rdp.encryption_level == 'LOW' or 
  rdp.encryption_method == 'RSA_56'
recommendation: "Upgrade to FIPS 140-2 compliant encryption (AES 128-bit or higher)"
references:
  - "NIST SP 800-171 Section 3.13.11"
  - "CIS Microsoft Windows Server 2019 Benchmark"
```

## Using Detection Rules

### Loading Rules
```python
from detection_engine import DetectionEngine

# Initialize detection engine
engine = DetectionEngine()

# Load all rules from directory
engine.load_rules('detection_rules/')

# Or load specific rule files
engine.load_rule('detection_rules/rdp/encryption.rules')
```

### Running Detections
```python
# Analyze RDP configuration
results = engine.analyze(rdp_config)

# Get findings by severity
high_risk = results.get_findings(severity='high')
```

## Creating Custom Rules

1. Create a new `.rules` file in the appropriate directory
2. Define your rules using the YAML format
3. Test your rules using the test framework
4. Submit a pull request for review

## Testing Rules

Run the rule tests with:
```bash
pytest tests/detection_rules/
```

## Contributing

Please follow these guidelines when contributing new rules:
- Each rule should have a unique ID
- Include clear descriptions and references
- Provide actionable recommendations
- Test rules before submission
- Document any dependencies or requirements
