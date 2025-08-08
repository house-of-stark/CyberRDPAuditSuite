# Test Data

This directory contains test data used for validating the CyberRDP Audit Suite functionality.

## Directory Structure

- `configs/` - Sample configuration files
- `gpo_backups/` - Sample Group Policy Object backups
- `logs/` - Sample log files for testing log parsing
- `reports/` - Sample report outputs for testing report generation
- `scripts/` - Test scripts and utilities

## Test Data Organization

### Sample Configurations
- `configs/secure_rdp.ini` - Example of secure RDP configuration
- `configs/insecure_rdp.ini` - Example of insecure RDP configuration
- `configs/mixed_rdp.ini` - Example with mixed security settings

### GPO Backups
- `gpo_backups/secure_gpo/` - Secure GPO settings
- `gpo_backups/insecure_gpo/` - Insecure GPO settings
- `gpo_backups/misconfigured_gpo/` - Common misconfigurations

## Usage

### Running Tests with Sample Data
```bash
# Run tests with sample data
pytest tests/ --test-data-dir=test_data/

# Run specific test with sample data
python -m pytest tests/test_rdp_config_analyzer.py -v --test-data-dir=test_data/
```

### Adding New Test Data
1. Place configuration files in the appropriate subdirectory
2. Update test cases to reference the new test data
3. Update this README if adding new categories of test data

## Test Data Generation

To generate additional test data:

```bash
# Generate sample RDP configuration
python scripts/generate_test_config.py --output test_data/configs/sample_rdp.ini

# Create test GPO backup
python scripts/create_test_gpo.py --name test_gpo --output test_data/gpo_backups/
```

## Notes

- Test data should be representative of real-world scenarios
- Include both positive and negative test cases
- Document any assumptions or special conditions for each test dataset
- Do not include sensitive or production data in test files
- Keep test data files small and focused on specific test cases
