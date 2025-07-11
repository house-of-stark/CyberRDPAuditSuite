# Test Execution Reports

This directory contains detailed test execution reports and logs from the CyberRDP Audit Suite.

## Contents

- **Test Results**: Detailed results from individual test executions
- **Execution Logs**: Logs containing runtime information and debug output
- **Temporary Files**: Intermediate files generated during test execution

## File Naming Convention

Test report files typically follow this pattern:

```
[test_type]_[target]_[date]_[time].[format]
```

Example: `rdp_bluekeep_127.0.0.1_20250623_190236.json`

## Understanding the Reports

- **JSON Reports**: Contain structured test results that can be processed programmatically
- **Log Files**: Provide detailed execution information for troubleshooting
- **Temporary Files**: Used during test execution (can be safely deleted)

## Notes

- These files are generated automatically during test execution
- Historical test results are preserved with timestamps for comparison
- Some files may contain sensitive information - handle with appropriate security measures
- Temporary files can be safely deleted between test runs
