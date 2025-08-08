# Analysis Directory

This directory contains analysis tools, scripts, and results for the CyberRDP Audit Suite.

## Directory Structure

- `logs/` - Log files generated during analysis
- `reports/` - Generated analysis reports in various formats (PDF, HTML, CSV)
- `results/` - Raw analysis results and intermediate data files

## Analysis Process

1. **Data Collection**: Scripts in the parent directory capture RDP configuration and session data
2. **Analysis**: Analysis scripts process the collected data to identify security issues
3. **Reporting**: Generate human-readable reports from the analysis results

## File Naming Convention

- Log files: `YYYYMMDD_HHMMSS_<analysis_type>.log`
- Report files: `YYYYMMDD_<target>_<analysis_type>_report.<format>`
- Result files: `<target>_<analysis_type>_results.json`

## Available Analysis Scripts

- `analyze_rdp_security.py` - Main security analysis script
- `generate_compliance_report.py` - Generates compliance reports against standards
- `compare_configs.py` - Compares configurations against baselines

## Dependencies

- Python 3.8+
- Required Python packages are listed in `requirements.txt`

## Usage

```bash
# Run basic security analysis
python3 analysis/analyze_rdp_security.py -t <target> -o analysis/results/

# Generate compliance report
python3 analysis/generate_compliance_report.py -i analysis/results/ -o analysis/reports/
```

## Notes

- Always review the analysis results carefully before taking any action
- Keep sensitive information secure and follow data handling policies
- Regularly back up important analysis results and reports
