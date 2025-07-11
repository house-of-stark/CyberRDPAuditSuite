# Changelog

All notable changes to the CyberRDP Audit Suite will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2025-07-10
### Added
- **Credential Caching Scanner**: New scanner module to detect cached RDP credentials on Windows and Linux systems
- Tests for Windows credential store locations (AppData, LocalAppData, .rdp files)
- Tests for Linux credential stores (Remmina, FreeRDP configurations)
- Integration with existing scanner registry and test runner
- Comprehensive test cases for credential caching scenarios

## [1.0.0] - 2025-06-24
### Added
- Initial release of CyberRDP Audit Suite (rebranded from RDP Security Settings Scanner)
- Comprehensive RDP security testing capabilities
- Policy validation against security baselines
- Advanced attack scenario testing (Relay, Session Hijack, BlueKeep, Authentication Bypass)
- Detailed reporting and documentation

### Changed
- Rebranded from "RDP Security Settings Scanner" to "CyberRDP Audit Suite"
- Updated all documentation with new branding
- Improved command-line interface and help text
- Enhanced error handling and logging

### Fixed
- Syntax issues in policy validator
- Navigation and cross-references in documentation
- Consistent naming conventions throughout the codebase

### Security
- Updated security policies and validation rules
- Enhanced authentication and session security testing
- Improved handling of sensitive information in logs and reports
