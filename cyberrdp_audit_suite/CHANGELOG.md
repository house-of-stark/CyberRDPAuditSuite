# Changelog

All notable changes to the CyberRDP Audit Suite will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive test coverage for all scanner modules
- Integration tests for core functionality
- Detailed error reporting and logging
- Support for custom scanner implementations
- Automated test runner script

### Changed
- Refactored scanner architecture for better extensibility
- Improved error handling in async operations
- Enhanced test reliability and coverage
- Updated documentation with usage examples

### Fixed
- Fixed async/await handling in test suite
- Resolved scanner initialization issues
- Addressed test reliability issues
- Fixed error handling for invalid scanner configurations

## [1.0.0] - 2025-06-24

### Added
- Initial public release of CyberRDP Audit Suite
- Core security scanning capabilities including:
  - Port scanning
  - Authentication bypass detection
  - Encryption configuration analysis
  - Network Level Authentication (NLA) checks
  - RDP security layer validation
- Support for multiple output formats (console, JSON)
- Comprehensive test coverage with unit and integration tests
- Detailed documentation and usage examples
- Modular scanner architecture for easy extension

### Changed
- Project structure optimized for packaging and distribution
- Improved error handling and user feedback
- Enhanced security checks and validations
- Refactored core components for better maintainability
- Updated to use modern Python async/await patterns

### Fixed
- Various bug fixes and stability improvements
- Resolved issues with scanner initialization
- Fixed test reliability issues
- Addressed deprecation warnings
- Improved error messages and logging

## [0.1.0] - 2025-05-15

### Added
- Initial development version
- Basic RDP security scanning functionality
- Core framework for security tests
- Basic reporting capabilities

### Changed
- Project structure and organization
- Code quality and documentation improvements

### Fixed
- Initial bug fixes and stability improvements
