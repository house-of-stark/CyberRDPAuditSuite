# Contributing to CyberRDP Audit Suite

Thank you for your interest in contributing to the CyberRDP Audit Suite! We welcome contributions from the community to help improve this tool.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Enhancements](#suggesting-enhancements)
  - [Your First Code Contribution](#your-first-code-contribution)
  - [Pull Requests](#pull-requests)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [License](#license)

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the [issue tracker](https://github.com/yourusername/cyberrdp-audit-suite/issues) to see if the problem has already been reported. If it hasn't, please open a new issue with the following information:

- A clear and descriptive title
- Steps to reproduce the issue
- Expected behavior
- Actual behavior
- Screenshots if applicable
- Your environment (OS, Python version, etc.)

### Suggesting Enhancements

We welcome enhancement suggestions. Please open an issue with:

- A clear and descriptive title
- A detailed description of the enhancement
- Why this enhancement would be useful
- Any alternatives you've considered

### Your First Code Contribution

1. Fork the repository
2. Create a new branch: `git checkout -b feature/your-feature-name`
3. Make your changes
4. Add tests for your changes
5. Run the test suite to ensure tests pass
6. Commit your changes: `git commit -m 'Add some feature'`
7. Push to the branch: `git push origin feature/your-feature-name`
8. Open a pull request

### Pull Requests

1. Ensure your code follows the project's coding standards
2. Update the documentation as needed
3. Add tests for new functionality
4. Ensure all tests pass
5. Update the CHANGELOG.md with your changes
6. Submit the pull request with a clear description of the changes

## Development Setup

1. Fork and clone the repository
2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```
4. Run the test suite:
   ```bash
   pytest
   ```

## Coding Standards

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide
- Use type hints for all function signatures
- Write docstrings for all public modules, classes, and functions
- Keep functions small and focused on a single responsibility
- Write meaningful commit messages

### Code Formatting

We use the following tools to maintain code quality:

- **Black** for code formatting
- **isort** for import sorting
- **flake8** for linting
- **mypy** for type checking

Run these tools before committing:

```bash
black .
isort .
flake8
mypy .
```

## Testing

- Write tests for all new functionality
- Ensure all tests pass before submitting a pull request
- Maintain good test coverage
- Use pytest fixtures for test dependencies
- Mark integration tests with `@pytest.mark.integration`

## Documentation

- Update the README.md with any new features or changes
- Add docstrings to all public modules, classes, and functions
- Update the CHANGELOG.md with notable changes
- Add examples for new features

## License

By contributing to CyberRDP Audit Suite, you agree that your contributions will be licensed under its MIT License.
