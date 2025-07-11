# CyberRDP Audit Suite Release Checklist

This checklist outlines the steps required to prepare and publish a new release of the CyberRDP Audit Suite.

## Pre-Release Tasks

### Code Quality
- [ ] Run all tests: `pytest -v`
- [ ] Ensure test coverage is adequate: `pytest --cov=cyberrdp_audit_suite --cov-report=term-missing`
- [ ] Run linters: `flake8`, `black --check .`, `isort --check-only .`
- [ ] Run type checking: `mypy .`
- [ ] Fix all warnings and errors

### Documentation
- [ ] Update `CHANGELOG.md` with release notes
- [ ] Update version in `cyberrdp_audit_suite/__init__.py`
- [ ] Update version in `setup.py`
- [ ] Verify all command-line help text is accurate
- [ ] Update any references to version numbers in documentation
- [ ] Ensure all new features are documented

### Testing
- [ ] Test installation in a clean virtual environment
- [ ] Test all CLI commands
- [ ] Run against a test RDP server
- [ ] Test on multiple platforms (Windows, Linux, macOS)
- [ ] Verify all examples in documentation work as expected

## Release Process

### GitHub Release
- [ ] Create a release branch: `git checkout -b release/vX.Y.Z`
- [ ] Update version numbers and commit changes
- [ ] Create a pull request and merge to main
- [ ] Create a signed tag: `git tag -s vX.Y.Z -m "Version X.Y.Z"`
- [ ] Push the tag: `git push origin vX.Y.Z`
- [ ] Draft a new release on GitHub
  - [ ] Use the tag you just pushed
  - [ ] Title: "Version X.Y.Z"
  - [ ] Use the changelog entry as the description
  - [ ] Attach any additional files (binaries, etc.)
  - [ ] Publish the release

### PyPI Release
- [ ] Build the distribution packages:
  ```bash
  python setup.py sdist bdist_wheel
  ```
- [ ] Test the distribution packages:
  ```bash
  twine check dist/*
  pip install --no-index --find-links=dist/ cyberrdp-audit-suite
  ```
- [ ] Upload to PyPI Test:
  ```bash
  twine upload --repository testpypi dist/*
  ```
- [ ] Test installation from PyPI Test:
  ```bash
  pip install -i https://test.pypi.org/simple/ cyberrdp-audit-suite
  ```
- [ ] Upload to PyPI:
  ```bash
  twine upload dist/*
  ```

## Post-Release Tasks

- [ ] Update documentation with new installation instructions
- [ ] Announce the release on relevant channels
- [ ] Monitor for any issues reported by users
- [ ] Close the milestone for this release
- [ ] Create a new milestone for the next release
- [ ] Update the development version in `__init__.py` to the next development version

## Rollback Plan

In case of issues with the release:

1. Remove the PyPI release if possible
2. Delete the GitHub release and tag
3. Revert the version bump commit
4. Document the issue and plan a patch release

## Verification

After release, verify the following:

- [ ] Package installs correctly: `pip install cyberrdp-audit-suite`
- [ ] CLI commands work as expected
- [ ] Documentation is up-to-date
- [ ] All tests pass with the released version
