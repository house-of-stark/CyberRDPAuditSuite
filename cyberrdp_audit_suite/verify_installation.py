#!/usr/bin/env python3
"""
Verification script for CyberRDP Audit Suite installation.

This script verifies that the package is properly installed and all components
are functioning as expected.
"""

import sys
import importlib
import pkg_resources
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('verify_installation')

# Expected package metadata
EXPECTED_PACKAGE = 'cyberrdp_audit_suite'
EXPECTED_VERSION = '1.0.0'
EXPECTED_DEPENDENCIES = [
    'click>=8.0.0',
    'colorama>=0.4.4',
    'cryptography>=3.4.0',
    'python-dotenv>=0.19.0',
    'pyOpenSSL>=20.0.0',
    'requests>=2.26.0',
    'rich>=10.0.0',
]

def check_python_version():
    """Verify Python version meets requirements."""
    logger.info("Checking Python version...")
    if sys.version_info < (3, 8):
        logger.error("Python 3.8 or higher is required")
        return False
    logger.info(f"Python {sys.version.split()[0]} is compatible")
    return True

def check_package_installation():
    """Verify the package is properly installed."""
    logger.info(f"Checking if {EXPECTED_PACKAGE} is installed...")
    
    try:
        dist = pkg_resources.get_distribution(EXPECTED_PACKAGE)
        logger.info(f"Found {dist.project_name} version {dist.version}")
        
        if dist.version != EXPECTED_VERSION:
            logger.warning(
                f"Version mismatch: Expected {EXPECTED_VERSION}, found {dist.version}"
            )
        
        return True
    except pkg_resources.DistributionNotFound:
        logger.error(f"Package {EXPECTED_PACKAGE} is not installed")
        return False
    except Exception as e:
        logger.error(f"Error checking package installation: {e}")
        return False

def check_dependencies():
    """Verify all required dependencies are installed."""
    logger.info("Checking dependencies...")
    missing_deps = []
    wrong_version = []
    
    for dep in EXPECTED_DEPENDENCIES:
        try:
            # Handle version specifiers
            if '>=' in dep:
                name, version = dep.split('>=')
                name = name.strip()
                version = version.strip()
                pkg_resources.require(f"{name}>={version}")
            else:
                pkg_resources.require(dep)
            logger.debug(f"Dependency found: {dep}")
        except pkg_resources.DistributionNotFound:
            missing_deps.append(dep)
        except pkg_resources.VersionConflict as e:
            wrong_version.append(f"{dep} (found: {e.dist.version})")
    
    if missing_deps or wrong_version:
        for dep in missing_deps:
            logger.error(f"Missing dependency: {dep}")
        for dep in wrong_version:
            logger.error(f"Incorrect version: {dep}")
        return False
    
    logger.info("All dependencies are satisfied")
    return True

def check_imports():
    """Verify that all required modules can be imported."""
    logger.info("Checking imports...")
    modules = [
        'cyberrdp_audit_suite',
        'cyberrdp_audit_suite.core',
        'cyrdp_audit_suite.core.runner',
        'cyberrdp_audit_suite.core.scanners',
        'cyberrdp_audit_suite.cli',
    ]
    
    for module_name in modules:
        try:
            importlib.import_module(module_name)
            logger.debug(f"Successfully imported: {module_name}")
        except ImportError as e:
            logger.error(f"Failed to import {module_name}: {e}")
            return False
    
    logger.info("All required modules can be imported")
    return True

def check_cli():
    """Verify that the CLI entry points are working."""
    logger.info("Checking CLI entry points...")
    
    # Check if the main CLI command is available
    try:
        from cyberrdp_audit_suite.cli.main import cli_entry_point
        logger.info("CLI entry point found")
        return True
    except ImportError as e:
        logger.error(f"Failed to import CLI entry point: {e}")
        return False

def check_data_files():
    """Verify that all required data files are present."""
    logger.info("Checking data files...")
    
    # List of required data files
    data_files = [
        'README.md',
        'CHANGELOG.md',
        'CONTRIBUTING.md',
        'CODE_OF_CONDUCT.md',
        'LICENSE',
    ]
    
    missing_files = []
    for file_path in data_files:
        if not Path(file_path).exists():
            missing_files.append(file_path)
    
    if missing_files:
        for file_path in missing_files:
            logger.error(f"Missing file: {file_path}")
        return False
    
    logger.info("All required data files are present")
    return True

def run_verification():
    """Run all verification checks."""
    logger.info("Starting CyberRDP Audit Suite verification")
    logger.info("=" * 40)
    
    checks = [
        ("Python Version", check_python_version),
        ("Package Installation", check_package_installation),
        ("Dependencies", check_dependencies),
        ("Imports", check_imports),
        ("CLI Entry Points", check_cli),
        ("Data Files", check_data_files),
    ]
    
    results = []
    for name, check_func in checks:
        logger.info(f"\nVerifying {name}...")
        try:
            result = check_func()
            status = "PASSED" if result else "FAILED"
            results.append((name, status, result))
            logger.info(f"{name}: {status}")
        except Exception as e:
            logger.error(f"Error during {name} check: {e}", exc_info=True)
            results.append((name, "ERROR", False))
    
    # Print summary
    logger.info("\n" + "=" * 40)
    logger.info("VERIFICATION SUMMARY")
    logger.info("=" * 40)
    
    all_passed = True
    for name, status, result in results:
        logger.info(f"{name}: {status}")
        if not result:
            all_passed = False
    
    if all_passed:
        logger.info("\nVERIFICATION COMPLETED SUCCESSFULLY")
    else:
        logger.error("\nVERIFICATION FAILED - Some checks did not pass")
    
    return all_passed

if __name__ == "__main__":
    success = run_verification()
    sys.exit(0 if success else 1)
