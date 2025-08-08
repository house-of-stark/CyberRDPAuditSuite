#!/usr/bin/env python3
"""
Script to verify that all imports and modules work with the new directory structure.
"""
import sys
import os
import importlib.util
import pkgutil
from pathlib import Path

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# List of main modules to test
MODULES_TO_TEST = [
    'cyberark_policy_validator',
    'cyberark_policy_auth_validator',
    'cyberark_policy_session_validator',
    'cyberark_policy_redirection_validator',
    'rdp_auth_bypass_tester',
    'rdp_session_hijack_tester',
    'rdp_bluekeep_tester',
    'rdp_relay_attack_tester',
    'mfa_bypass_tester',
    'rbac_validator',
    'shadow_session_tester',
    'virtual_channel_tester',
    'clipboard_security',
    'time_based_attacks',
    'credential_cache_tester'
]

def test_import(module_name):
    """Test importing a module and print the result."""
    try:
        module = importlib.import_module(module_name)
        print(f"✅ Successfully imported {module_name} (version: {getattr(module, '__version__', 'N/A')})")
        return True
    except Exception as e:
        print(f"❌ Failed to import {module_name}: {str(e)}")
        return False

def find_missing_imports():
    """Find modules that are imported but not found."""
    print("\n🔍 Checking for missing imports in all Python files...")
    
    # Get all Python files in the project
    python_files = []
    for root, _, files in os.walk('.'):
        if any(d in root for d in ['venv', '__pycache__', '.git', 'dist', 'build']):
            continue
        for file in files:
            if file.endswith('.py'):
                python_files.append(os.path.join(root, file))
    
    # Check imports in each file
    import_patterns = [
        r'^import\s+([^\s.]+)',
        r'^from\s+([^\s.]+)\s+import',
        r'^import\s+([^\s.]+\.[^\s.]+)'
    ]
    
    missing_imports = set()
    
    for py_file in python_files:
        try:
            with open(py_file, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # Check for relative imports
                if 'from .' in content or 'import .' in content:
                    print(f"⚠️  Found relative import in {py_file}")
                    
                # Check for common import issues
                for pattern in import_patterns:
                    import re
                    matches = re.finditer(pattern, content, re.MULTILINE)
                    for match in matches:
                        module_name = match.group(1)
                        if not module_name.startswith(('os', 'sys', 're', 'json', 'time', 'datetime', 'logging')):
                            try:
                                importlib.import_module(module_name)
                            except (ImportError, ModuleNotFoundError):
                                missing_imports.add(module_name)
                                print(f"   - Missing import in {os.path.basename(py_file)}: {module_name}")
        except Exception as e:
            print(f"⚠️  Error checking {py_file}: {str(e)}")
    
    if missing_imports:
        print("\n❌ Missing imports found:")
        for imp in sorted(missing_imports):
            print(f"   - {imp}")
    else:
        print("\n✅ No missing imports found!")

def main():
    print("🔍 Testing imports with new directory structure...\n")
    
    # Test importing main modules
    success_count = 0
    for module in MODULES_TO_TEST:
        if test_import(module):
            success_count += 1
    
    # Check for missing imports
    find_missing_imports()
    
    # Print summary
    print(f"\n📊 Summary:")
    print(f"   - Tested {len(MODULES_TO_TEST)} modules")
    print(f"   - {success_count} modules imported successfully")
    print(f"   - {len(MODULES_TO_TEST) - success_count} modules had issues")
    
    if success_count == len(MODULES_TO_TEST):
        print("\n✅ All tests passed successfully!")
        return 0
    else:
        print("\n❌ Some tests failed. Please check the output above for details.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
