#!/usr/bin/env python3
"""
Script to verify that all main scripts in the CyberRDP Audit Suite work with the new directory structure.
"""
import os
import sys
import importlib.util
import subprocess
from pathlib import Path

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# List of main scripts to test with their required arguments
SCRIPTS_TO_TEST = [
    {
        'name': 'cyberark_policy_validator.py',
        'args': ['--help'],
        'description': 'CyberArk Policy Validator',
        'required': True
    },
    {
        'name': 'rdp_auth_bypass_tester.py',
        'args': ['--help'],
        'description': 'RDP Authentication Bypass Tester',
        'required': True
    },
    {
        'name': 'rdp_session_hijack_tester.py',
        'args': ['--help'],
        'description': 'RDP Session Hijack Tester',
        'required': True
    },
    {
        'name': 'mfa_bypass_tester.py',
        'args': ['--help'],
        'description': 'MFA Bypass Tester',
        'required': False
    },
    {
        'name': 'rbac_validator.py',
        'args': ['--help'],
        'description': 'RBAC Validator',
        'required': False
    }
]

def check_script(script_info):
    """Check if a script runs with the given arguments."""
    script_path = os.path.join(os.getcwd(), script_info['name'])
    
    if not os.path.exists(script_path):
        if script_info['required']:
            print(f"❌ Missing required script: {script_info['name']}")
            return False
        print(f"⚠️  Optional script not found: {script_info['name']}")
        return None
    
    try:
        cmd = [sys.executable, script_path] + script_info['args']
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            print(f"✅ {script_info['description']} ({script_info['name']}) - Success")
            return True
        else:
            print(f"❌ {script_info['description']} ({script_info['name']}) - Failed with code {result.returncode}")
            if result.stderr:
                print(f"   Error: {result.stderr[:200]}...")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"⚠️  {script_info['description']} ({script_info['name']}) - Timed out")
        return False
    except Exception as e:
        print(f"❌ {script_info['description']} ({script_info['name']}) - Error: {str(e)}")
        return False

def check_imports():
    """Check if all required modules can be imported."""
    print("\n🔍 Checking module imports...")
    
    # List of core modules that should be importable
    core_modules = [
        'cyberark_policy_validator',
        'rdp_auth_bypass_tester',
        'rdp_session_hijack_tester',
        'mfa_bypass_tester',
        'rbac_validator',
        'shadow_session_tester',
        'virtual_channel_tester',
        'clipboard_security',
        'time_based_attacks',
        'credential_cache_tester'
    ]
    
    success = True
    for module in core_modules:
        try:
            importlib.import_module(module)
            print(f"✅ Import successful: {module}")
        except ImportError as e:
            print(f"❌ Import failed: {module} - {str(e)}")
            success = False
    
    return success

def check_directory_structure():
    """Verify the directory structure is as expected."""
    print("\n📁 Checking directory structure...")
    
    expected_dirs = [
        'analysis',
        'analysis/logs',
        'analysis/reports',
        'analysis/results',
        'analyzers',
        'detection_rules',
        'docs',
        'docs/analysis',
        'docs/development',
        'docs/guides',
        'docs/guides/analysis',
        'docs/references',
        'examples',
        'reports',
        'scripts',
        'scripts/analysis',
        'scripts/capture',
        'test_data',
        'test_reports',
        'tests',
        'tests/analyzers'
    ]
    
    missing_dirs = []
    for dir_path in expected_dirs:
        full_path = os.path.join(os.getcwd(), dir_path)
        if not os.path.exists(full_path):
            missing_dirs.append(dir_path)
    
    if missing_dirs:
        print("❌ Missing directories:")
        for dir_path in missing_dirs:
            print(f"   - {dir_path}")
        return False
    else:
        print("✅ All expected directories exist")
        return True

def main():
    print("🔍 CyberRDP Audit Suite - Script Validation Tool\n")
    
    # Change to the script's directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    os.chdir('../..')  # Move to project root
    
    print("📂 Working directory:", os.getcwd())
    
    # Check directory structure
    dir_check = check_directory_structure()
    
    # Check imports
    import_check = check_imports()
    
    # Check scripts
    print("\n🚀 Testing scripts...")
    script_results = []
    for script_info in SCRIPTS_TO_TEST:
        result = check_script(script_info)
        if result is not None:  # Only count non-None results (None means optional script not found)
            script_results.append(result)
    
    # Print summary
    print("\n📊 Summary:")
    print(f"- Directory structure: {'✅' if dir_check else '❌'}")
    print(f"- Module imports: {'✅' if import_check else '❌'}")
    
    if script_results:
        success_count = sum(1 for r in script_results if r)
        print(f"- Script tests: {success_count}/{len(script_results)} passed")
    
    if dir_check and import_check and all(script_results):
        print("\n🎉 All checks passed successfully!")
        return 0
    else:
        print("\n❌ Some checks failed. Please review the output above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
