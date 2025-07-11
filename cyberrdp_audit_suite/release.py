#!/usr/bin/env python3
"""
Release script for CyberRDP Audit Suite.

This script automates the release process, including version bumping,
tagging, and publishing to PyPI.
"""

import re
import sys
import subprocess
import argparse
from pathlib import Path
from typing import Optional, Tuple
from datetime import datetime

# File paths
ROOT_DIR = Path(__file__).parent
INIT_FILE = ROOT_DIR / "cyberrdp_audit_suite" / "__init__.py"
SETUP_FILE = ROOT_DIR / "setup.py"
CHANGELOG_FILE = ROOT_DIR / "CHANGELOG.md"

class ReleaseError(Exception):
    """Custom exception for release-related errors."""
    pass

def get_current_version() -> str:
    """Get the current version from __init__.py."""
    content = INIT_FILE.read_text()
    match = re.search(r'^__version__ = ["\']([^"\']+)["\']', content, re.M)
    if not match:
        raise ReleaseError("Could not find __version__ in __init__.py")
    return match.group(1)

def update_version(new_version: str) -> None:
    """Update version in all relevant files."""
    # Update __init__.py
    content = INIT_FILE.read_text()
    content = re.sub(
        r'^(__version__ = ["\'])[^"\']+(["\'])',
        f'\\g<1>{new_version}\\g<2>',
        content,
        flags=re.M
    )
    INIT_FILE.write_text(content)
    
    # Update setup.py
    content = SETUP_FILE.read_text()
    content = re.sub(
        r'(version=["\'])[^"\']+(["\'])',
        f'\\g<1>{new_version}\\g<2>',
        content,
        flags=re.M
    )
    SETUP_FILE.write_text(content)
    
    print(f"Updated version to {new_version} in {INIT_FILE} and {SETUP_FILE}")

def update_changelog(version: str, release_date: str = None) -> None:
    """Update the changelog with the new version."""
    if not release_date:
        release_date = datetime.now().strftime("%Y-%m-%d")
    
    content = CHANGELOG_FILE.read_text()
    
    # Replace "Unreleased" with the new version and date
    new_content = re.sub(
        r'^## \[Unreleased\]\n',
        f"## [Unreleased]\n\n## [{version}] - {release_date}\n",
        content,
        flags=re.M
    )
    
    if new_content == content:
        raise ReleaseError("Failed to update changelog - could not find 'Unreleased' section")
    
    CHANGELOG_FILE.write_text(new_content)
    print(f"Updated {CHANGELOG_FILE} for version {version}")

def run_command(cmd: str, cwd: Optional[Path] = None) -> Tuple[bool, str]:
    """Run a shell command and return (success, output)."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            cwd=cwd or ROOT_DIR,
            check=True,
            text=True,
            capture_output=True
        )
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        return False, f"Command failed with code {e.returncode}: {e.stderr}"

def check_git_clean() -> bool:
    """Check if the git working directory is clean."""
    success, output = run_command("git status --porcelain")
    if not success:
        raise ReleaseError(f"Failed to check git status: {output}")
    return not bool(output.strip())

def create_git_tag(version: str, message: str = None) -> bool:
    """Create a git tag for the release."""
    if not message:
        message = f"Version {version}"
    
    tag_name = f"v{version}"
    success, output = run_command(f"git tag -a {tag_name} -m '{message}'")
    if not success:
        raise ReleaseError(f"Failed to create git tag: {output}")
    
    print(f"Created git tag: {tag_name}")
    return True

def build_distribution() -> bool:
    """Build the distribution packages."""
    # Clean up any existing builds
    run_command("rm -rf build dist *.egg-info")
    
    # Build the package
    success, output = run_command("python setup.py sdist bdist_wheel")
    if not success:
        raise ReleaseError(f"Failed to build distribution: {output}")
    
    print("Successfully built distribution packages")
    return True

def check_distribution() -> bool:
    """Check the distribution packages with twine."""
    success, output = run_command("twine check dist/*")
    if not success:
        raise ReleaseError(f"Distribution check failed: {output}")
    
    print("Distribution packages passed twine check")
    return True

def upload_to_pypi(test: bool = False) -> bool:
    """Upload the package to PyPI or TestPyPI."""
    repo = "--repository testpypi" if test else ""
    success, output = run_command(f"twine upload {repo} dist/*")
    if not success:
        raise ReleaseError(f"Failed to upload to {'TestPyPI' if test else 'PyPI'}: {output}")
    
    print(f"Successfully uploaded to {'TestPyPI' if test else 'PyPI'}")
    return True

def main() -> int:
    """Main entry point for the release script."""
    parser = argparse.ArgumentParser(description="Release script for CyberRDP Audit Suite")
    parser.add_argument("version", help="Version number to release (e.g., 1.0.0)")
    parser.add_argument("--date", help="Release date in YYYY-MM-DD format")
    parser.add_argument("--test", action="store_true", help="Upload to TestPyPI instead of PyPI")
    parser.add_argument("--dry-run", action="store_true", help="Don't actually make any changes")
    
    args = parser.parse_args()
    
    if not re.match(r'^\d+\.\d+\.\d+$', args.version):
        print("Error: Version must be in format X.Y.Z", file=sys.stderr)
        return 1
    
    try:
        current_version = get_current_version()
        print(f"Current version: {current_version}")
        print(f"New version:     {args.version}")
        print(f"Dry run:         {'yes' if args.dry_run else 'no'}")
        
        if not args.dry_run:
            # Check for uncommitted changes
            if not check_git_clean():
                print("Error: Working directory is not clean. Please commit or stash changes.", file=sys.stderr)
                return 1
            
            # Update version in files
            update_version(args.version)
            update_changelog(args.version, args.date)
            
            # Create a commit
            run_command(f'git commit -a -m "Bump version to {args.version}"')
            
            # Create a tag
            create_git_tag(args.version)
            
            # Build the distribution
            build_distribution()
            check_distribution()
            
            # Upload to PyPI
            if input(f"Upload to {'TestPyPI' if args.test else 'PyPI'}? [y/N] ").lower() == 'y':
                upload_to_pypi(test=args.test)
            
            print("\nRelease steps completed successfully!")
            print("Next steps:")
            print(f"1. Push the tag: git push origin v{args.version}")
            print("2. Create a GitHub release")
            print("3. Update documentation with new version information")
        else:
            print("\nDry run complete. No changes were made.")
        
        return 0
    except ReleaseError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nRelease process cancelled by user.", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
