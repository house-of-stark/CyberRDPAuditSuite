#!/usr/bin/env python3
"""
Setup script for CyberRDP Audit Suite.
"""

import os
import sys
from setuptools import setup, find_packages

# Read the long description from README.md
with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

# Read version from package
version = {}
with open(os.path.join('cyberrdp_audit_suite', '__init__.py'), 'r', encoding='utf-8') as f:
    exec(f.read(), version)

# Dependencies
install_requires = [
    'click>=8.0.0',
    'colorama>=0.4.4',
    'cryptography>=3.4.0',
    'python-dotenv>=0.19.0',
    'pyOpenSSL>=20.0.0',
    'requests>=2.26.0',
    'rich>=10.0.0',
]

tests_require = [
    'pytest>=6.2.0',
    'pytest-asyncio>=0.15.0',
    'pytest-cov>=2.12.0',
    'pytest-mock>=3.6.0',
]

setup(
    name='cyberrdp-audit-suite',
    version=version.get('__version__', '1.0.0'),
    description='Comprehensive RDP security assessment tool',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Your Name',
    author_email='your.email@example.com',
    url='https://github.com/yourusername/cyberrdp-audit-suite',
    packages=find_packages(include=['cyberrdp_audit_suite', 'cyberrdp_audit_suite.*']),
    package_data={
        'cyberrdp_audit_suite': ['data/*.json', 'templates/*.html'],
    },
    entry_points={
        'console_scripts': [
            'cyberrdp-audit=cyberrdp_audit_suite.cli.main:cli_entry_point',
            'rdp-audit=cyberrdp_audit_suite.cli.main:cli_entry_point',  # Alias for convenience
        ],
    },
    python_requires='>=3.8',
    install_requires=install_requires,
    extras_require={
        'test': tests_require,
        'dev': tests_require + [
            'black>=21.0',
            'flake8>=3.9.0',
            'isort>=5.0.0',
            'mypy>=0.900',
            'sphinx>=4.0.0',
            'sphinx-rtd-theme>=0.5.0',
        ],
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Topic :: Security',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
    ],
    keywords='rdp security audit scanner cybersec infosec',
    project_urls={
        'Bug Reports': 'https://github.com/yourusername/cyberrdp-audit-suite/issues',
        'Source': 'https://github.com/yourusername/cyberrdp-audit-suite',
    },
)
