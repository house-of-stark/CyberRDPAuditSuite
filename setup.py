#!/usr/bin/env python3

from setuptools import setup, find_packages

VERSION = "1.0.0"
RELEASE_DATE = "2025-06-24"

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="cyberrdp-audit-suite",
    version=VERSION,
    author="CyberArk Labs",
    author_email="labs@cyberark.com",
    description="Comprehensive RDP Security Assessment Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/cyberark/cyberrdp-audit-suite",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
    python_requires='>=3.6',
    install_requires=[
        'pywinrm>=0.4.3',
        'requests>=2.25.1',
        'colorama>=0.4.4',
        'python-nmap>=0.7.1',
        'pycryptodome>=3.10.1',
        'pytest>=6.2.5',
    ],
    entry_points={
        'console_scripts': [
            'cyberrdp-audit=run_comprehensive_tests:main',
            'cyberrdp-policy-validator=cyberark_policy_validator_main:main',
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
