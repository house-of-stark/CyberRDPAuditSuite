"""
CyberRDP Audit Suite - A comprehensive security assessment tool for RDP services.

This package provides tools for auditing and assessing the security of RDP (Remote Desktop Protocol)
services. It includes various scanners for detecting security misconfigurations, vulnerabilities,
and potential attack vectors in RDP implementations.
"""

__version__ = "1.0.0"
__author__ = "Your Name <your.email@example.com>"
__license__ = "MIT"

# Import core components to make them available at the package level
from cyberrdp_audit_suite.core.runner import run_audit, AuditResult
from cyberrdp_audit_suite.core.scanners import (
    get_available_scanners,
    BaseScanner,
    PortScanner,
    AuthBypassScanner,
    EncryptionScanner,
    NLAScanner,
    RDPSecurityScanner,
)

# Make these available when importing from the package
__all__ = [
    'run_audit',
    'AuditResult',
    'get_available_scanners',
    'BaseScanner',
    'PortScanner',
    'AuthBypassScanner',
    'EncryptionScanner',
    'NLAScanner',
    'RDPSecurityScanner',
]
