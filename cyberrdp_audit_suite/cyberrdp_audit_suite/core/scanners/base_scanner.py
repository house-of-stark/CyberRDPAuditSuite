"""
CyberRDP Audit Suite - Base Scanner

This module contains the base scanner class that all security scanners should inherit from.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
import logging
from datetime import datetime

from ..scanners import ScannerRegistry

logger = logging.getLogger(__name__)

class BaseScanner(ABC):
    """Base class for all security scanners.
    
    This class defines the interface that all security scanners must implement.
    Subclasses should override the `run()` method to implement the actual scanning logic.
    """
    
    # Scanner metadata
    name: str = "Base Scanner"
    description: str = "Base class for all security scanners"
    
    # Default severity levels
    SEVERITY_CRITICAL = "CRITICAL"
    SEVERITY_HIGH = "HIGH"
    SEVERITY_MEDIUM = "MEDIUM"
    SEVERITY_LOW = "LOW"
    SEVERITY_INFO = "INFO"
    
    def __init__(
        self,
        target: str,
        port: int = 3389,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        **kwargs
    ):
        """Initialize the scanner with target information.
        
        Args:
            target: Target IP address or hostname
            port: Target port (default: 3389)
            username: Username for authentication (if needed)
            password: Password for authentication (if needed)
            domain: Domain for authentication (if needed)
            **kwargs: Additional scanner-specific arguments
        """
        self.target = target
        self.port = port
        self.username = username
        self.password = password
        self.domain = domain
        self.vulnerabilities: List[Dict[str, Any]] = []
        
        # Store any additional arguments
        self.config = kwargs
        
        # Set the name to the class name if not overridden
        if self.__class__.name == "Base Scanner":
            self.name = self.__class__.__name__
    
    def __init_subclass__(cls, **kwargs):
        """Register scanner subclasses in the registry."""
        super().__init_subclass__(**kwargs)
        if cls.__name__ != 'BaseScanner':
            ScannerRegistry.register(cls)
    
    @abstractmethod
    async def run(self) -> Dict[str, Any]:
        """Run the security scan.
        
        This method must be implemented by subclasses to perform the actual scanning.
        
        Returns:
            Dict containing the scan results. The dict should include at least:
            - 'status': 'PASSED', 'FAILED', or 'ERROR'
            - 'details': Detailed results of the scan
            - 'timestamp': When the scan was completed
        """
        pass
    
    def add_vulnerability(
        self,
        name: str,
        description: str,
        severity: str,
        details: Dict[str, Any] = None,
        remediation: str = "",
        references: List[str] = None
    ) -> None:
        """Add a vulnerability finding.
        
        Args:
            name: Short name/identifier of the vulnerability
            description: Detailed description of the vulnerability
            severity: Severity level (use class constants: SEVERITY_*)
            details: Additional details about the finding
            remediation: Recommended remediation steps
            references: List of reference URLs or documents
        """
        if details is None:
            details = {}
        if references is None:
            references = []
            
        vuln = {
            'name': name,
            'description': description,
            'severity': severity,
            'details': details,
            'remediation': remediation,
            'references': references,
            'timestamp': datetime.utcnow().isoformat(),
            'scanner': self.name,
            'target': self.target,
            'port': self.port
        }
        
        self.vulnerabilities.append(vuln)
        logger.warning(f"Vulnerability found: {name} ({severity})")
    
    def log_info(self, message: str) -> None:
        """Log an informational message."""
        logger.info(f"[{self.name}] {message}")
    
    def log_warning(self, message: str) -> None:
        """Log a warning message."""
        logger.warning(f"[{self.name}] {message}")
    
    def log_error(self, message: str) -> None:
        """Log an error message."""
        logger.error(f"[{self.name}] {message}")
    
    def log_debug(self, message: str) -> None:
        """Log a debug message."""
        logger.debug(f"[{self.name}] {message}")
    
    def get_base_result(self) -> Dict[str, Any]:
        """Get a base result dictionary with common fields."""
        return {
            'scanner': self.name,
            'target': self.target,
            'port': self.port,
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'UNKNOWN',
            'details': {}
        }
