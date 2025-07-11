"""
CyberRDP Audit Suite - Security Scanners

This package contains security scanner implementations for the CyberRDP Audit Suite.
"""

from __future__ import annotations
from typing import Dict, Type, List, Any, Optional, TYPE_CHECKING, TypeVar, cast
import importlib
import warnings

# Type variable for BaseScanner
if TYPE_CHECKING:
    from .base_scanner import BaseScanner
    B = TypeVar('B', bound='BaseScanner')
else:
    B = TypeVar('B')

# Global scanner registry - use string literals for type hints to avoid circular imports
SCANNER_REGISTRY: Dict[str, Type['BaseScanner']] = {}

class ScannerRegistry:
    """Registry for all available security scanners."""
    
    @classmethod
    def register(cls, scanner_class: Type[B]) -> Type[B]:
        """Register a scanner class in the registry.
        
        If the scanner is already registered, this is a no-op and the existing
        registration is preserved.
        
        Returns:
            The registered scanner class
        """
        # Late import to avoid circular imports
        from .base_scanner import BaseScanner
        
        if not issubclass(scanner_class, BaseScanner):
            raise TypeError(f"{scanner_class.__name__} must be a subclass of BaseScanner")
        
        scanner_name = scanner_class.__name__
        if scanner_name not in SCANNER_REGISTRY:
            SCANNER_REGISTRY[scanner_name] = scanner_class
            
        return cast(Type[B], scanner_class)
    
    @classmethod
    def get_scanner_class(cls, name: str) -> Optional[Type['BaseScanner']]:
        """Get a scanner class by name."""
        return SCANNER_REGISTRY.get(name)
    
    @classmethod
    def get_available_scanners(cls) -> List[Type['BaseScanner']]:
        """Get all registered scanner classes."""
        return list(SCANNER_REGISTRY.values())
    
    @classmethod
    def initialize_scanners(
        cls, 
        scanner_classes: List[Type['BaseScanner']],
        **kwargs: Any
    ) -> List['BaseScanner']:
        """Initialize scanner instances with the given configuration."""
        return [scanner_class(**kwargs) for scanner_class in scanner_classes]

# Import base_scanner after defining ScannerRegistry to avoid circular imports
from .base_scanner import BaseScanner  # noqa: E402

# Import and register all scanner classes
from .port_scanner import PortScanner  # noqa: E402
from .auth_bypass_scanner import AuthBypassScanner  # noqa: E402
from .encryption_scanner import EncryptionScanner  # noqa: E402
from .nla_scanner import NLAScanner  # noqa: E402
from .rdp_security_scanner import RDPSecurityScanner  # noqa: E402
from .credential_caching_scanner import CredentialCachingScanner  # noqa: E402

# Re-export for easier imports
__all__ = [
    # Core classes
    'BaseScanner',
    'ScannerRegistry',
    
    # Scanner implementations
    'PortScanner',
    'AuthBypassScanner',
    'EncryptionScanner',
    'NLAScanner',
    'RDPSecurityScanner',
    'CredentialCachingScanner',
    
    # Utility functions
    'get_available_scanners',
    'initialize_scanners',
]

def get_available_scanners() -> List[Type[BaseScanner]]:
    """Get all registered scanner classes."""
    return ScannerRegistry.get_available_scanners()

def initialize_scanners(
    scanner_classes: List[Type[BaseScanner]],
    **kwargs: Any
) -> List[BaseScanner]:
    """Initialize scanner instances with the given configuration."""
    return ScannerRegistry.initialize_scanners(scanner_classes, **kwargs)

def _import_scanner_modules() -> None:
    """Dynamically import all scanner modules.
    
    Note: This is kept for backward compatibility but is no longer needed
    as we now explicitly import all scanner classes above.
    """
    pass  # No longer needed as we import all scanners explicitly

# We're explicitly importing all scanner classes above, so no need to call _import_scanner_modules()
# This prevents duplicate registration of scanner classes
