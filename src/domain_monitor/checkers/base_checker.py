"""
Base checker infrastructure for domain monitoring.

Provides abstract base class and result dataclass for all checker implementations.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional


@dataclass
class CheckResult:
    """
    Result of a domain check operation.
    
    Attributes:
        domain: The domain name that was checked
        check_type: Type of check performed (e.g., 'whois', 'ssl', 'http')
        status: Status of the check (OK, WARNING, ERROR, CRITICAL)
        message: Human-readable message describing the result
        details: Additional structured data about the check result
        timestamp: When the check was performed
    """
    domain: str
    check_type: str
    status: str
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    
    # Status constants
    OK = "OK"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class BaseChecker(ABC):
    """
    Abstract base class for all domain checkers.
    
    All checker implementations must inherit from this class and implement
    the check() method. Provides common functionality like timeout configuration
    and result creation.
    """
    
    def __init__(self, timeout: int = 10):
        """
        Initialize the checker.
        
        Args:
            timeout: Maximum time in seconds to wait for check completion (default: 10)
        """
        self.timeout = timeout
    
    @abstractmethod
    async def check(self, domain: str, **kwargs) -> CheckResult:
        """
        Execute the check for the specified domain.
        
        This method must be implemented by all subclasses to perform
        the specific check logic.
        
        Args:
            domain: The domain name to check
            **kwargs: Additional parameters specific to the check type
            
        Returns:
            CheckResult object containing the check results
            
        Raises:
            Various exceptions depending on the check type
        """
        pass
    
    def _create_result(
        self,
        domain: str,
        status: str,
        message: str,
        details: Optional[Dict[str, Any]] = None
    ) -> CheckResult:
        """
        Helper method to create CheckResult objects.
        
        Args:
            domain: The domain name that was checked
            status: Status of the check (use CheckResult constants)
            message: Human-readable message describing the result
            details: Optional additional structured data
            
        Returns:
            CheckResult object with the specified parameters
        """
        return CheckResult(
            domain=domain,
            check_type=self.__class__.__name__.replace('Checker', '').lower(),
            status=status,
            message=message,
            details=details or {},
            timestamp=datetime.now()
        )
