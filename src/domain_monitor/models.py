"""Data models for live status monitoring."""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, List
from urllib.parse import urlparse
import json
import re


# Valid HTTP methods for endpoint configuration
VALID_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

# Sensitive header keys that should be masked
SENSITIVE_HEADER_KEYS = {
    "authorization",
    "api-key",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
    "cookie",
    "set-cookie",
    "proxy-authorization",
}


def mask_sensitive_headers(headers: Optional[Dict[str, str]]) -> Optional[Dict[str, str]]:
    """Mask sensitive header values for display/logging.
    
    Args:
        headers: Dictionary of HTTP headers or None
        
    Returns:
        Dictionary with sensitive values masked or None if input is None
    """
    if not headers:
        return headers
    
    masked = {}
    for key, value in headers.items():
        key_lower = key.lower()
        if key_lower in SENSITIVE_HEADER_KEYS:
            # Mask the value, showing only first 4 chars if long enough
            if len(value) > 8:
                masked[key] = f"{value[:4]}***"
            else:
                masked[key] = "***"
        else:
            masked[key] = value
    
    return masked


def sanitize_string(text: str, max_length: int = 200) -> str:
    """Sanitize string for safe display by removing control characters and limiting length.
    
    Args:
        text: String to sanitize
        max_length: Maximum allowed length
        
    Returns:
        Sanitized string
    """
    if not text:
        return text
    
    # Remove control characters except newline and tab
    sanitized = re.sub(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f-\x9f]', '', text)
    
    # Limit length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length - 3] + "..."
    
    return sanitized


def validate_json_body(body: str) -> None:
    """Validate that body is valid JSON.
    
    Args:
        body: JSON string to validate
        
    Raises:
        ValueError: If body is not valid JSON
    """
    try:
        json.loads(body)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON body: {e}") from e


@dataclass
class EndpointConfig:
    """Configuration for an HTTP endpoint to monitor."""
    name: str  # Display name/identifier
    url: str  # Full URL including path
    method: str = "GET"  # HTTP method
    headers: Optional[Dict[str, str]] = None  # Custom headers
    body: Optional[str] = None  # Request body (JSON string or plain text)
    timeout: float = 5.0  # Request timeout in seconds
    
    def __post_init__(self):
        """Validate configuration after initialization."""
        # Validate HTTP method
        if self.method.upper() not in VALID_HTTP_METHODS:
            raise ValueError(
                f"Invalid HTTP method '{self.method}'. "
                f"Must be one of: {', '.join(sorted(VALID_HTTP_METHODS))}"
            )
        self.method = self.method.upper()
        
        # Validate and sanitize URL
        self._validate_url()
        
        # Sanitize endpoint name
        self.name = sanitize_string(self.name, max_length=100)
        
        # Validate JSON body if Content-Type is application/json
        if self.body and self.headers:
            content_type = self.headers.get("Content-Type") or self.headers.get("content-type")
            if content_type and "application/json" in content_type.lower():
                validate_json_body(self.body)
        
        # Validate timeout
        if self.timeout <= 0:
            raise ValueError(f"Timeout must be positive, got {self.timeout}")
    
    def _validate_url(self):
        """Validate and sanitize URL format."""
        if not self.url:
            raise ValueError("URL cannot be empty")
        
        # Sanitize URL string
        self.url = sanitize_string(self.url, max_length=500)
        
        # Parse URL to validate format
        try:
            parsed = urlparse(self.url)
            
            # Ensure scheme is present
            if not parsed.scheme:
                raise ValueError(f"URL must include scheme (http:// or https://): {self.url}")
            
            # Ensure scheme is http or https
            if parsed.scheme not in ("http", "https"):
                raise ValueError(f"URL scheme must be http or https, got: {parsed.scheme}")
            
            # Ensure netloc (domain) is present
            if not parsed.netloc:
                raise ValueError(f"URL must include domain: {self.url}")
            
        except Exception as e:
            if isinstance(e, ValueError):
                raise
            raise ValueError(f"Invalid URL format: {self.url}") from e
    
    def get_safe_headers_for_display(self) -> Optional[Dict[str, str]]:
        """Get headers with sensitive values masked for display.
        
        Returns:
            Dictionary with masked sensitive headers or None
        """
        return mask_sensitive_headers(self.headers)
    
    def get_identifier(self) -> str:
        """Get unique identifier for this endpoint."""
        return f"{self.method} {self.name}"


@dataclass
class EndpointStatus:
    """Status information for a single endpoint check."""
    config: EndpointConfig
    status_code: Optional[int]  # None if network error
    response_time: float  # in seconds
    error: Optional[str]  # Error message if check failed
    timestamp: datetime
    
    @property
    def method(self) -> str:
        """Get HTTP method."""
        return self.config.method
    
    @property
    def endpoint_name(self) -> str:
        """Get endpoint name without method."""
        return self.config.name
    
    def is_healthy(self) -> bool:
        """Check if status indicates healthy endpoint."""
        return self.status_code is not None and 200 <= self.status_code < 300
    
    def severity(self) -> str:
        """Get severity level for color coding."""
        if self.error or (self.status_code and self.status_code >= 500):
            return "error"
        elif self.status_code and (300 <= self.status_code < 500):
            return "warning"
        else:
            return "success"


# Legacy alias for backward compatibility
@dataclass
class DomainStatus:
    """Status information for a single domain check."""
    domain: str
    status_code: Optional[int]  # None if network error
    response_time: float  # in seconds
    error: Optional[str]  # Error message if check failed
    timestamp: datetime
    
    def is_healthy(self) -> bool:
        """Check if status indicates healthy domain."""
        return self.status_code is not None and 200 <= self.status_code < 300
    
    def severity(self) -> str:
        """Get severity level for color coding."""
        if self.error or (self.status_code and self.status_code >= 500):
            return "error"
        elif self.status_code and (300 <= self.status_code < 500):
            return "warning"
        else:
            return "success"


@dataclass
class StateChange:
    """Record of a status change event."""
    endpoint_id: str  # Endpoint identifier (includes method for endpoints, e.g., "GET example.com")
    timestamp: datetime
    old_status_code: Optional[int]
    new_status_code: Optional[int]
    old_error: Optional[str]
    new_error: Optional[str]
    
    def format_log_entry(self) -> str:
        """Format as log file entry.
        
        The endpoint_id already includes the HTTP method for endpoints (e.g., "GET example.com"),
        so the log format naturally includes the method information.
        """
        timestamp_str = self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        
        # Format old status
        if self.old_status_code is not None:
            old_status = str(self.old_status_code)
        elif self.old_error:
            old_status = "ERROR"
        else:
            old_status = "UNKNOWN"
        
        # Format new status
        if self.new_status_code is not None:
            new_status = str(self.new_status_code)
        elif self.new_error:
            new_status = "ERROR"
        else:
            new_status = "UNKNOWN"
        
        # Build log entry with endpoint_id (which includes method for endpoints)
        log_entry = f"{timestamp_str} [CHANGE] {self.endpoint_id}: {old_status} -> {new_status}"
        
        # Add error details if present
        if self.new_error:
            log_entry += f" ({self.new_error})"
        elif self.old_error and not self.new_error:
            log_entry += " (recovered)"
        
        return log_entry


# DNS Propagation Checker Models

@dataclass
class DNSServerInfo:
    """Information about a DNS server."""
    ip: str
    name: str
    location: str


@dataclass
class DNSQueryResult:
    """Result of a DNS query to a single server."""
    server: DNSServerInfo
    status: str  # 'matched', 'mismatched', 'unreachable', 'timeout'
    values: List[str]  # Actual DNS record values
    response_time: float  # Query response time in seconds
    error: Optional[str] = None


@dataclass
class PropagationResult:
    """Result of DNS propagation check across multiple servers."""
    domain: str
    record_type: str
    expected_value: Optional[str]
    query_results: List[DNSQueryResult]
    timestamp: datetime
    
    @property
    def matched_count(self) -> int:
        """Count of servers with matched values."""
        return sum(1 for r in self.query_results if r.status == 'matched')
    
    @property
    def mismatched_count(self) -> int:
        """Count of servers with mismatched values."""
        return sum(1 for r in self.query_results if r.status == 'mismatched')
    
    @property
    def unreachable_count(self) -> int:
        """Count of unreachable servers."""
        return sum(1 for r in self.query_results if r.status in ('unreachable', 'timeout'))
    
    @property
    def responsive_count(self) -> int:
        """Count of responsive servers (matched + mismatched)."""
        return self.matched_count + self.mismatched_count
    
    @property
    def propagation_rate(self) -> float:
        """Propagation rate as percentage (0-100)."""
        if self.responsive_count == 0:
            return 0.0
        return (self.matched_count / self.responsive_count) * 100
    
    @property
    def is_complete(self) -> bool:
        """Check if propagation is complete (100%)."""
        return self.propagation_rate == 100.0 and self.responsive_count > 0
