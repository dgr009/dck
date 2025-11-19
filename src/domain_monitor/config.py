"""Configuration management for domain monitoring."""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any

import yaml

from domain_monitor.models import EndpointConfig


@dataclass
class DomainConfig:
    """Configuration for a single domain to monitor."""
    
    name: str
    tags: List[str] = field(default_factory=list)
    checks: List[str] = field(default_factory=list)
    dkim_selectors: List[str] = field(default_factory=list)


@dataclass
class ManifestConfig:
    """Complete manifest configuration."""
    
    default_checks: List[str]
    domains: List[DomainConfig]


# Valid check types
VALID_CHECK_TYPES = {'whois', 'ssl', 'http', 'dns', 'security', 'rbl'}


def get_default_manifest_path() -> Optional[str]:
    """
    Find default manifest file in current directory.
    
    Looks for domains.yaml first, then domains.json.
    
    Returns:
        Path to manifest file if found, None otherwise.
    """
    yaml_path = Path('domains.yaml')
    if yaml_path.exists():
        return str(yaml_path)
    
    json_path = Path('domains.json')
    if json_path.exists():
        return str(json_path)
    
    return None


def load_manifest(file_path: str) -> ManifestConfig:
    """
    Load and parse manifest file (YAML or JSON).
    
    Args:
        file_path: Path to manifest file
        
    Returns:
        Parsed ManifestConfig object
        
    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If file format is invalid or parsing fails
    """
    path = Path(file_path)
    
    if not path.exists():
        raise FileNotFoundError(f"Manifest file not found: {file_path}")
    
    try:
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Determine file type and parse
        if path.suffix in ['.yaml', '.yml']:
            data = yaml.safe_load(content)
        elif path.suffix == '.json':
            data = json.loads(content)
        else:
            raise ValueError(f"Unsupported file format: {path.suffix}. Use .yaml, .yml, or .json")
        
        if data is None:
            raise ValueError("Manifest file is empty")
        
        # Parse default_checks
        default_checks = data.get('default_checks', [])
        if not isinstance(default_checks, list):
            raise ValueError("'default_checks' must be a list")
        
        # Parse domains
        domains_data = data.get('domains', [])
        if not isinstance(domains_data, list):
            raise ValueError("'domains' must be a list")
        
        domains = []
        for idx, domain_data in enumerate(domains_data):
            if not isinstance(domain_data, dict):
                raise ValueError(f"Domain at index {idx} must be an object/dictionary")
            
            # Extract domain fields
            name = domain_data.get('name')
            if not name:
                raise ValueError(f"Domain at index {idx} is missing required 'name' field")
            
            tags = domain_data.get('tags', [])
            if not isinstance(tags, list):
                raise ValueError(f"Domain '{name}': 'tags' must be a list")
            
            checks = domain_data.get('checks', [])
            if not isinstance(checks, list):
                raise ValueError(f"Domain '{name}': 'checks' must be a list")
            
            dkim_selectors = domain_data.get('dkim_selectors', [])
            if not isinstance(dkim_selectors, list):
                raise ValueError(f"Domain '{name}': 'dkim_selectors' must be a list")
            
            domains.append(DomainConfig(
                name=name,
                tags=tags,
                checks=checks,
                dkim_selectors=dkim_selectors
            ))
        
        manifest = ManifestConfig(
            default_checks=default_checks,
            domains=domains
        )
        
        # Validate the manifest
        validate_manifest(manifest)
        
        return manifest
        
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML syntax: {str(e)}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON syntax at line {e.lineno}, column {e.colno}: {e.msg}")
    except Exception as e:
        if isinstance(e, (FileNotFoundError, ValueError)):
            raise
        raise ValueError(f"Failed to parse manifest file: {str(e)}")


def validate_manifest(manifest: ManifestConfig) -> None:
    """
    Validate manifest configuration.
    
    Args:
        manifest: ManifestConfig to validate
        
    Raises:
        ValueError: If validation fails with descriptive error message
    """
    # Validate default_checks
    for check_type in manifest.default_checks:
        if check_type not in VALID_CHECK_TYPES:
            raise ValueError(
                f"Invalid check type in default_checks: '{check_type}'. "
                f"Valid types are: {', '.join(sorted(VALID_CHECK_TYPES))}"
            )
    
    # Validate each domain
    for domain in manifest.domains:
        # Check name is not empty
        if not domain.name or not domain.name.strip():
            raise ValueError("Domain name cannot be empty")
        
        # Validate check types
        for check_type in domain.checks:
            if check_type not in VALID_CHECK_TYPES:
                raise ValueError(
                    f"Invalid check type for domain '{domain.name}': '{check_type}'. "
                    f"Valid types are: {', '.join(sorted(VALID_CHECK_TYPES))}"
                )


def load_endpoints_config(file_path: str) -> List[EndpointConfig]:
    """
    Load and parse endpoint configuration file (YAML or JSON).
    
    Expected YAML format:
        endpoints:
          - name: example.com
            url: https://example.com
            method: GET  # Optional, defaults to GET
            headers:  # Optional
              Authorization: Bearer token
              Accept: application/json
            body: '{"key": "value"}'  # Optional
            timeout: 5.0  # Optional, defaults to 5.0
    
    Args:
        file_path: Path to endpoint configuration file
        
    Returns:
        List of parsed EndpointConfig objects
        
    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If file format is invalid or parsing fails
    """
    path = Path(file_path)
    
    if not path.exists():
        raise FileNotFoundError(f"Endpoint configuration file not found: {file_path}")
    
    try:
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Determine file type and parse
        if path.suffix in ['.yaml', '.yml']:
            data = yaml.safe_load(content)
        elif path.suffix == '.json':
            data = json.loads(content)
        else:
            raise ValueError(f"Unsupported file format: {path.suffix}. Use .yaml, .yml, or .json")
        
        if data is None:
            raise ValueError("Endpoint configuration file is empty")
        
        # Parse endpoints list
        endpoints_data = data.get('endpoints', [])
        if not isinstance(endpoints_data, list):
            raise ValueError("'endpoints' must be a list")
        
        if not endpoints_data:
            raise ValueError("No endpoints defined in configuration file")
        
        endpoints = []
        for idx, endpoint_data in enumerate(endpoints_data):
            try:
                endpoint = _parse_endpoint(endpoint_data, idx)
                endpoints.append(endpoint)
            except ValueError as e:
                raise ValueError(f"Endpoint at index {idx}: {str(e)}")
        
        return endpoints
        
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML syntax: {str(e)}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON syntax at line {e.lineno}, column {e.colno}: {e.msg}")
    except Exception as e:
        if isinstance(e, (FileNotFoundError, ValueError)):
            raise
        raise ValueError(f"Failed to parse endpoint configuration file: {str(e)}")


def _parse_endpoint(endpoint_data: Any, index: int) -> EndpointConfig:
    """
    Parse a single endpoint configuration from dictionary data.
    
    Args:
        endpoint_data: Dictionary containing endpoint configuration
        index: Index of endpoint in list (for error messages)
        
    Returns:
        Parsed EndpointConfig object
        
    Raises:
        ValueError: If configuration is invalid
    """
    if not isinstance(endpoint_data, dict):
        raise ValueError("must be an object/dictionary")
    
    # Extract required fields
    name = endpoint_data.get('name')
    if name is None:
        raise ValueError("missing required 'name' field")
    
    if not isinstance(name, str) or not name.strip():
        raise ValueError("'name' must be a non-empty string")
    
    url = endpoint_data.get('url')
    if url is None:
        raise ValueError("missing required 'url' field")
    
    if not isinstance(url, str) or not url.strip():
        raise ValueError("'url' must be a non-empty string")
    
    # Extract optional fields with defaults
    method = endpoint_data.get('method', 'GET')
    if not isinstance(method, str):
        raise ValueError("'method' must be a string")
    
    timeout = endpoint_data.get('timeout', 5.0)
    if not isinstance(timeout, (int, float)):
        raise ValueError("'timeout' must be a number")
    
    if timeout <= 0:
        raise ValueError(f"'timeout' must be positive, got {timeout}")
    
    # Parse headers (optional)
    headers = endpoint_data.get('headers')
    if headers is not None:
        if not isinstance(headers, dict):
            raise ValueError("'headers' must be an object/dictionary")
        
        # Validate all header keys and values are strings
        for key, value in headers.items():
            if not isinstance(key, str):
                raise ValueError(f"header key must be a string, got {type(key).__name__}")
            if not isinstance(value, str):
                raise ValueError(f"header value for '{key}' must be a string, got {type(value).__name__}")
    
    # Parse body (optional)
    body = endpoint_data.get('body')
    if body is not None:
        if not isinstance(body, str):
            raise ValueError("'body' must be a string")
    
    # Create EndpointConfig (validation happens in __post_init__)
    try:
        return EndpointConfig(
            name=name.strip(),
            url=url.strip(),
            method=method.strip(),
            headers=headers,
            body=body,
            timeout=float(timeout)
        )
    except ValueError as e:
        # Re-raise validation errors from EndpointConfig
        raise ValueError(str(e))
