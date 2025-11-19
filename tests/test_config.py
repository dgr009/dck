"""
Tests for configuration management module.

Tests YAML/JSON parsing, validation, and default manifest path resolution.
"""

import json
import tempfile
from pathlib import Path

import pytest
import yaml

from domain_monitor.config import (
    DomainConfig,
    ManifestConfig,
    get_default_manifest_path,
    load_manifest,
    validate_manifest,
    load_endpoints_config,
    VALID_CHECK_TYPES,
)
from domain_monitor.models import EndpointConfig


class TestDomainConfig:
    """Tests for DomainConfig dataclass."""
    
    def test_domain_config_creation(self):
        """Test creating a DomainConfig with all fields."""
        config = DomainConfig(
            name="example.com",
            tags=["prod", "main"],
            checks=["whois", "ssl"],
            dkim_selectors=["google"]
        )
        
        assert config.name == "example.com"
        assert config.tags == ["prod", "main"]
        assert config.checks == ["whois", "ssl"]
        assert config.dkim_selectors == ["google"]
    
    def test_domain_config_defaults(self):
        """Test DomainConfig with default values."""
        config = DomainConfig(name="example.com")
        
        assert config.name == "example.com"
        assert config.tags == []
        assert config.checks == []
        assert config.dkim_selectors == []


class TestManifestConfig:
    """Tests for ManifestConfig dataclass."""
    
    def test_manifest_config_creation(self):
        """Test creating a ManifestConfig."""
        domain = DomainConfig(name="example.com")
        manifest = ManifestConfig(
            default_checks=["whois", "ssl"],
            domains=[domain]
        )
        
        assert manifest.default_checks == ["whois", "ssl"]
        assert len(manifest.domains) == 1
        assert manifest.domains[0].name == "example.com"


class TestGetDefaultManifestPath:
    """Tests for get_default_manifest_path function."""
    
    def test_finds_domains_yaml(self, tmp_path, monkeypatch):
        """Test that domains.yaml is found first."""
        # Change to temp directory
        monkeypatch.chdir(tmp_path)
        
        # Create both files
        (tmp_path / "domains.yaml").write_text("test: data")
        (tmp_path / "domains.json").write_text('{"test": "data"}')
        
        result = get_default_manifest_path()
        assert result == "domains.yaml"
    
    def test_finds_domains_json_when_yaml_missing(self, tmp_path, monkeypatch):
        """Test that domains.json is found when yaml is missing."""
        monkeypatch.chdir(tmp_path)
        
        # Create only JSON file
        (tmp_path / "domains.json").write_text('{"test": "data"}')
        
        result = get_default_manifest_path()
        assert result == "domains.json"
    
    def test_returns_none_when_no_manifest(self, tmp_path, monkeypatch):
        """Test that None is returned when no manifest file exists."""
        monkeypatch.chdir(tmp_path)
        
        result = get_default_manifest_path()
        assert result is None


class TestLoadManifest:
    """Tests for load_manifest function."""
    
    def test_load_valid_yaml(self, tmp_path):
        """Test loading a valid YAML manifest file."""
        manifest_data = {
            "default_checks": ["whois", "ssl"],
            "domains": [
                {
                    "name": "example.com",
                    "tags": ["prod"],
                    "checks": ["whois", "ssl", "http"],
                    "dkim_selectors": ["google"]
                }
            ]
        }
        
        manifest_file = tmp_path / "test.yaml"
        with open(manifest_file, 'w') as f:
            yaml.dump(manifest_data, f)
        
        result = load_manifest(str(manifest_file))
        
        assert isinstance(result, ManifestConfig)
        assert result.default_checks == ["whois", "ssl"]
        assert len(result.domains) == 1
        assert result.domains[0].name == "example.com"
        assert result.domains[0].tags == ["prod"]
        assert result.domains[0].checks == ["whois", "ssl", "http"]
        assert result.domains[0].dkim_selectors == ["google"]
    
    def test_load_valid_json(self, tmp_path):
        """Test loading a valid JSON manifest file."""
        manifest_data = {
            "default_checks": ["dns", "rbl"],
            "domains": [
                {
                    "name": "test.com",
                    "tags": ["staging"],
                    "checks": ["dns"],
                    "dkim_selectors": []
                }
            ]
        }
        
        manifest_file = tmp_path / "test.json"
        with open(manifest_file, 'w') as f:
            json.dump(manifest_data, f)
        
        result = load_manifest(str(manifest_file))
        
        assert isinstance(result, ManifestConfig)
        assert result.default_checks == ["dns", "rbl"]
        assert len(result.domains) == 1
        assert result.domains[0].name == "test.com"
    
    def test_load_yaml_with_yml_extension(self, tmp_path):
        """Test loading YAML file with .yml extension."""
        manifest_data = {
            "default_checks": [],
            "domains": [{"name": "example.com"}]
        }
        
        manifest_file = tmp_path / "test.yml"
        with open(manifest_file, 'w') as f:
            yaml.dump(manifest_data, f)
        
        result = load_manifest(str(manifest_file))
        assert isinstance(result, ManifestConfig)
    
    def test_file_not_found(self):
        """Test error when manifest file doesn't exist."""
        with pytest.raises(FileNotFoundError, match="Manifest file not found"):
            load_manifest("/nonexistent/file.yaml")
    
    def test_invalid_yaml_syntax(self, tmp_path):
        """Test error with invalid YAML syntax."""
        manifest_file = tmp_path / "invalid.yaml"
        manifest_file.write_text("invalid: yaml: syntax: [")
        
        with pytest.raises(ValueError, match="Invalid YAML syntax"):
            load_manifest(str(manifest_file))
    
    def test_invalid_json_syntax(self, tmp_path):
        """Test error with invalid JSON syntax."""
        manifest_file = tmp_path / "invalid.json"
        manifest_file.write_text('{"invalid": json syntax}')
        
        with pytest.raises(ValueError, match="Invalid JSON syntax"):
            load_manifest(str(manifest_file))
    
    def test_unsupported_file_format(self, tmp_path):
        """Test error with unsupported file format."""
        manifest_file = tmp_path / "test.txt"
        manifest_file.write_text("some text")
        
        with pytest.raises(ValueError, match="Unsupported file format"):
            load_manifest(str(manifest_file))
    
    def test_empty_file(self, tmp_path):
        """Test error with empty manifest file."""
        manifest_file = tmp_path / "empty.yaml"
        manifest_file.write_text("")
        
        with pytest.raises(ValueError, match="Manifest file is empty"):
            load_manifest(str(manifest_file))
    
    def test_missing_name_field(self, tmp_path):
        """Test error when domain is missing required 'name' field."""
        manifest_data = {
            "default_checks": [],
            "domains": [
                {"tags": ["prod"]}  # Missing 'name'
            ]
        }
        
        manifest_file = tmp_path / "test.yaml"
        with open(manifest_file, 'w') as f:
            yaml.dump(manifest_data, f)
        
        with pytest.raises(ValueError, match="missing required 'name' field"):
            load_manifest(str(manifest_file))
    
    def test_default_checks_not_list(self, tmp_path):
        """Test error when default_checks is not a list."""
        manifest_data = {
            "default_checks": "whois",  # Should be a list
            "domains": []
        }
        
        manifest_file = tmp_path / "test.yaml"
        with open(manifest_file, 'w') as f:
            yaml.dump(manifest_data, f)
        
        with pytest.raises(ValueError, match="'default_checks' must be a list"):
            load_manifest(str(manifest_file))
    
    def test_domains_not_list(self, tmp_path):
        """Test error when domains is not a list."""
        manifest_data = {
            "default_checks": [],
            "domains": "example.com"  # Should be a list
        }
        
        manifest_file = tmp_path / "test.yaml"
        with open(manifest_file, 'w') as f:
            yaml.dump(manifest_data, f)
        
        with pytest.raises(ValueError, match="'domains' must be a list"):
            load_manifest(str(manifest_file))
    
    def test_domain_not_dict(self, tmp_path):
        """Test error when domain entry is not a dictionary."""
        manifest_data = {
            "default_checks": [],
            "domains": ["example.com"]  # Should be dict
        }
        
        manifest_file = tmp_path / "test.yaml"
        with open(manifest_file, 'w') as f:
            yaml.dump(manifest_data, f)
        
        with pytest.raises(ValueError, match="must be an object/dictionary"):
            load_manifest(str(manifest_file))
    
    def test_tags_not_list(self, tmp_path):
        """Test error when tags is not a list."""
        manifest_data = {
            "default_checks": [],
            "domains": [
                {
                    "name": "example.com",
                    "tags": "prod"  # Should be a list
                }
            ]
        }
        
        manifest_file = tmp_path / "test.yaml"
        with open(manifest_file, 'w') as f:
            yaml.dump(manifest_data, f)
        
        with pytest.raises(ValueError, match="'tags' must be a list"):
            load_manifest(str(manifest_file))
    
    def test_checks_not_list(self, tmp_path):
        """Test error when checks is not a list."""
        manifest_data = {
            "default_checks": [],
            "domains": [
                {
                    "name": "example.com",
                    "checks": "whois"  # Should be a list
                }
            ]
        }
        
        manifest_file = tmp_path / "test.yaml"
        with open(manifest_file, 'w') as f:
            yaml.dump(manifest_data, f)
        
        with pytest.raises(ValueError, match="'checks' must be a list"):
            load_manifest(str(manifest_file))


class TestValidateManifest:
    """Tests for validate_manifest function."""
    
    def test_valid_manifest(self):
        """Test validation of a valid manifest."""
        domain = DomainConfig(
            name="example.com",
            checks=["whois", "ssl"]
        )
        manifest = ManifestConfig(
            default_checks=["http", "dns"],
            domains=[domain]
        )
        
        # Should not raise any exception
        validate_manifest(manifest)
    
    def test_invalid_default_check_type(self):
        """Test error with invalid check type in default_checks."""
        manifest = ManifestConfig(
            default_checks=["invalid_check"],
            domains=[]
        )
        
        with pytest.raises(ValueError, match="Invalid check type in default_checks"):
            validate_manifest(manifest)
    
    def test_invalid_domain_check_type(self):
        """Test error with invalid check type in domain checks."""
        domain = DomainConfig(
            name="example.com",
            checks=["whois", "invalid_check"]
        )
        manifest = ManifestConfig(
            default_checks=[],
            domains=[domain]
        )
        
        with pytest.raises(ValueError, match="Invalid check type for domain"):
            validate_manifest(manifest)
    
    def test_empty_domain_name(self):
        """Test error with empty domain name."""
        domain = DomainConfig(name="")
        manifest = ManifestConfig(
            default_checks=[],
            domains=[domain]
        )
        
        with pytest.raises(ValueError, match="Domain name cannot be empty"):
            validate_manifest(manifest)
    
    def test_whitespace_only_domain_name(self):
        """Test error with whitespace-only domain name."""
        domain = DomainConfig(name="   ")
        manifest = ManifestConfig(
            default_checks=[],
            domains=[domain]
        )
        
        with pytest.raises(ValueError, match="Domain name cannot be empty"):
            validate_manifest(manifest)
    
    def test_all_valid_check_types(self):
        """Test that all valid check types are accepted."""
        for check_type in VALID_CHECK_TYPES:
            domain = DomainConfig(
                name="example.com",
                checks=[check_type]
            )
            manifest = ManifestConfig(
                default_checks=[],
                domains=[domain]
            )
            
            # Should not raise any exception
            validate_manifest(manifest)



class TestLoadEndpointsConfig:
    """Tests for load_endpoints_config function."""
    
    def test_load_valid_yaml_minimal(self, tmp_path):
        """Test loading a minimal valid YAML endpoint configuration."""
        config_data = {
            "endpoints": [
                {
                    "name": "example.com",
                    "url": "https://example.com"
                }
            ]
        }
        
        config_file = tmp_path / "endpoints.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)
        
        result = load_endpoints_config(str(config_file))
        
        assert len(result) == 1
        assert isinstance(result[0], EndpointConfig)
        assert result[0].name == "example.com"
        assert result[0].url == "https://example.com"
        assert result[0].method == "GET"  # Default
        assert result[0].timeout == 5.0  # Default
        assert result[0].headers is None
        assert result[0].body is None
    
    def test_load_valid_yaml_full(self, tmp_path):
        """Test loading a full YAML endpoint configuration with all fields."""
        config_data = {
            "endpoints": [
                {
                    "name": "api.example.com/users",
                    "url": "https://api.example.com/users",
                    "method": "POST",
                    "headers": {
                        "Authorization": "Bearer token123",
                        "Content-Type": "application/json"
                    },
                    "body": '{"username": "test"}',
                    "timeout": 10.0
                }
            ]
        }
        
        config_file = tmp_path / "endpoints.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)
        
        result = load_endpoints_config(str(config_file))
        
        assert len(result) == 1
        endpoint = result[0]
        assert endpoint.name == "api.example.com/users"
        assert endpoint.url == "https://api.example.com/users"
        assert endpoint.method == "POST"
        assert endpoint.headers == {
            "Authorization": "Bearer token123",
            "Content-Type": "application/json"
        }
        assert endpoint.body == '{"username": "test"}'
        assert endpoint.timeout == 10.0
    
    def test_load_multiple_endpoints(self, tmp_path):
        """Test loading multiple endpoints."""
        config_data = {
            "endpoints": [
                {
                    "name": "example1.com",
                    "url": "https://example1.com"
                },
                {
                    "name": "example2.com",
                    "url": "https://example2.com",
                    "method": "POST"
                },
                {
                    "name": "example3.com",
                    "url": "https://example3.com",
                    "timeout": 3.0
                }
            ]
        }
        
        config_file = tmp_path / "endpoints.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)
        
        result = load_endpoints_config(str(config_file))
        
        assert len(result) == 3
        assert result[0].name == "example1.com"
        assert result[1].name == "example2.com"
        assert result[1].method == "POST"
        assert result[2].timeout == 3.0
    
    def test_load_valid_json(self, tmp_path):
        """Test loading a valid JSON endpoint configuration."""
        config_data = {
            "endpoints": [
                {
                    "name": "test.com",
                    "url": "https://test.com",
                    "method": "GET"
                }
            ]
        }
        
        config_file = tmp_path / "endpoints.json"
        with open(config_file, 'w') as f:
            json.dump(config_data, f)
        
        result = load_endpoints_config(str(config_file))
        
        assert len(result) == 1
        assert result[0].name == "test.com"
    
    def test_file_not_found(self):
        """Test error when endpoint configuration file doesn't exist."""
        with pytest.raises(FileNotFoundError, match="Endpoint configuration file not found"):
            load_endpoints_config("/nonexistent/endpoints.yaml")
    
    def test_invalid_yaml_syntax(self, tmp_path):
        """Test error with invalid YAML syntax."""
        config_file = tmp_path / "invalid.yaml"
        config_file.write_text("invalid: yaml: syntax: [")
        
        with pytest.raises(ValueError, match="Invalid YAML syntax"):
            load_endpoints_config(str(config_file))
    
    def test_invalid_json_syntax(self, tmp_path):
        """Test error with invalid JSON syntax."""
        config_file = tmp_path / "invalid.json"
        config_file.write_text('{"invalid": json}')
        
        with pytest.raises(ValueError, match="Invalid JSON syntax"):
            load_endpoints_config(str(config_file))
    
    def test_unsupported_file_format(self, tmp_path):
        """Test error with unsupported file format."""
        config_file = tmp_path / "endpoints.txt"
        config_file.write_text("some text")
        
        with pytest.raises(ValueError, match="Unsupported file format"):
            load_endpoints_config(str(config_file))
    
    def test_empty_file(self, tmp_path):
        """Test error with empty configuration file."""
        config_file = tmp_path / "empty.yaml"
        config_file.write_text("")
        
        with pytest.raises(ValueError, match="Endpoint configuration file is empty"):
            load_endpoints_config(str(config_file))
    
    def test_endpoints_not_list(self, tmp_path):
        """Test error when endpoints is not a list."""
        config_data = {
            "endpoints": "not a list"
        }
        
        config_file = tmp_path / "endpoints.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)
        
        with pytest.raises(ValueError, match="'endpoints' must be a list"):
            load_endpoints_config(str(config_file))
    
    def test_no_endpoints_defined(self, tmp_path):
        """Test error when no endpoints are defined."""
        config_data = {
            "endpoints": []
        }
        
        config_file = tmp_path / "endpoints.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)
        
        with pytest.raises(ValueError, match="No endpoints defined"):
            load_endpoints_config(str(config_file))
    
    def test_endpoint_not_dict(self, tmp_path):
        """Test error when endpoint entry is not a dictionary."""
        config_data = {
            "endpoints": ["not a dict"]
        }
        
        config_file = tmp_path / "endpoints.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)
        
        with pytest.raises(ValueError, match="must be an object/dictionary"):
            load_endpoints_config(str(config_file))
    
    def test_missing_name_field(self, tmp_path):
        """Test error when endpoint is missing required 'name' field."""
        config_data = {
            "endpoints": [
                {
                    "url": "https://example.com"
                }
            ]
        }
        
        config_file = tmp_path / "endpoints.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)
        
        with pytest.raises(ValueError, match="missing required 'name' field"):
            load_endpoints_config(str(config_file))
    
    def test_missing_url_field(self, tmp_path):
        """Test error when endpoint is missing required 'url' field."""
        config_data = {
            "endpoints": [
                {
                    "name": "example.com"
                }
            ]
        }
        
        config_file = tmp_path / "endpoints.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)
        
        with pytest.raises(ValueError, match="missing required 'url' field"):
            load_endpoints_config(str(config_file))
    
    def test_empty_name(self, tmp_path):
        """Test error when name is empty string."""
        config_data = {
            "endpoints": [
                {
                    "name": "",
                    "url": "https://example.com"
                }
            ]
        }
        
        config_file = tmp_path / "endpoints.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)
        
        with pytest.raises(ValueError, match="'name' must be a non-empty string"):
            load_endpoints_config(str(config_file))
    
    def test_empty_url(self, tmp_path):
        """Test error when url is empty string."""
        config_data = {
            "endpoints": [
                {
                    "name": "example.com",
                    "url": ""
                }
            ]
        }
        
        config_file = tmp_path / "endpoints.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)
        
        with pytest.raises(ValueError, match="'url' must be a non-empty string"):
            load_endpoints_config(str(config_file))
    
    def test_invalid_http_method(self, tmp_path):
        """Test error with invalid HTTP method."""
        config_data = {
            "endpoints": [
                {
                    "name": "example.com",
                    "url": "https://example.com",
                    "method": "INVALID"
                }
            ]
        }
        
        config_file = tmp_path / "endpoints.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)
        
        with pytest.raises(ValueError, match="Invalid HTTP method"):
            load_endpoints_config(str(config_file))
    
    def test_method_case_insensitive(self, tmp_path):
        """Test that HTTP method is case-insensitive."""
        config_data = {
            "endpoints": [
                {
                    "name": "example.com",
                    "url": "https://example.com",
                    "method": "post"
                }
            ]
        }
        
        config_file = tmp_path / "endpoints.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)
        
        result = load_endpoints_config(str(config_file))
        assert result[0].method == "POST"
    
    def test_invalid_timeout_type(self, tmp_path):
        """Test error when timeout is not a number."""
        config_data = {
            "endpoints": [
                {
                    "name": "example.com",
                    "url": "https://example.com",
                    "timeout": "not a number"
                }
            ]
        }
        
        config_file = tmp_path / "endpoints.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)
        
        with pytest.raises(ValueError, match="'timeout' must be a number"):
            load_endpoints_config(str(config_file))
    
    def test_negative_timeout(self, tmp_path):
        """Test error when timeout is negative."""
        config_data = {
            "endpoints": [
                {
                    "name": "example.com",
                    "url": "https://example.com",
                    "timeout": -1.0
                }
            ]
        }
        
        config_file = tmp_path / "endpoints.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)
        
        with pytest.raises(ValueError, match="'timeout' must be positive"):
            load_endpoints_config(str(config_file))
    
    def test_headers_not_dict(self, tmp_path):
        """Test error when headers is not a dictionary."""
        config_data = {
            "endpoints": [
                {
                    "name": "example.com",
                    "url": "https://example.com",
                    "headers": "not a dict"
                }
            ]
        }
        
        config_file = tmp_path / "endpoints.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)
        
        with pytest.raises(ValueError, match="'headers' must be an object/dictionary"):
            load_endpoints_config(str(config_file))
    
    def test_body_not_string(self, tmp_path):
        """Test error when body is not a string."""
        config_data = {
            "endpoints": [
                {
                    "name": "example.com",
                    "url": "https://example.com",
                    "body": {"key": "value"}  # Should be string
                }
            ]
        }
        
        config_file = tmp_path / "endpoints.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)
        
        with pytest.raises(ValueError, match="'body' must be a string"):
            load_endpoints_config(str(config_file))
    
    def test_invalid_url_no_scheme(self, tmp_path):
        """Test error when URL has no scheme."""
        config_data = {
            "endpoints": [
                {
                    "name": "example.com",
                    "url": "example.com"
                }
            ]
        }
        
        config_file = tmp_path / "endpoints.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)
        
        with pytest.raises(ValueError, match="URL must include scheme"):
            load_endpoints_config(str(config_file))
    
    def test_invalid_url_wrong_scheme(self, tmp_path):
        """Test error when URL has invalid scheme."""
        config_data = {
            "endpoints": [
                {
                    "name": "example.com",
                    "url": "ftp://example.com"
                }
            ]
        }
        
        config_file = tmp_path / "endpoints.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)
        
        with pytest.raises(ValueError, match="URL scheme must be http or https"):
            load_endpoints_config(str(config_file))
    
    def test_all_valid_http_methods(self, tmp_path):
        """Test that all valid HTTP methods are accepted."""
        methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
        
        for method in methods:
            config_data = {
                "endpoints": [
                    {
                        "name": f"test-{method}",
                        "url": "https://example.com",
                        "method": method
                    }
                ]
            }
            
            config_file = tmp_path / f"endpoints-{method}.yaml"
            with open(config_file, 'w') as f:
                yaml.dump(config_data, f)
            
            result = load_endpoints_config(str(config_file))
            assert result[0].method == method
    
    def test_whitespace_trimming(self, tmp_path):
        """Test that whitespace is trimmed from name, url, and method."""
        config_data = {
            "endpoints": [
                {
                    "name": "  example.com  ",
                    "url": "  https://example.com  ",
                    "method": "  GET  "
                }
            ]
        }
        
        config_file = tmp_path / "endpoints.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)
        
        result = load_endpoints_config(str(config_file))
        assert result[0].name == "example.com"
        assert result[0].url == "https://example.com"
        assert result[0].method == "GET"
