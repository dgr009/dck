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
    VALID_CHECK_TYPES,
)


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
