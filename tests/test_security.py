"""Tests for security features in live monitoring."""

import pytest
from domain_monitor.models import (
    EndpointConfig,
    mask_sensitive_headers,
    sanitize_string,
    validate_json_body,
)


class TestHeaderMasking:
    """Tests for sensitive header masking."""
    
    def test_mask_authorization_header(self):
        """Test that Authorization header is masked."""
        headers = {
            "Authorization": "Bearer secret_token_12345",
            "Content-Type": "application/json"
        }
        
        masked = mask_sensitive_headers(headers)
        
        assert masked["Authorization"] == "Bear***"
        assert masked["Content-Type"] == "application/json"
    
    def test_mask_api_key_header(self):
        """Test that API-Key header is masked."""
        headers = {
            "API-Key": "my_secret_api_key_12345",
            "Accept": "application/json"
        }
        
        masked = mask_sensitive_headers(headers)
        
        assert masked["API-Key"] == "my_s***"
        assert masked["Accept"] == "application/json"
    
    def test_mask_x_api_key_header(self):
        """Test that X-API-Key header is masked."""
        headers = {
            "X-API-Key": "another_secret_key",
            "User-Agent": "test-agent"
        }
        
        masked = mask_sensitive_headers(headers)
        
        assert masked["X-API-Key"] == "anot***"
        assert masked["User-Agent"] == "test-agent"
    
    def test_mask_short_sensitive_value(self):
        """Test that short sensitive values are fully masked."""
        headers = {
            "Authorization": "short",
            "Content-Type": "text/plain"
        }
        
        masked = mask_sensitive_headers(headers)
        
        assert masked["Authorization"] == "***"
        assert masked["Content-Type"] == "text/plain"
    
    def test_mask_cookie_header(self):
        """Test that Cookie header is masked."""
        headers = {
            "Cookie": "session=abc123; user=john",
            "Accept": "*/*"
        }
        
        masked = mask_sensitive_headers(headers)
        
        assert masked["Cookie"] == "sess***"
        assert masked["Accept"] == "*/*"
    
    def test_mask_none_headers(self):
        """Test that None headers return None."""
        assert mask_sensitive_headers(None) is None
    
    def test_mask_empty_headers(self):
        """Test that empty headers return empty dict."""
        assert mask_sensitive_headers({}) == {}


class TestStringSanitization:
    """Tests for string sanitization."""
    
    def test_sanitize_normal_string(self):
        """Test that normal strings pass through unchanged."""
        text = "This is a normal string"
        assert sanitize_string(text) == text
    
    def test_sanitize_removes_control_characters(self):
        """Test that control characters are removed."""
        text = "Hello\x00World\x1f!"
        result = sanitize_string(text)
        assert result == "HelloWorld!"
        assert "\x00" not in result
        assert "\x1f" not in result
    
    def test_sanitize_preserves_newline_and_tab(self):
        """Test that newline and tab are preserved."""
        text = "Line1\nLine2\tTabbed"
        result = sanitize_string(text)
        assert "\n" in result
        assert "\t" in result
    
    def test_sanitize_truncates_long_strings(self):
        """Test that long strings are truncated."""
        text = "a" * 300
        result = sanitize_string(text, max_length=100)
        assert len(result) == 100
        assert result.endswith("...")
    
    def test_sanitize_empty_string(self):
        """Test that empty strings are handled."""
        assert sanitize_string("") == ""
    
    def test_sanitize_custom_max_length(self):
        """Test custom max length parameter."""
        text = "a" * 100
        result = sanitize_string(text, max_length=50)
        assert len(result) == 50
        assert result.endswith("...")


class TestJSONValidation:
    """Tests for JSON body validation."""
    
    def test_validate_valid_json(self):
        """Test that valid JSON passes validation."""
        body = '{"username": "test", "password": "test123"}'
        # Should not raise
        validate_json_body(body)
    
    def test_validate_valid_json_array(self):
        """Test that valid JSON array passes validation."""
        body = '[{"id": 1}, {"id": 2}]'
        # Should not raise
        validate_json_body(body)
    
    def test_validate_invalid_json_raises(self):
        """Test that invalid JSON raises ValueError."""
        body = '{"username": "test", invalid}'
        
        with pytest.raises(ValueError, match="Invalid JSON body"):
            validate_json_body(body)
    
    def test_validate_empty_json_object(self):
        """Test that empty JSON object is valid."""
        body = '{}'
        # Should not raise
        validate_json_body(body)
    
    def test_validate_json_with_nested_objects(self):
        """Test that nested JSON objects are valid."""
        body = '{"user": {"name": "test", "age": 30}, "active": true}'
        # Should not raise
        validate_json_body(body)


class TestEndpointConfigSecurity:
    """Tests for security features in EndpointConfig."""
    
    def test_endpoint_name_sanitization(self):
        """Test that endpoint names are sanitized."""
        config = EndpointConfig(
            name="test\x00endpoint\x1f",
            url="https://example.com"
        )
        
        assert "\x00" not in config.name
        assert "\x1f" not in config.name
        assert config.name == "testendpoint"
    
    def test_url_sanitization(self):
        """Test that URLs are sanitized."""
        config = EndpointConfig(
            name="test",
            url="https://example.com/path\x00"
        )
        
        assert "\x00" not in config.url
    
    def test_json_body_validation_with_json_content_type(self):
        """Test that JSON body is validated when Content-Type is application/json."""
        with pytest.raises(ValueError, match="Invalid JSON body"):
            EndpointConfig(
                name="test",
                url="https://example.com",
                method="POST",
                headers={"Content-Type": "application/json"},
                body='{"invalid json'
            )
    
    def test_json_body_validation_passes_with_valid_json(self):
        """Test that valid JSON body passes validation."""
        config = EndpointConfig(
            name="test",
            url="https://example.com",
            method="POST",
            headers={"Content-Type": "application/json"},
            body='{"username": "test"}'
        )
        
        assert config.body == '{"username": "test"}'
    
    def test_json_body_not_validated_without_json_content_type(self):
        """Test that body is not validated when Content-Type is not JSON."""
        # Should not raise even with invalid JSON
        config = EndpointConfig(
            name="test",
            url="https://example.com",
            method="POST",
            headers={"Content-Type": "text/plain"},
            body='not json at all'
        )
        
        assert config.body == 'not json at all'
    
    def test_get_safe_headers_for_display(self):
        """Test that sensitive headers are masked for display."""
        config = EndpointConfig(
            name="test",
            url="https://example.com",
            headers={
                "Authorization": "Bearer secret_token",
                "Content-Type": "application/json"
            }
        )
        
        safe_headers = config.get_safe_headers_for_display()
        
        assert safe_headers["Authorization"] == "Bear***"
        assert safe_headers["Content-Type"] == "application/json"
    
    def test_long_endpoint_name_truncation(self):
        """Test that very long endpoint names are truncated."""
        long_name = "a" * 200
        config = EndpointConfig(
            name=long_name,
            url="https://example.com"
        )
        
        assert len(config.name) <= 100
        assert config.name.endswith("...")
    
    def test_long_url_truncation(self):
        """Test that very long URLs are truncated."""
        long_url = "https://example.com/" + "a" * 600
        config = EndpointConfig(
            name="test",
            url=long_url
        )
        
        assert len(config.url) <= 500
        assert config.url.endswith("...")
