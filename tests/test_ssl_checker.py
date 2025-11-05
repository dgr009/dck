"""
Tests for SSL certificate checker module.

Tests SSL certificate retrieval, parsing, and expiration status determination.
"""

import socket
import ssl
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, patch, MagicMock

import pytest

from domain_monitor.checkers.ssl import SSLChecker
from domain_monitor.checkers.base_checker import CheckResult


@pytest.fixture
def ssl_checker():
    """Create an SSLChecker instance for testing."""
    return SSLChecker(timeout=10)


@pytest.fixture
def mock_cert_dict():
    """Create mock certificate dictionary."""
    expiration_date = datetime.now(timezone.utc) + timedelta(days=30)
    not_after_str = expiration_date.strftime('%b %d %H:%M:%S %Y GMT')
    
    return {
        'issuer': (
            (('organizationName', 'Let\'s Encrypt'),),
        ),
        'subject': (
            (('commonName', 'example.com'),),
        ),
        'subjectAltName': (
            ('DNS', 'example.com'),
            ('DNS', 'www.example.com'),
        ),
        'notAfter': not_after_str,
        '_der': b'mock_der_data'
    }


class TestSSLChecker:
    """Tests for SSLChecker class."""
    
    @pytest.mark.asyncio
    async def test_check_success_valid_certificate(self, ssl_checker, mock_cert_dict):
        """Test successful SSL check with valid certificate."""
        with patch.object(ssl_checker, '_get_certificate', return_value=mock_cert_dict):
            result = await ssl_checker.check("example.com")
        
        assert isinstance(result, CheckResult)
        assert result.domain == "example.com"
        assert result.check_type == "ssl"
        assert result.status in [CheckResult.OK, CheckResult.WARNING, CheckResult.CRITICAL]
        assert result.details["issuer"] == "Let's Encrypt"
        assert result.details["subject"] == "example.com"
        assert "example.com" in result.details["sans"]
    
    @pytest.mark.asyncio
    async def test_check_ok_status(self, ssl_checker):
        """Test SSL check returns OK for certificate valid > 14 days."""
        expiration_date = datetime.now(timezone.utc) + timedelta(days=30)
        not_after_str = expiration_date.strftime('%b %d %H:%M:%S %Y GMT')
        
        mock_cert = {
            'issuer': ((('organizationName', 'Test CA'),),),
            'subject': ((('commonName', 'example.com'),),),
            'subjectAltName': (('DNS', 'example.com'),),
            'notAfter': not_after_str,
            '_der': b'mock'
        }
        
        with patch.object(ssl_checker, '_get_certificate', return_value=mock_cert):
            result = await ssl_checker.check("example.com")
        
        assert result.status == CheckResult.OK
        assert result.details["days_until_expiry"] == 30
    
    @pytest.mark.asyncio
    async def test_check_warning_status(self, ssl_checker):
        """Test SSL check returns WARNING for certificate expiring in 7-13 days."""
        expiration_date = datetime.now(timezone.utc) + timedelta(days=10)
        not_after_str = expiration_date.strftime('%b %d %H:%M:%S %Y GMT')
        
        mock_cert = {
            'issuer': ((('organizationName', 'Test CA'),),),
            'subject': ((('commonName', 'example.com'),),),
            'subjectAltName': (('DNS', 'example.com'),),
            'notAfter': not_after_str,
            '_der': b'mock'
        }
        
        with patch.object(ssl_checker, '_get_certificate', return_value=mock_cert):
            result = await ssl_checker.check("example.com")
        
        assert result.status == CheckResult.WARNING
        assert result.details["days_until_expiry"] == 10
    
    @pytest.mark.asyncio
    async def test_check_critical_status_expiring_soon(self, ssl_checker):
        """Test SSL check returns CRITICAL for certificate expiring in < 7 days."""
        expiration_date = datetime.now(timezone.utc) + timedelta(days=3)
        not_after_str = expiration_date.strftime('%b %d %H:%M:%S %Y GMT')
        
        mock_cert = {
            'issuer': ((('organizationName', 'Test CA'),),),
            'subject': ((('commonName', 'example.com'),),),
            'subjectAltName': (('DNS', 'example.com'),),
            'notAfter': not_after_str,
            '_der': b'mock'
        }
        
        with patch.object(ssl_checker, '_get_certificate', return_value=mock_cert):
            result = await ssl_checker.check("example.com")
        
        assert result.status == CheckResult.CRITICAL
        assert result.details["days_until_expiry"] == 3
    
    @pytest.mark.asyncio
    async def test_check_critical_status_expired(self, ssl_checker):
        """Test SSL check returns CRITICAL for expired certificate."""
        expiration_date = datetime.now(timezone.utc) - timedelta(days=5)
        not_after_str = expiration_date.strftime('%b %d %H:%M:%S %Y GMT')
        
        mock_cert = {
            'issuer': ((('organizationName', 'Test CA'),),),
            'subject': ((('commonName', 'example.com'),),),
            'subjectAltName': (('DNS', 'example.com'),),
            'notAfter': not_after_str,
            '_der': b'mock'
        }
        
        with patch.object(ssl_checker, '_get_certificate', return_value=mock_cert):
            result = await ssl_checker.check("example.com")
        
        assert result.status == CheckResult.CRITICAL
        assert "expired" in result.message.lower()
        assert result.details["days_until_expiry"] < 0
    
    @pytest.mark.asyncio
    async def test_check_dns_resolution_failure(self, ssl_checker):
        """Test SSL check handles DNS resolution failure."""
        with patch.object(ssl_checker, '_get_certificate', side_effect=socket.gaierror("Name resolution failed")):
            result = await ssl_checker.check("nonexistent.example.com")
        
        assert result.status == CheckResult.ERROR
        assert "Failed to resolve domain name" in result.message
    
    @pytest.mark.asyncio
    async def test_check_connection_timeout(self, ssl_checker):
        """Test SSL check handles connection timeout."""
        with patch.object(ssl_checker, '_get_certificate', side_effect=socket.timeout("Connection timed out")):
            result = await ssl_checker.check("example.com")
        
        assert result.status == CheckResult.ERROR
        assert "timed out" in result.message.lower()
    
    @pytest.mark.asyncio
    async def test_check_ssl_error(self, ssl_checker):
        """Test SSL check handles SSL errors."""
        with patch.object(ssl_checker, '_get_certificate', side_effect=ssl.SSLError("SSL handshake failed")):
            result = await ssl_checker.check("example.com")
        
        assert result.status == CheckResult.ERROR
        assert "SSL error" in result.message
    
    @pytest.mark.asyncio
    async def test_check_generic_exception(self, ssl_checker):
        """Test SSL check handles generic exceptions."""
        with patch.object(ssl_checker, '_get_certificate', side_effect=Exception("Unexpected error")):
            result = await ssl_checker.check("example.com")
        
        assert result.status == CheckResult.ERROR
        assert "SSL check failed" in result.message


class TestCertificateParsing:
    """Tests for certificate parsing methods."""
    
    def test_parse_certificate_issuer(self, ssl_checker):
        """Test parsing certificate issuer."""
        cert_dict = {
            'issuer': ((('organizationName', 'Let\'s Encrypt'),),),
            'subject': ((('commonName', 'example.com'),),),
            'subjectAltName': (),
            'notAfter': 'Dec 31 23:59:59 2025 GMT',
            '_der': b'mock'
        }
        
        result = ssl_checker._parse_certificate(cert_dict)
        assert result['issuer'] == "Let's Encrypt"
    
    def test_parse_certificate_issuer_fallback_to_cn(self, ssl_checker):
        """Test parsing certificate issuer falls back to commonName."""
        cert_dict = {
            'issuer': ((('commonName', 'Test CA'),),),
            'subject': ((('commonName', 'example.com'),),),
            'subjectAltName': (),
            'notAfter': 'Dec 31 23:59:59 2025 GMT',
            '_der': b'mock'
        }
        
        result = ssl_checker._parse_certificate(cert_dict)
        assert result['issuer'] == "Test CA"
    
    def test_parse_certificate_subject(self, ssl_checker):
        """Test parsing certificate subject."""
        cert_dict = {
            'issuer': ((('organizationName', 'Test CA'),),),
            'subject': ((('commonName', 'example.com'),),),
            'subjectAltName': (),
            'notAfter': 'Dec 31 23:59:59 2025 GMT',
            '_der': b'mock'
        }
        
        result = ssl_checker._parse_certificate(cert_dict)
        assert result['subject'] == "example.com"
    
    def test_parse_certificate_sans(self, ssl_checker):
        """Test parsing Subject Alternative Names."""
        cert_dict = {
            'issuer': ((('organizationName', 'Test CA'),),),
            'subject': ((('commonName', 'example.com'),),),
            'subjectAltName': (
                ('DNS', 'example.com'),
                ('DNS', 'www.example.com'),
                ('DNS', '*.example.com'),
            ),
            'notAfter': 'Dec 31 23:59:59 2025 GMT',
            '_der': b'mock'
        }
        
        result = ssl_checker._parse_certificate(cert_dict)
        assert result['sans'] == ['example.com', 'www.example.com', '*.example.com']
    
    def test_parse_certificate_empty_sans(self, ssl_checker):
        """Test parsing certificate with no SANs."""
        cert_dict = {
            'issuer': ((('organizationName', 'Test CA'),),),
            'subject': ((('commonName', 'example.com'),),),
            'notAfter': 'Dec 31 23:59:59 2025 GMT',
            '_der': b'mock'
        }
        
        result = ssl_checker._parse_certificate(cert_dict)
        assert result['sans'] == []
    
    def test_parse_certificate_expiration_date(self, ssl_checker):
        """Test parsing certificate expiration date."""
        cert_dict = {
            'issuer': ((('organizationName', 'Test CA'),),),
            'subject': ((('commonName', 'example.com'),),),
            'subjectAltName': (),
            'notAfter': 'Dec 31 23:59:59 2025 GMT',
            '_der': b'mock'
        }
        
        result = ssl_checker._parse_certificate(cert_dict)
        assert 'expiration_date' in result
        assert '2025-12-31' in result['expiration_date']


class TestStatusDetermination:
    """Tests for SSL status determination."""
    
    def test_determine_status_ok(self, ssl_checker):
        """Test status determination for OK (>= 14 days)."""
        assert ssl_checker._determine_status(14) == CheckResult.OK
        assert ssl_checker._determine_status(30) == CheckResult.OK
        assert ssl_checker._determine_status(365) == CheckResult.OK
    
    def test_determine_status_warning(self, ssl_checker):
        """Test status determination for WARNING (7-13 days)."""
        assert ssl_checker._determine_status(7) == CheckResult.WARNING
        assert ssl_checker._determine_status(10) == CheckResult.WARNING
        assert ssl_checker._determine_status(13) == CheckResult.WARNING
    
    def test_determine_status_critical_expiring_soon(self, ssl_checker):
        """Test status determination for CRITICAL (< 7 days)."""
        assert ssl_checker._determine_status(6) == CheckResult.CRITICAL
        assert ssl_checker._determine_status(3) == CheckResult.CRITICAL
        assert ssl_checker._determine_status(0) == CheckResult.CRITICAL
    
    def test_determine_status_critical_expired(self, ssl_checker):
        """Test status determination for CRITICAL (expired)."""
        assert ssl_checker._determine_status(-1) == CheckResult.CRITICAL
        assert ssl_checker._determine_status(-10) == CheckResult.CRITICAL
        assert ssl_checker._determine_status(-100) == CheckResult.CRITICAL
