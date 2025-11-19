"""
Tests for WHOIS checker module.

Tests WHOIS data extraction, expiration calculation, and status determination.
"""

from datetime import datetime, timedelta
from unittest.mock import Mock, patch

import pytest

from domain_monitor.checkers.whois import WhoisChecker
from domain_monitor.checkers.base_checker import CheckResult


@pytest.fixture
def whois_checker():
    """Create a WhoisChecker instance for testing."""
    return WhoisChecker(timeout=10)


@pytest.fixture
def mock_whois_data():
    """Create mock WHOIS data object."""
    mock_data = Mock()
    mock_data.registrar = "Example Registrar Inc."
    mock_data.status = ["clientTransferProhibited", "clientUpdateProhibited"]
    return mock_data


class TestWhoisChecker:
    """Tests for WhoisChecker class."""
    
    @pytest.mark.asyncio
    async def test_check_success_with_valid_data(self, whois_checker, mock_whois_data):
        """Test successful WHOIS check with valid data."""
        # Set expiration date to 90 days from now (should be OK/GREEN)
        expiration_date = datetime.now() + timedelta(days=90)
        mock_whois_data.expiration_date = expiration_date
        
        with patch('whois.whois', return_value=mock_whois_data):
            result = await whois_checker.check("example.com")
        
        assert isinstance(result, CheckResult)
        assert result.domain == "example.com"
        assert result.check_type == "whois"
        assert result.status == CheckResult.OK
        assert "90 days" in result.message
        assert result.details["registrar"] == "Example Registrar Inc."
        assert result.details["days_until_expiry"] == 90
    
    @pytest.mark.asyncio
    async def test_check_warning_status(self, whois_checker, mock_whois_data):
        """Test WHOIS check returns WARNING for expiration < 60 days."""
        # Set expiration date to 45 days from now (should be WARNING/YELLOW)
        expiration_date = datetime.now() + timedelta(days=45)
        mock_whois_data.expiration_date = expiration_date
        
        with patch('whois.whois', return_value=mock_whois_data):
            result = await whois_checker.check("example.com")
        
        assert result.status == CheckResult.WARNING
        assert result.details["days_until_expiry"] == 45
    
    @pytest.mark.asyncio
    async def test_check_critical_status(self, whois_checker, mock_whois_data):
        """Test WHOIS check returns CRITICAL for expiration < 30 days."""
        # Set expiration date to 15 days from now (should be CRITICAL/RED)
        expiration_date = datetime.now() + timedelta(days=15)
        mock_whois_data.expiration_date = expiration_date
        
        with patch('whois.whois', return_value=mock_whois_data):
            result = await whois_checker.check("example.com")
        
        assert result.status == CheckResult.CRITICAL
        assert result.details["days_until_expiry"] == 15
    
    @pytest.mark.asyncio
    async def test_check_expired_domain(self, whois_checker, mock_whois_data):
        """Test WHOIS check for already expired domain."""
        # Set expiration date to 10 days ago (should be CRITICAL)
        expiration_date = datetime.now() - timedelta(days=10)
        mock_whois_data.expiration_date = expiration_date
        
        with patch('whois.whois', return_value=mock_whois_data):
            result = await whois_checker.check("example.com")
        
        assert result.status == CheckResult.CRITICAL
        assert "expired" in result.message.lower()
        assert result.details["days_until_expiry"] == -10
    
    @pytest.mark.asyncio
    async def test_check_missing_expiration_date(self, whois_checker, mock_whois_data):
        """Test WHOIS check when expiration date is missing."""
        mock_whois_data.expiration_date = None
        
        with patch('whois.whois', return_value=mock_whois_data):
            result = await whois_checker.check("example.com")
        
        assert result.status == CheckResult.ERROR
        assert "Unable to extract expiration date" in result.message
    
    @pytest.mark.asyncio
    async def test_check_whois_error(self, whois_checker):
        """Test WHOIS check handles WHOIS query errors."""
        from whois.parser import PywhoisError
        
        with patch('whois.whois', side_effect=PywhoisError("WHOIS query failed")):
            result = await whois_checker.check("example.com")
        
        assert result.status == CheckResult.ERROR
        assert "WHOIS query failed" in result.message
        assert result.details["error_type"] == "whois_error"
    
    @pytest.mark.asyncio
    async def test_check_generic_exception(self, whois_checker):
        """Test WHOIS check handles generic exceptions."""
        with patch('whois.whois', side_effect=Exception("Network error")):
            result = await whois_checker.check("example.com")
        
        assert result.status == CheckResult.ERROR
        assert "WHOIS check failed" in result.message


class TestWhoisDataExtraction:
    """Tests for WHOIS data extraction methods."""
    
    def test_extract_registrar_string(self, whois_checker):
        """Test extracting registrar when it's a string."""
        mock_data = Mock()
        mock_data.registrar = "Example Registrar"
        
        result = whois_checker._extract_registrar(mock_data)
        assert result == "Example Registrar"
    
    def test_extract_registrar_list(self, whois_checker):
        """Test extracting registrar when it's a list."""
        mock_data = Mock()
        mock_data.registrar = ["First Registrar", "Second Registrar"]
        
        result = whois_checker._extract_registrar(mock_data)
        assert result == "First Registrar"
    
    def test_extract_registrar_empty_list(self, whois_checker):
        """Test extracting registrar from empty list."""
        mock_data = Mock()
        mock_data.registrar = []
        
        result = whois_checker._extract_registrar(mock_data)
        assert result is None
    
    def test_extract_registrar_missing(self, whois_checker):
        """Test extracting registrar when attribute is missing."""
        mock_data = Mock(spec=[])
        
        result = whois_checker._extract_registrar(mock_data)
        assert result is None
    
    def test_extract_status_string(self, whois_checker):
        """Test extracting status when it's a string."""
        mock_data = Mock()
        mock_data.status = "clientTransferProhibited"
        
        result = whois_checker._extract_status(mock_data)
        assert result == "clientTransferProhibited"
    
    def test_extract_status_list(self, whois_checker):
        """Test extracting status when it's a list."""
        mock_data = Mock()
        mock_data.status = ["status1", "status2", "status3"]
        
        result = whois_checker._extract_status(mock_data)
        assert result == "status1, status2, status3"
    
    def test_extract_expiration_date_datetime(self, whois_checker):
        """Test extracting expiration date as datetime."""
        mock_data = Mock()
        expiration = datetime(2025, 12, 31, 23, 59, 59)
        mock_data.expiration_date = expiration
        
        result = whois_checker._extract_expiration_date(mock_data)
        assert result == expiration
    
    def test_extract_expiration_date_list(self, whois_checker):
        """Test extracting expiration date from list."""
        mock_data = Mock()
        expiration = datetime(2025, 12, 31, 23, 59, 59)
        mock_data.expiration_date = [expiration, datetime(2026, 1, 1)]
        
        result = whois_checker._extract_expiration_date(mock_data)
        assert result == expiration
    
    def test_extract_expiration_date_missing(self, whois_checker):
        """Test extracting expiration date when missing."""
        mock_data = Mock(spec=[])
        
        result = whois_checker._extract_expiration_date(mock_data)
        assert result is None
    
    def test_extract_country_string(self, whois_checker):
        """Test extracting country when it's a string."""
        mock_data = Mock()
        mock_data.country = "KR"
        
        result = whois_checker._extract_country(mock_data)
        assert result == "KR"
    
    def test_extract_country_list(self, whois_checker):
        """Test extracting country when it's a list."""
        mock_data = Mock()
        mock_data.country = ["KR", "US"]
        
        result = whois_checker._extract_country(mock_data)
        assert result == "KR"
    
    def test_extract_country_empty_list(self, whois_checker):
        """Test extracting country from empty list."""
        mock_data = Mock()
        mock_data.country = []
        
        result = whois_checker._extract_country(mock_data)
        assert result is None
    
    def test_extract_country_missing(self, whois_checker):
        """Test extracting country when attribute is missing."""
        mock_data = Mock(spec=[])
        
        result = whois_checker._extract_country(mock_data)
        assert result is None


class TestExpirationCalculation:
    """Tests for expiration date calculation."""
    
    def test_calculate_days_until_expiry_future(self, whois_checker):
        """Test calculating days until expiry for future date."""
        expiry_date = datetime.now() + timedelta(days=100)
        
        result = whois_checker._calculate_days_until_expiry(expiry_date)
        assert result == 100
    
    def test_calculate_days_until_expiry_past(self, whois_checker):
        """Test calculating days until expiry for past date."""
        expiry_date = datetime.now() - timedelta(days=50)
        
        result = whois_checker._calculate_days_until_expiry(expiry_date)
        assert result == -50
    
    def test_calculate_days_until_expiry_timezone_aware(self, whois_checker):
        """Test calculating days with timezone-aware datetime."""
        from datetime import timezone
        
        expiry_date = datetime.now(timezone.utc) + timedelta(days=75)
        
        result = whois_checker._calculate_days_until_expiry(expiry_date)
        assert result == 75


class TestStatusDetermination:
    """Tests for status determination based on days until expiry."""
    
    def test_determine_status_ok(self, whois_checker):
        """Test status determination for OK (>= 60 days)."""
        assert whois_checker._determine_status(60) == CheckResult.OK
        assert whois_checker._determine_status(100) == CheckResult.OK
        assert whois_checker._determine_status(365) == CheckResult.OK
    
    def test_determine_status_warning(self, whois_checker):
        """Test status determination for WARNING (30-59 days)."""
        assert whois_checker._determine_status(30) == CheckResult.WARNING
        assert whois_checker._determine_status(45) == CheckResult.WARNING
        assert whois_checker._determine_status(59) == CheckResult.WARNING
    
    def test_determine_status_critical(self, whois_checker):
        """Test status determination for CRITICAL (< 30 days)."""
        assert whois_checker._determine_status(29) == CheckResult.CRITICAL
        assert whois_checker._determine_status(15) == CheckResult.CRITICAL
        assert whois_checker._determine_status(0) == CheckResult.CRITICAL
        assert whois_checker._determine_status(-10) == CheckResult.CRITICAL
