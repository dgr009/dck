"""
Tests for DNS checker module.

Tests DNS record queries, propagation checking, and cache mismatch detection.
"""

from unittest.mock import Mock, patch, AsyncMock

import dns.resolver
import dns.exception
import pytest

from domain_monitor.checkers.dns import DNSChecker
from domain_monitor.checkers.base_checker import CheckResult


@pytest.fixture
def dns_checker():
    """Create a DNSChecker instance for testing."""
    return DNSChecker(timeout=10)


class TestDNSChecker:
    """Tests for DNSChecker class."""
    
    @pytest.mark.asyncio
    async def test_check_success_all_records(self, dns_checker):
        """Test successful DNS check with all record types."""
        with patch.object(dns_checker, '_query_record', return_value=['192.0.2.1']), \
             patch.object(dns_checker, '_check_propagation', return_value={'consistent': True, 'message': 'OK', 'results': {}}), \
             patch.object(dns_checker, '_check_cache_mismatch', return_value={'mismatch': False, 'message': 'OK'}):
            
            result = await dns_checker.check("example.com")
        
        assert isinstance(result, CheckResult)
        assert result.domain == "example.com"
        assert result.check_type == "dns"
        assert result.status == CheckResult.OK
        assert "successfully" in result.message.lower()
    
    @pytest.mark.asyncio
    async def test_check_propagation_mismatch_warning(self, dns_checker):
        """Test DNS check returns WARNING for propagation mismatch."""
        with patch.object(dns_checker, '_query_record', return_value=['192.0.2.1']), \
             patch.object(dns_checker, '_check_propagation', return_value={
                 'consistent': False,
                 'message': 'Different results from servers: 1.1.1.1',
                 'results': {}
             }), \
             patch.object(dns_checker, '_check_cache_mismatch', return_value={'mismatch': False, 'message': 'OK'}):
            
            result = await dns_checker.check("example.com")
        
        assert result.status == CheckResult.WARNING
        assert "Propagation Mismatch" in result.message
    
    @pytest.mark.asyncio
    async def test_check_cache_mismatch_warning(self, dns_checker):
        """Test DNS check returns WARNING for cache mismatch."""
        with patch.object(dns_checker, '_query_record', return_value=['192.0.2.1']), \
             patch.object(dns_checker, '_check_propagation', return_value={'consistent': True, 'message': 'OK', 'results': {}}), \
             patch.object(dns_checker, '_check_cache_mismatch', return_value={
                 'mismatch': True,
                 'message': 'Local DNS differs from public DNS'
             }):
            
            result = await dns_checker.check("example.com")
        
        assert result.status == CheckResult.WARNING
        assert "Cache Mismatch" in result.message
    
    @pytest.mark.asyncio
    async def test_check_both_warnings(self, dns_checker):
        """Test DNS check with both propagation and cache warnings."""
        with patch.object(dns_checker, '_query_record', return_value=['192.0.2.1']), \
             patch.object(dns_checker, '_check_propagation', return_value={
                 'consistent': False,
                 'message': 'Propagation issue',
                 'results': {}
             }), \
             patch.object(dns_checker, '_check_cache_mismatch', return_value={
                 'mismatch': True,
                 'message': 'Cache issue'
             }):
            
            result = await dns_checker.check("example.com")
        
        assert result.status == CheckResult.WARNING
        assert "Propagation Mismatch" in result.message
        assert "Cache Mismatch" in result.message
    
    @pytest.mark.asyncio
    async def test_check_exception_handling(self, dns_checker):
        """Test DNS check handles exceptions."""
        with patch.object(dns_checker, '_query_record', side_effect=Exception("DNS error")):
            result = await dns_checker.check("example.com")
        
        assert result.status == CheckResult.ERROR
        assert "DNS check failed" in result.message


class TestQueryRecord:
    """Tests for _query_record method."""
    
    @pytest.mark.asyncio
    async def test_query_a_record(self, dns_checker):
        """Test querying A records."""
        with patch.object(dns_checker, '_query_record_sync', return_value=['192.0.2.1', '192.0.2.2']):
            result = await dns_checker._query_record("example.com", 'A')
        
        assert result == ['192.0.2.1', '192.0.2.2']
    
    @pytest.mark.asyncio
    async def test_query_aaaa_record(self, dns_checker):
        """Test querying AAAA records."""
        with patch.object(dns_checker, '_query_record_sync', return_value=['2001:db8::1']):
            result = await dns_checker._query_record("example.com", 'AAAA')
        
        assert result == ['2001:db8::1']
    
    @pytest.mark.asyncio
    async def test_query_mx_record(self, dns_checker):
        """Test querying MX records."""
        with patch.object(dns_checker, '_query_record_sync', return_value=['10 mail.example.com']):
            result = await dns_checker._query_record("example.com", 'MX')
        
        assert result == ['10 mail.example.com']
    
    @pytest.mark.asyncio
    async def test_query_ns_record(self, dns_checker):
        """Test querying NS records."""
        with patch.object(dns_checker, '_query_record_sync', return_value=['ns1.example.com', 'ns2.example.com']):
            result = await dns_checker._query_record("example.com", 'NS')
        
        assert result == ['ns1.example.com', 'ns2.example.com']
    
    @pytest.mark.asyncio
    async def test_query_txt_record(self, dns_checker):
        """Test querying TXT records."""
        with patch.object(dns_checker, '_query_record_sync', return_value=['v=spf1 include:_spf.example.com ~all']):
            result = await dns_checker._query_record("example.com", 'TXT')
        
        assert result == ['v=spf1 include:_spf.example.com ~all']
    
    @pytest.mark.asyncio
    async def test_query_nxdomain(self, dns_checker):
        """Test querying non-existent domain."""
        with patch.object(dns_checker, '_query_record_sync', side_effect=dns.resolver.NXDOMAIN()):
            result = await dns_checker._query_record("nonexistent.example.com", 'A')
        
        assert result == []
    
    @pytest.mark.asyncio
    async def test_query_no_answer(self, dns_checker):
        """Test querying record type with no answer."""
        with patch.object(dns_checker, '_query_record_sync', side_effect=dns.resolver.NoAnswer()):
            result = await dns_checker._query_record("example.com", 'AAAA')
        
        assert result == []
    
    @pytest.mark.asyncio
    async def test_query_timeout(self, dns_checker):
        """Test querying with timeout."""
        with patch.object(dns_checker, '_query_record_sync', side_effect=dns.exception.Timeout()):
            result = await dns_checker._query_record("example.com", 'A')
        
        assert result == []
    
    @pytest.mark.asyncio
    async def test_query_with_nameserver(self, dns_checker):
        """Test querying with specific nameserver."""
        with patch.object(dns_checker, '_query_record_sync', return_value=['192.0.2.1']) as mock_query:
            result = await dns_checker._query_record("example.com", 'A', nameserver='8.8.8.8')
        
        mock_query.assert_called_once_with("example.com", 'A', '8.8.8.8')
        assert result == ['192.0.2.1']


class TestCheckPropagation:
    """Tests for DNS propagation checking."""
    
    @pytest.mark.asyncio
    async def test_propagation_consistent(self, dns_checker):
        """Test propagation check when all servers agree."""
        async def mock_query(domain, record_type, nameserver=None):
            return ['192.0.2.1', '192.0.2.2']
        
        with patch.object(dns_checker, '_query_record', side_effect=mock_query):
            result = await dns_checker._check_propagation("example.com")
        
        assert result['consistent'] is True
        assert "consistently" in result['message'].lower()
    
    @pytest.mark.asyncio
    async def test_propagation_mismatch(self, dns_checker):
        """Test propagation check when servers disagree."""
        call_count = 0
        
        async def mock_query(domain, record_type, nameserver=None):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return ['192.0.2.1']
            else:
                return ['192.0.2.2']
        
        with patch.object(dns_checker, '_query_record', side_effect=mock_query):
            result = await dns_checker._check_propagation("example.com")
        
        assert result['consistent'] is False
        assert "Different results" in result['message']
    
    @pytest.mark.asyncio
    async def test_propagation_no_records(self, dns_checker):
        """Test propagation check when no records found."""
        async def mock_query(domain, record_type, nameserver=None):
            return []
        
        with patch.object(dns_checker, '_query_record', side_effect=mock_query):
            result = await dns_checker._check_propagation("example.com")
        
        assert result['consistent'] is True
        assert "No A records" in result['message']
    
    @pytest.mark.asyncio
    async def test_propagation_queries_all_servers(self, dns_checker):
        """Test that propagation check queries all public DNS servers."""
        query_calls = []
        
        async def mock_query(domain, record_type, nameserver=None):
            query_calls.append(nameserver)
            return ['192.0.2.1']
        
        with patch.object(dns_checker, '_query_record', side_effect=mock_query):
            await dns_checker._check_propagation("example.com")
        
        assert '8.8.8.8' in query_calls
        assert '1.1.1.1' in query_calls
        assert '9.9.9.9' in query_calls


class TestCheckCacheMismatch:
    """Tests for local vs public DNS cache comparison."""
    
    @pytest.mark.asyncio
    async def test_cache_match(self, dns_checker):
        """Test cache check when local and public DNS match."""
        async def mock_query(domain, record_type, nameserver=None):
            return ['192.0.2.1']
        
        with patch.object(dns_checker, '_query_record', side_effect=mock_query):
            result = await dns_checker._check_cache_mismatch("example.com")
        
        assert result['mismatch'] is False
        assert "match" in result['message'].lower()
    
    @pytest.mark.asyncio
    async def test_cache_mismatch(self, dns_checker):
        """Test cache check when local and public DNS differ."""
        call_count = 0
        
        async def mock_query(domain, record_type, nameserver=None):
            nonlocal call_count
            call_count += 1
            if nameserver is None:
                # Local resolver
                return ['192.0.2.1']
            else:
                # Public DNS
                return ['192.0.2.2']
        
        with patch.object(dns_checker, '_query_record', side_effect=mock_query):
            result = await dns_checker._check_cache_mismatch("example.com")
        
        assert result['mismatch'] is True
        assert "differs" in result['message'].lower()
        assert result['local_results'] == ['192.0.2.1']
        assert result['public_results'] == ['192.0.2.2']
    
    @pytest.mark.asyncio
    async def test_cache_queries_system_and_google(self, dns_checker):
        """Test that cache check queries both system resolver and Google DNS."""
        query_calls = []
        
        async def mock_query(domain, record_type, nameserver=None):
            query_calls.append(nameserver)
            return ['192.0.2.1']
        
        with patch.object(dns_checker, '_query_record', side_effect=mock_query):
            await dns_checker._check_cache_mismatch("example.com")
        
        assert None in query_calls  # System resolver
        assert '8.8.8.8' in query_calls  # Google DNS
