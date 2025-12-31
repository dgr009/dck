"""
Unit tests for DNS propagation error handling.

Tests error handling for NXDOMAIN, timeout, and invalid record type scenarios.
"""

import pytest
import asyncio
from unittest.mock import patch, MagicMock

from domain_monitor.checkers.dns_propagation_checker import DNSPropagationChecker
from domain_monitor.models import DNSServerInfo


class TestNXDOMAINHandling:
    """Tests for NXDOMAIN (domain not found) error handling."""
    
    @pytest.mark.asyncio
    async def test_nxdomain_returns_empty_values(self):
        """
        Test that NXDOMAIN errors result in empty values list.
        
        When a domain does not exist, the query should return an empty values list
        and handle the error gracefully without raising an exception.
        
        Validates: Requirements 9.1
        """
        # Use a domain that definitely doesn't exist
        nonexistent_domain = f"this-domain-absolutely-does-not-exist-{asyncio.get_event_loop().time()}.invalid"
        
        # Use a single fast DNS server
        fast_servers = [("8.8.8.8", "Google Primary", "Global")]
        checker = DNSPropagationChecker(custom_servers=fast_servers)
        
        # Query the nonexistent domain
        result = await checker.check_propagation(nonexistent_domain, "A")
        
        # Verify the query completed without raising an exception
        assert result is not None
        assert result.domain == nonexistent_domain
        assert result.record_type == "A"
        
        # Verify that results have empty values (NXDOMAIN)
        for query_result in result.query_results:
            # Should not have timeout/unreachable status
            # NXDOMAIN is handled as successful query with empty results
            assert query_result.status in ('success', 'no_records', 'matched', 'mismatched')
            assert len(query_result.values) == 0, \
                f"Expected empty values for NXDOMAIN, got {query_result.values}"
    
    @pytest.mark.asyncio
    async def test_nxdomain_with_expected_value(self):
        """
        Test that NXDOMAIN with expected value results in mismatched status.
        
        When a domain doesn't exist but an expected value is provided,
        the status should be 'mismatched' since the actual value (empty) 
        doesn't match the expected value.
        
        Validates: Requirements 9.1, 4.2, 4.3
        """
        # Use a domain that doesn't exist
        nonexistent_domain = f"nonexistent-{asyncio.get_event_loop().time()}.invalid"
        
        # Use a single fast DNS server
        fast_servers = [("8.8.8.8", "Google Primary", "Global")]
        checker = DNSPropagationChecker(custom_servers=fast_servers)
        
        # Query with expected value
        result = await checker.check_propagation(
            nonexistent_domain, 
            "A", 
            expected_value="192.0.2.1"
        )
        
        # Verify that results are marked as mismatched
        for query_result in result.query_results:
            if query_result.status not in ('timeout', 'unreachable'):
                assert query_result.status == 'mismatched', \
                    f"Expected 'mismatched' status for NXDOMAIN with expected value"
                assert len(query_result.values) == 0
    
    @pytest.mark.asyncio
    async def test_nxdomain_does_not_block_other_queries(self):
        """
        Test that NXDOMAIN on one server doesn't affect other servers.
        
        When querying multiple servers and one returns NXDOMAIN, other servers
        should still complete their queries normally.
        
        Validates: Requirements 9.1, 2.3
        """
        # Use a domain that doesn't exist
        nonexistent_domain = f"nonexistent-{asyncio.get_event_loop().time()}.invalid"
        
        # Use multiple fast DNS servers
        fast_servers = [
            ("8.8.8.8", "Google Primary", "Global"),
            ("1.1.1.1", "Cloudflare Primary", "Global"),
            ("9.9.9.9", "Quad9", "Global"),
        ]
        checker = DNSPropagationChecker(custom_servers=fast_servers)
        
        # Query the nonexistent domain
        result = await checker.check_propagation(nonexistent_domain, "A")
        
        # Verify all servers completed their queries (default + custom)
        # Default servers: 12, Custom servers: 3, but some may be duplicates
        assert len(result.query_results) >= len(fast_servers)
        
        # All should have empty values (NXDOMAIN is consistent across servers)
        for query_result in result.query_results:
            assert len(query_result.values) == 0


class TestTimeoutHandling:
    """Tests for timeout error handling."""
    
    @pytest.mark.asyncio
    async def test_timeout_marked_as_timeout_status(self):
        """
        Test that timeout errors result in 'timeout' status.
        
        When a DNS server query times out, the result should have status 'timeout'
        and include error information.
        
        Validates: Requirements 9.2, 1.4
        """
        # Use an unreachable IP address (TEST-NET-1)
        unreachable_servers = [("192.0.2.1", "Unreachable Server", "Test")]
        checker = DNSPropagationChecker(custom_servers=unreachable_servers)
        
        # Query a known domain
        result = await checker.check_propagation("google.com", "A")
        
        # Find the unreachable server result (default servers + custom)
        unreachable_result = None
        for query_result in result.query_results:
            if query_result.server.ip == "192.0.2.1":
                unreachable_result = query_result
                break
        
        assert unreachable_result is not None, "Unreachable server result not found"
        assert unreachable_result.status in ('timeout', 'unreachable'), \
            f"Expected 'timeout' or 'unreachable' status, got {unreachable_result.status}"
        assert len(unreachable_result.values) == 0
        assert unreachable_result.error is not None, "Expected error message for timeout"
    
    @pytest.mark.asyncio
    async def test_timeout_does_not_block_other_servers(self):
        """
        Test that timeout on one server doesn't block other servers.
        
        When one DNS server times out, other servers should still complete
        their queries successfully.
        
        Validates: Requirements 9.2, 2.3, 1.4
        """
        # Mix of unreachable and reachable servers
        mixed_servers = [
            ("192.0.2.1", "Unreachable", "Test"),
            ("8.8.8.8", "Google Primary", "Global"),
            ("1.1.1.1", "Cloudflare Primary", "Global"),
        ]
        checker = DNSPropagationChecker(custom_servers=mixed_servers)
        
        # Query a known domain
        result = await checker.check_propagation("google.com", "A")
        
        # Verify all servers were queried (default + custom)
        assert len(result.query_results) >= 3
        
        # Verify at least one timeout/unreachable
        timeout_count = sum(1 for r in result.query_results 
                           if r.status in ('timeout', 'unreachable'))
        assert timeout_count >= 1, "Expected at least one timeout"
        
        # Verify at least one successful query
        success_count = sum(1 for r in result.query_results 
                           if r.status not in ('timeout', 'unreachable'))
        assert success_count >= 2, "Expected at least two successful queries"
    
    @pytest.mark.asyncio
    async def test_timeout_respects_timeout_limit(self):
        """
        Test that timeout occurs within reasonable time limit.
        
        Individual DNS queries should timeout within the configured limit
        (5 seconds per query).
        
        Validates: Requirements 9.2, 2.5
        """
        import time
        
        # Use unreachable server
        unreachable_servers = [("192.0.2.1", "Unreachable", "Test")]
        checker = DNSPropagationChecker(custom_servers=unreachable_servers)
        
        # Measure query time
        start_time = time.time()
        result = await checker.check_propagation("google.com", "A")
        elapsed_time = time.time() - start_time
        
        # Should timeout within reasonable time (5s timeout + overhead)
        assert elapsed_time < 10.0, \
            f"Query took too long: {elapsed_time}s (expected < 10s)"
        
        # Find the unreachable server result
        unreachable_result = None
        for query_result in result.query_results:
            if query_result.server.ip == "192.0.2.1":
                unreachable_result = query_result
                break
        
        assert unreachable_result is not None, "Unreachable server result not found"
        assert unreachable_result.status in ('timeout', 'unreachable')


class TestInvalidRecordTypeValidation:
    """Tests for invalid record type validation."""
    
    @pytest.mark.asyncio
    async def test_invalid_record_type_raises_value_error(self):
        """
        Test that invalid record type raises ValueError.
        
        When an unsupported record type is specified, the checker should
        raise a ValueError with a clear error message.
        
        Validates: Requirements 9.3
        """
        checker = DNSPropagationChecker()
        
        # Try to query with invalid record type
        with pytest.raises(ValueError) as exc_info:
            await checker.check_propagation("google.com", "INVALID")
        
        # Verify error message is helpful
        error_message = str(exc_info.value)
        assert "Invalid record type" in error_message
        assert "INVALID" in error_message
        assert "Supported types" in error_message
    
    @pytest.mark.asyncio
    async def test_invalid_record_type_lists_valid_types(self):
        """
        Test that error message lists valid record types.
        
        The error message for invalid record type should include a list
        of all supported record types.
        
        Validates: Requirements 9.3
        """
        checker = DNSPropagationChecker()
        
        # Try to query with invalid record type
        with pytest.raises(ValueError) as exc_info:
            await checker.check_propagation("google.com", "BADTYPE")
        
        # Verify error message lists valid types
        error_message = str(exc_info.value)
        
        # Should mention all supported types
        for record_type in ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']:
            assert record_type in error_message, \
                f"Expected {record_type} in error message"
    
    @pytest.mark.asyncio
    async def test_multiple_invalid_record_types(self):
        """
        Test that various invalid record types are all rejected.
        
        Any unsupported record type should be rejected with a clear error.
        
        Validates: Requirements 9.3
        """
        checker = DNSPropagationChecker()
        
        invalid_types = ['INVALID', 'BADTYPE', 'WRONG', 'XYZ', 'PTR', 'SOA']
        
        for invalid_type in invalid_types:
            with pytest.raises(ValueError) as exc_info:
                await checker.check_propagation("google.com", invalid_type)
            
            error_message = str(exc_info.value)
            assert "Invalid record type" in error_message
            assert invalid_type in error_message
    
    @pytest.mark.asyncio
    async def test_case_insensitive_record_type_validation(self):
        """
        Test that record type validation is case-insensitive.
        
        Valid record types should be accepted in any case (uppercase, lowercase, mixed).
        
        Validates: Requirements 9.3, 3.1-3.6
        """
        # Use a fast server for quick testing
        fast_servers = [("8.8.8.8", "Google Primary", "Global")]
        checker = DNSPropagationChecker(custom_servers=fast_servers)
        
        # Test lowercase
        result_lower = await checker.check_propagation("google.com", "a")
        assert result_lower.record_type == "A"
        
        # Test uppercase
        result_upper = await checker.check_propagation("google.com", "A")
        assert result_upper.record_type == "A"
        
        # Test mixed case
        result_mixed = await checker.check_propagation("google.com", "Mx")
        assert result_mixed.record_type == "MX"


class TestNetworkErrorHandling:
    """Tests for network error handling."""
    
    @pytest.mark.asyncio
    async def test_network_unreachable_marked_correctly(self):
        """
        Test that network unreachable errors are marked as 'unreachable'.
        
        When a DNS server cannot be reached due to network issues,
        the result should have status 'unreachable'.
        
        Validates: Requirements 9.2, 9.4
        """
        # Use unreachable IP address
        unreachable_servers = [("192.0.2.1", "Unreachable", "Test")]
        checker = DNSPropagationChecker(custom_servers=unreachable_servers)
        
        # Query
        result = await checker.check_propagation("google.com", "A")
        
        # Find the unreachable server result
        unreachable_result = None
        for query_result in result.query_results:
            if query_result.server.ip == "192.0.2.1":
                unreachable_result = query_result
                break
        
        assert unreachable_result is not None, "Unreachable server result not found"
        assert unreachable_result.status in ('timeout', 'unreachable'), \
            f"Expected 'timeout' or 'unreachable' status, got {unreachable_result.status}"
        assert len(unreachable_result.values) == 0
        assert unreachable_result.error is not None
    
    @pytest.mark.asyncio
    async def test_partial_network_failure_continues(self):
        """
        Test that partial network failures don't stop the entire check.
        
        When some servers are unreachable, the check should continue
        with the remaining servers.
        
        Validates: Requirements 9.4, 2.3
        """
        # Mix of unreachable and reachable servers
        mixed_servers = [
            ("192.0.2.1", "Unreachable 1", "Test"),
            ("8.8.8.8", "Google Primary", "Global"),
            ("192.0.2.2", "Unreachable 2", "Test"),
            ("1.1.1.1", "Cloudflare Primary", "Global"),
        ]
        checker = DNSPropagationChecker(custom_servers=mixed_servers)
        
        # Query
        result = await checker.check_propagation("google.com", "A")
        
        # Verify all servers were attempted (default + custom)
        assert len(result.query_results) >= 4
        
        # Verify some failed
        failed_count = sum(1 for r in result.query_results 
                          if r.status in ('timeout', 'unreachable'))
        assert failed_count >= 2, "Expected at least 2 failed queries"
        
        # Verify some succeeded
        success_count = sum(1 for r in result.query_results 
                           if r.status not in ('timeout', 'unreachable'))
        assert success_count >= 2, "Expected at least 2 successful queries"
    
    @pytest.mark.asyncio
    async def test_all_servers_unreachable_completes_gracefully(self):
        """
        Test that check completes gracefully when all servers are unreachable.
        
        Even when all DNS servers are unreachable, the check should complete
        without raising an exception.
        
        Validates: Requirements 9.4
        """
        # All unreachable servers
        unreachable_servers = [
            ("192.0.2.1", "Unreachable 1", "Test"),
            ("192.0.2.2", "Unreachable 2", "Test"),
            ("192.0.2.3", "Unreachable 3", "Test"),
        ]
        checker = DNSPropagationChecker(custom_servers=unreachable_servers)
        
        # Query should complete without exception
        result = await checker.check_propagation("google.com", "A")
        
        # Verify all custom unreachable servers failed (default + custom)
        unreachable_count = sum(1 for r in result.query_results 
                               if r.server.ip in ["192.0.2.1", "192.0.2.2", "192.0.2.3"])
        assert unreachable_count == 3, "Expected 3 unreachable servers"
        
        for query_result in result.query_results:
            if query_result.server.ip in ["192.0.2.1", "192.0.2.2", "192.0.2.3"]:
                assert query_result.status in ('timeout', 'unreachable')
                assert len(query_result.values) == 0
        
        # Verify propagation rate is 0 (no responsive servers)
        assert result.responsive_count == 0
        assert result.propagation_rate == 0.0
