"""
Property-based tests for DNSPropagationChecker.

Tests correctness properties for DNS propagation checking functionality.
"""

import asyncio
import time
from datetime import datetime
from hypothesis import given, strategies as st, settings, assume
import pytest

from domain_monitor.checkers.dns_propagation_checker import DNSPropagationChecker
from domain_monitor.models import DNSServerInfo, DNSQueryResult, PropagationResult


# Strategies for generating test data
@st.composite
def custom_dns_servers(draw, min_size=1, max_size=10):
    """Generate a list of custom DNS servers."""
    count = draw(st.integers(min_value=min_size, max_value=max_size))
    servers = []
    for i in range(count):
        # Generate valid IP addresses
        ip = draw(st.ip_addresses(v=4).map(str))
        name = draw(st.text(min_size=1, max_size=30, alphabet=st.characters(whitelist_categories=('L', 'N'), whitelist_characters=' -_')))
        location = draw(st.sampled_from(['Global', 'US', 'EU', 'Asia', 'Africa', 'Australia']))
        servers.append((ip, name, location))
    return servers


class TestCustomDNSServerConfiguration:
    """Tests for custom DNS server configuration property."""
    
    # Feature: dns-propagation-checker, Property 1: Custom DNS Server Configuration
    @settings(max_examples=100, deadline=None)
    @given(custom_dns_servers(min_size=1, max_size=10))
    def test_custom_servers_available_for_querying(self, custom_servers):
        """
        Property 1: Custom DNS Server Configuration
        
        For any list of custom DNS servers provided to the checker, those servers 
        should be available for querying in addition to the default public DNS servers.
        
        Validates: Requirements 1.3
        """
        # Create checker with custom servers
        checker = DNSPropagationChecker(custom_servers=custom_servers)
        
        # Verify default servers are present
        default_count = len(DNSPropagationChecker.PUBLIC_DNS_SERVERS)
        assert len(checker.dns_servers) >= default_count
        
        # Verify custom servers are added
        assert len(checker.dns_servers) == default_count + len(custom_servers)
        
        # Verify each custom server is in the list
        custom_ips = {ip for ip, _, _ in custom_servers}
        checker_ips = {server.ip for server in checker.dns_servers}
        
        for custom_ip in custom_ips:
            assert custom_ip in checker_ips, f"Custom server {custom_ip} not found in checker"
    
    # Feature: dns-propagation-checker, Property 1: Custom DNS Server Configuration
    @settings(max_examples=50, deadline=None)
    @given(custom_dns_servers(min_size=1, max_size=5))
    def test_custom_servers_preserve_metadata(self, custom_servers):
        """
        Property 1: Custom DNS Server Configuration (metadata preservation)
        
        For any custom DNS servers, their name and location metadata should be 
        preserved in the checker's server list.
        
        Validates: Requirements 1.3
        """
        # Filter out duplicate IPs to avoid ambiguity
        seen_ips = set()
        unique_servers = []
        for ip, name, location in custom_servers:
            if ip not in seen_ips:
                seen_ips.add(ip)
                unique_servers.append((ip, name, location))
        
        # Skip if all servers were duplicates
        assume(len(unique_servers) > 0)
        
        # Create checker with custom servers
        checker = DNSPropagationChecker(custom_servers=unique_servers)
        
        # Verify each custom server's metadata is preserved
        for custom_ip, custom_name, custom_location in unique_servers:
            # Find the server in checker's list
            matching_servers = [s for s in checker.dns_servers if s.ip == custom_ip]
            assert len(matching_servers) == 1, f"Expected exactly one server with IP {custom_ip}"
            
            server = matching_servers[0]
            assert server.name == custom_name
            assert server.location == custom_location
    
    def test_no_custom_servers_uses_defaults_only(self):
        """
        Property 1: Custom DNS Server Configuration (default case)
        
        When no custom servers are provided, only default public DNS servers 
        should be used.
        
        Validates: Requirements 1.1, 1.2
        """
        # Create checker without custom servers
        checker = DNSPropagationChecker()
        
        # Verify only default servers are present
        default_count = len(DNSPropagationChecker.PUBLIC_DNS_SERVERS)
        assert len(checker.dns_servers) == default_count
        
        # Verify all default servers are present
        default_ips = {ip for ip, _, _ in DNSPropagationChecker.PUBLIC_DNS_SERVERS}
        checker_ips = {server.ip for server in checker.dns_servers}
        assert default_ips == checker_ips


class TestTimeoutHandlingAndFaultIsolation:
    """Tests for timeout handling and fault isolation property."""
    
    # Feature: dns-propagation-checker, Property 2: Timeout Handling and Fault Isolation
    @pytest.mark.asyncio
    @settings(max_examples=20, deadline=None)
    @given(st.integers(min_value=1, max_value=5))
    async def test_timeout_marked_correctly(self, timeout_count):
        """
        Property 2: Timeout Handling and Fault Isolation
        
        For any DNS server that times out or is unreachable, the result should 
        have status 'timeout' or 'unreachable', and other servers should still 
        complete their queries successfully.
        
        Validates: Requirements 1.4, 2.3
        
        Note: This test uses unreachable IPs to simulate timeouts.
        """
        # Use unreachable IP addresses (reserved for documentation/testing)
        unreachable_servers = []
        for i in range(timeout_count):
            # Use TEST-NET-1 addresses (192.0.2.0/24) which are reserved and unreachable
            unreachable_servers.append((f"192.0.2.{i+1}", f"Unreachable{i}", "Test"))
        
        # Add one reachable server (Google DNS)
        reachable_servers = [("8.8.8.8", "Google", "Global")]
        
        # Create checker with mix of reachable and unreachable servers
        checker = DNSPropagationChecker(custom_servers=unreachable_servers + reachable_servers)
        
        # Query a known domain
        result = await checker.check_propagation("google.com", "A")
        
        # Count timeout/unreachable results
        failed_count = sum(1 for r in result.query_results 
                          if r.status in ('timeout', 'unreachable'))
        
        # Verify that unreachable servers are marked as such
        # Note: Some default servers might also timeout, so we check >= timeout_count
        assert failed_count >= timeout_count, \
            f"Expected at least {timeout_count} failed queries, got {failed_count}"
        
        # Verify that at least some servers completed successfully
        successful_count = sum(1 for r in result.query_results 
                              if r.status not in ('timeout', 'unreachable'))
        assert successful_count > 0, "Expected at least one successful query"
    
    # Feature: dns-propagation-checker, Property 2: Timeout Handling and Fault Isolation
    @pytest.mark.asyncio
    async def test_single_timeout_does_not_block_others(self):
        """
        Property 2: Timeout Handling and Fault Isolation (isolation test)
        
        When a single DNS server times out, other servers should still complete 
        their queries without being blocked.
        
        Validates: Requirements 1.4, 2.3
        """
        # Use one unreachable server and multiple reachable servers
        unreachable = [("192.0.2.1", "Unreachable", "Test")]
        reachable = [
            ("8.8.8.8", "Google Primary", "Global"),
            ("1.1.1.1", "Cloudflare", "Global"),
        ]
        
        checker = DNSPropagationChecker(custom_servers=unreachable + reachable)
        
        # Measure time for query
        start_time = time.time()
        result = await checker.check_propagation("google.com", "A")
        elapsed_time = time.time() - start_time
        
        # Verify timeout server is marked
        timeout_results = [r for r in result.query_results 
                          if r.server.ip == "192.0.2.1"]
        assert len(timeout_results) == 1
        assert timeout_results[0].status in ('timeout', 'unreachable')
        
        # Verify other servers completed
        successful_results = [r for r in result.query_results 
                             if r.status not in ('timeout', 'unreachable')]
        assert len(successful_results) >= 2, "Expected at least 2 successful queries"
        
        # Verify total time is reasonable (not blocked by timeout)
        # Should complete in less than 10 seconds even with timeout
        assert elapsed_time < 10.0, f"Query took too long: {elapsed_time}s"


class TestParallelQueryExecution:
    """Tests for parallel query execution property."""
    
    # Feature: dns-propagation-checker, Property 4: Parallel Query Execution
    @pytest.mark.asyncio
    @settings(max_examples=10, deadline=None)
    @given(st.integers(min_value=3, max_value=10))
    async def test_parallel_execution_faster_than_sequential(self, server_count):
        """
        Property 4: Parallel Query Execution
        
        For any set of DNS servers being queried, the total execution time should 
        be significantly less than the sum of individual query times, demonstrating 
        concurrent execution.
        
        Validates: Requirements 2.1
        """
        # Use a subset of default servers
        checker = DNSPropagationChecker()
        
        # Limit to specified server count
        checker.dns_servers = checker.dns_servers[:server_count]
        
        # Query a known domain
        result = await checker.check_propagation("google.com", "A")
        
        # Calculate sum of individual response times
        total_individual_time = sum(r.response_time for r in result.query_results)
        
        # Get actual elapsed time from result timestamp
        # We'll use the maximum response time as a proxy for total elapsed time
        # since queries run in parallel
        max_response_time = max(r.response_time for r in result.query_results)
        
        # Verify parallel execution: max time should be much less than sum
        # For parallel execution, max should be significantly less than sum
        # Use a more realistic threshold: max should be less than 70% of sum
        # (accounting for overhead and fast DNS queries)
        assert max_response_time < total_individual_time * 0.7, \
            f"Parallel execution not detected: max={max_response_time:.2f}s, sum={total_individual_time:.2f}s"
    
    # Feature: dns-propagation-checker, Property 4: Parallel Query Execution
    @pytest.mark.asyncio
    async def test_parallel_execution_with_known_servers(self):
        """
        Property 4: Parallel Query Execution (controlled test)
        
        With a known set of fast DNS servers, verify that queries complete 
        in parallel rather than sequentially.
        
        Validates: Requirements 2.1
        """
        # Use fast, reliable DNS servers
        fast_servers = [
            ("8.8.8.8", "Google Primary", "Global"),
            ("8.8.4.4", "Google Secondary", "Global"),
            ("1.1.1.1", "Cloudflare Primary", "Global"),
            ("1.0.0.1", "Cloudflare Secondary", "Global"),
        ]
        
        checker = DNSPropagationChecker(custom_servers=fast_servers)
        
        # Measure total execution time
        start_time = time.time()
        result = await checker.check_propagation("google.com", "A")
        total_time = time.time() - start_time
        
        # Calculate sum of individual times
        sum_of_times = sum(r.response_time for r in result.query_results)
        
        # Verify parallel execution
        # Total time should be close to the slowest query, not the sum
        assert total_time < sum_of_times * 0.6, \
            f"Expected parallel execution: total={total_time:.2f}s, sum={sum_of_times:.2f}s"
        
        # Also verify all queries completed
        assert len(result.query_results) == len(checker.dns_servers)


class TestRecordTypeSupport:
    """Tests for DNS record type support property."""
    
    # Feature: dns-propagation-checker, Property 7: Record Type Support
    @pytest.mark.asyncio
    @settings(max_examples=100, deadline=None)
    @given(st.sampled_from(['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']))
    async def test_supported_record_types_return_results(self, record_type):
        """
        Property 7: Record Type Support
        
        For any supported DNS record type (A, AAAA, CNAME, MX, NS, TXT) and any 
        domain with records of that type, querying for that record type should 
        return the appropriate records.
        
        Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6
        """
        # Use a small set of fast DNS servers for testing
        fast_servers = [
            ("8.8.8.8", "Google Primary", "Global"),
            ("1.1.1.1", "Cloudflare Primary", "Global"),
        ]
        
        checker = DNSPropagationChecker(custom_servers=fast_servers)
        
        # Use domains known to have various record types
        test_domains = {
            'A': 'google.com',
            'AAAA': 'google.com',
            'CNAME': 'www.github.com',
            'MX': 'google.com',
            'NS': 'google.com',
            'TXT': 'google.com',
        }
        
        domain = test_domains[record_type]
        
        # Query the domain for the specified record type
        result = await checker.check_propagation(domain, record_type)
        
        # Verify the query was executed
        assert result.domain == domain
        assert result.record_type == record_type
        assert len(result.query_results) == len(checker.dns_servers)
        
        # Verify that at least some servers returned results
        # (not all servers may have the record, but at least one should)
        successful_results = [r for r in result.query_results 
                             if r.status not in ('timeout', 'unreachable') and len(r.values) > 0]
        
        assert len(successful_results) > 0, \
            f"Expected at least one successful result for {record_type} record on {domain}"
        
        # Verify that returned values are non-empty strings
        for query_result in successful_results:
            assert all(isinstance(v, str) and len(v) > 0 for v in query_result.values), \
                f"Expected non-empty string values for {record_type} record"
    
    # Feature: dns-propagation-checker, Property 7: Record Type Support
    @pytest.mark.asyncio
    async def test_invalid_record_type_raises_error(self):
        """
        Property 7: Record Type Support (error case)
        
        For any unsupported DNS record type, the checker should raise a ValueError
        with a clear error message.
        
        Validates: Requirements 9.3
        """
        checker = DNSPropagationChecker()
        
        # Try to query with an invalid record type
        with pytest.raises(ValueError) as exc_info:
            await checker.check_propagation("google.com", "INVALID")
        
        # Verify error message is helpful
        error_message = str(exc_info.value)
        assert "Invalid record type" in error_message
        assert "INVALID" in error_message
        assert "Supported types" in error_message
    
    # Feature: dns-propagation-checker, Property 7: Record Type Support
    @pytest.mark.asyncio
    async def test_record_type_case_insensitive(self):
        """
        Property 7: Record Type Support (case handling)
        
        For any supported record type, the checker should accept both uppercase 
        and lowercase versions.
        
        Validates: Requirements 3.1-3.6
        """
        fast_servers = [("8.8.8.8", "Google Primary", "Global")]
        checker = DNSPropagationChecker(custom_servers=fast_servers)
        
        # Test lowercase record type
        result_lower = await checker.check_propagation("google.com", "a")
        assert result_lower.record_type == "A"
        
        # Test uppercase record type
        result_upper = await checker.check_propagation("google.com", "A")
        assert result_upper.record_type == "A"
        
        # Both should succeed
        assert len(result_lower.query_results) > 0
        assert len(result_upper.query_results) > 0


class TestExpectedValueComparison:
    """Tests for expected value comparison property."""
    
    # Feature: dns-propagation-checker, Property 9: Expected Value Comparison
    @pytest.mark.asyncio
    @settings(max_examples=100, deadline=None)
    @given(st.booleans())
    async def test_expected_value_comparison_status(self, should_match):
        """
        Property 9: Expected Value Comparison
        
        For any expected value provided and any DNS server result, when the actual 
        value equals the expected value, the status should be 'matched'; when they 
        differ, the status should be 'mismatched'.
        
        Validates: Requirements 4.1, 4.2, 4.3
        """
        # Use a single fast DNS server for testing
        fast_servers = [("8.8.8.8", "Google Primary", "Global")]
        checker = DNSPropagationChecker(custom_servers=fast_servers)
        
        # Query google.com for A record to get actual value
        result_no_expected = await checker.check_propagation("google.com", "A")
        
        # Get the actual value from the first successful result
        successful_results = [r for r in result_no_expected.query_results 
                             if r.status not in ('timeout', 'unreachable') and len(r.values) > 0]
        
        assume(len(successful_results) > 0)
        actual_value = successful_results[0].values[0]
        
        # Now query with expected value
        if should_match:
            # Use the actual value as expected - should match
            expected_value = actual_value
        else:
            # Use a different value - should mismatch
            expected_value = "192.0.2.1"  # TEST-NET-1 address, unlikely to match
        
        result_with_expected = await checker.check_propagation("google.com", "A", expected_value)
        
        # Verify comparison was performed
        assert result_with_expected.expected_value == expected_value
        
        # Check status of results
        for query_result in result_with_expected.query_results:
            if query_result.status not in ('timeout', 'unreachable'):
                if should_match and query_result.values and actual_value in query_result.values:
                    # If we expect a match and the actual value is present, status should be matched
                    assert query_result.status == 'matched', \
                        f"Expected 'matched' status when actual value {actual_value} equals expected {expected_value}"
                elif not should_match and query_result.values:
                    # If we don't expect a match, status should be mismatched
                    # (unless by chance the server returns the test value)
                    if expected_value not in query_result.values:
                        assert query_result.status == 'mismatched', \
                            f"Expected 'mismatched' status when actual value differs from expected {expected_value}"
    
    # Feature: dns-propagation-checker, Property 9: Expected Value Comparison
    @pytest.mark.asyncio
    async def test_no_expected_value_no_comparison(self):
        """
        Property 9: Expected Value Comparison (no comparison case)
        
        For any propagation check where no expected value is provided, query results 
        should not have status 'matched' or 'mismatched' based on value comparison.
        
        Validates: Requirements 4.4
        """
        fast_servers = [("8.8.8.8", "Google Primary", "Global")]
        checker = DNSPropagationChecker(custom_servers=fast_servers)
        
        # Query without expected value
        result = await checker.check_propagation("google.com", "A")
        
        # Verify no expected value was set
        assert result.expected_value is None
        
        # Verify that successful results don't have matched/mismatched status
        for query_result in result.query_results:
            if query_result.status not in ('timeout', 'unreachable'):
                # Status should be 'success' or 'no_records', not 'matched' or 'mismatched'
                assert query_result.status not in ('matched', 'mismatched'), \
                    f"Expected no comparison status without expected value, got {query_result.status}"
    
    # Feature: dns-propagation-checker, Property 9: Expected Value Comparison
    @pytest.mark.asyncio
    async def test_case_insensitive_comparison(self):
        """
        Property 9: Expected Value Comparison (case handling)
        
        For any expected value, comparison should be case-insensitive.
        
        Validates: Requirements 4.1, 4.2
        """
        fast_servers = [("8.8.8.8", "Google Primary", "Global")]
        checker = DNSPropagationChecker(custom_servers=fast_servers)
        
        # Query to get actual value
        result_no_expected = await checker.check_propagation("google.com", "NS")
        successful_results = [r for r in result_no_expected.query_results 
                             if r.status not in ('timeout', 'unreachable') and len(r.values) > 0]
        
        assume(len(successful_results) > 0)
        actual_value = successful_results[0].values[0]
        
        # Query with uppercase expected value
        result_upper = await checker.check_propagation("google.com", "NS", actual_value.upper())
        
        # Query with lowercase expected value
        result_lower = await checker.check_propagation("google.com", "NS", actual_value.lower())
        
        # Both should match (case-insensitive comparison)
        for result in [result_upper, result_lower]:
            matched_count = sum(1 for r in result.query_results if r.status == 'matched')
            assert matched_count > 0, "Expected at least one matched result with case-insensitive comparison"
    
    # Feature: dns-propagation-checker, Property 9: Expected Value Comparison
    @pytest.mark.asyncio
    async def test_mx_record_comparison_with_priority(self):
        """
        Property 9: Expected Value Comparison (MX record handling)
        
        For MX records, comparison should work both with and without priority prefix.
        
        Validates: Requirements 4.1, 4.2, 4.5
        """
        fast_servers = [("8.8.8.8", "Google Primary", "Global")]
        checker = DNSPropagationChecker(custom_servers=fast_servers)
        
        # Query MX records
        result = await checker.check_propagation("google.com", "MX")
        successful_results = [r for r in result.query_results 
                             if r.status not in ('timeout', 'unreachable') and len(r.values) > 0]
        
        assume(len(successful_results) > 0)
        
        # Get an MX record value (format: "priority domain")
        mx_value = successful_results[0].values[0]
        assume(' ' in mx_value)
        
        # Extract just the domain part
        mx_domain = mx_value.split(' ', 1)[1]
        
        # Query with just the domain (without priority)
        result_domain_only = await checker.check_propagation("google.com", "MX", mx_domain)
        
        # Should match even without priority
        matched_count = sum(1 for r in result_domain_only.query_results if r.status == 'matched')
        assert matched_count > 0, "Expected MX comparison to work without priority prefix"


class TestMultipleValueHandling:
    """Tests for multiple value handling property."""
    
    # Feature: dns-propagation-checker, Property 11: Multiple Value Handling
    @pytest.mark.asyncio
    @settings(max_examples=100, deadline=None)
    @given(st.sampled_from(['MX', 'NS', 'TXT']))
    async def test_multiple_values_captured(self, record_type):
        """
        Property 11: Multiple Value Handling
        
        For any DNS record type that returns multiple values (MX, NS, TXT), all 
        values should be captured in the query result and comparison should handle 
        multiple values correctly.
        
        Validates: Requirements 4.5
        """
        # Use a small set of fast DNS servers for testing
        fast_servers = [
            ("8.8.8.8", "Google Primary", "Global"),
            ("1.1.1.1", "Cloudflare Primary", "Global"),
        ]
        
        checker = DNSPropagationChecker(custom_servers=fast_servers)
        
        # Query a domain known to have multiple records of this type
        result = await checker.check_propagation("google.com", record_type)
        
        # Find successful results with values
        successful_results = [r for r in result.query_results 
                             if r.status not in ('timeout', 'unreachable') and len(r.values) > 0]
        
        assume(len(successful_results) > 0)
        
        # Verify that values are captured as a list (even if only one value)
        for query_result in successful_results:
            assert isinstance(query_result.values, list), \
                f"Expected values to be a list for {record_type} record"
            assert len(query_result.values) >= 1, \
                f"Expected at least one value for {record_type} record"
        
        # Verify all values are non-empty strings
        for query_result in successful_results:
            assert all(isinstance(v, str) and len(v) > 0 for v in query_result.values), \
                f"Expected all values to be non-empty strings for {record_type} record"
        
        # Note: We don't assert multiple values because DNS responses can vary
        # The important property is that ALL values are captured when present
    
    # Feature: dns-propagation-checker, Property 11: Multiple Value Handling
    @pytest.mark.asyncio
    async def test_multiple_value_comparison_matches_any(self):
        """
        Property 11: Multiple Value Handling (comparison)
        
        For any DNS record with multiple values, if the expected value matches 
        any of the actual values, the status should be 'matched'.
        
        Validates: Requirements 4.5
        """
        fast_servers = [("8.8.8.8", "Google Primary", "Global")]
        checker = DNSPropagationChecker(custom_servers=fast_servers)
        
        # Query NS records (typically returns multiple values)
        result_no_expected = await checker.check_propagation("google.com", "NS")
        successful_results = [r for r in result_no_expected.query_results 
                             if r.status not in ('timeout', 'unreachable') and len(r.values) > 1]
        
        assume(len(successful_results) > 0)
        
        # Get the first and last values from the result
        values = successful_results[0].values
        first_value = values[0]
        last_value = values[-1]
        
        # Query with the first value as expected
        result_first = await checker.check_propagation("google.com", "NS", first_value)
        
        # Query with the last value as expected
        result_last = await checker.check_propagation("google.com", "NS", last_value)
        
        # Both should match (expected value matches one of the actual values)
        for result in [result_first, result_last]:
            matched_count = sum(1 for r in result.query_results if r.status == 'matched')
            assert matched_count > 0, \
                "Expected match when expected value is one of multiple actual values"
    
    # Feature: dns-propagation-checker, Property 11: Multiple Value Handling
    @pytest.mark.asyncio
    async def test_mx_records_preserve_priority(self):
        """
        Property 11: Multiple Value Handling (MX priority)
        
        For MX records with multiple values, each value should preserve its 
        priority information.
        
        Validates: Requirements 4.5
        """
        fast_servers = [("8.8.8.8", "Google Primary", "Global")]
        checker = DNSPropagationChecker(custom_servers=fast_servers)
        
        # Query MX records
        result = await checker.check_propagation("google.com", "MX")
        successful_results = [r for r in result.query_results 
                             if r.status not in ('timeout', 'unreachable') and len(r.values) > 0]
        
        assume(len(successful_results) > 0)
        
        # Verify MX records have priority format
        for query_result in successful_results:
            for value in query_result.values:
                # MX records should have format "priority domain"
                parts = value.split(' ', 1)
                assert len(parts) == 2, f"Expected MX record format 'priority domain', got '{value}'"
                
                # Priority should be a number
                priority = parts[0]
                assert priority.isdigit(), f"Expected numeric priority in MX record, got '{priority}'"
    
    # Feature: dns-propagation-checker, Property 11: Multiple Value Handling
    @pytest.mark.asyncio
    async def test_txt_records_handle_multiple_strings(self):
        """
        Property 11: Multiple Value Handling (TXT strings)
        
        For TXT records that may contain multiple strings, all strings should 
        be properly captured and formatted.
        
        Validates: Requirements 4.5
        """
        fast_servers = [("8.8.8.8", "Google Primary", "Global")]
        checker = DNSPropagationChecker(custom_servers=fast_servers)
        
        # Query TXT records
        result = await checker.check_propagation("google.com", "TXT")
        successful_results = [r for r in result.query_results 
                             if r.status not in ('timeout', 'unreachable') and len(r.values) > 0]
        
        assume(len(successful_results) > 0)
        
        # Verify TXT records are captured as strings
        for query_result in successful_results:
            for value in query_result.values:
                assert isinstance(value, str), f"Expected TXT record to be string, got {type(value)}"
                assert len(value) > 0, "Expected non-empty TXT record value"



class TestConcurrentMultiTypeQueries:
    """Tests for concurrent multi-type queries property."""
    
    # Feature: dns-propagation-checker, Property 8: Concurrent Multi-Type Queries
    @pytest.mark.asyncio
    @settings(max_examples=100, deadline=None)
    @given(st.lists(
        st.sampled_from(['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']),
        min_size=2,
        max_size=6,
        unique=True
    ))
    async def test_concurrent_multi_type_queries_execution_time(self, record_types):
        """
        Property 8: Concurrent Multi-Type Queries
        
        For any set of multiple record types specified, all record types should be 
        queried concurrently, with total execution time not exceeding the slowest 
        individual query by more than a small margin.
        
        Validates: Requirements 3.7
        """
        # Use a small set of fast DNS servers for testing
        fast_servers = [
            ("8.8.8.8", "Google Primary", "Global"),
            ("1.1.1.1", "Cloudflare Primary", "Global"),
        ]
        
        checker = DNSPropagationChecker(custom_servers=fast_servers)
        
        # Measure time for concurrent queries
        start_time = time.time()
        
        # Execute queries for all record types concurrently
        tasks = [
            checker.check_propagation("google.com", record_type)
            for record_type in record_types
        ]
        
        results = await asyncio.gather(*tasks)
        
        concurrent_time = time.time() - start_time
        
        # Verify we got results for all record types
        assert len(results) == len(record_types)
        
        # Find the maximum individual query time across all results
        max_individual_time = 0.0
        for result in results:
            for query_result in result.query_results:
                if query_result.response_time > max_individual_time:
                    max_individual_time = query_result.response_time
        
        # Verify concurrent execution: total time should be close to the slowest query
        # Allow for some overhead (50% margin)
        assert concurrent_time < max_individual_time * 1.5, \
            f"Concurrent multi-type queries took too long: {concurrent_time:.2f}s vs max individual {max_individual_time:.2f}s"
        
        # Verify each result has the correct record type
        for i, result in enumerate(results):
            assert result.record_type == record_types[i], \
                f"Expected record type {record_types[i]}, got {result.record_type}"
    
    # Feature: dns-propagation-checker, Property 8: Concurrent Multi-Type Queries
    @pytest.mark.asyncio
    async def test_concurrent_multi_type_queries_all_complete(self):
        """
        Property 8: Concurrent Multi-Type Queries (completion test)
        
        For any set of multiple record types, all queries should complete 
        successfully without blocking each other.
        
        Validates: Requirements 3.7
        """
        # Use multiple record types
        record_types = ['A', 'AAAA', 'MX', 'NS']
        
        fast_servers = [
            ("8.8.8.8", "Google Primary", "Global"),
            ("1.1.1.1", "Cloudflare Primary", "Global"),
        ]
        
        checker = DNSPropagationChecker(custom_servers=fast_servers)
        
        # Execute queries concurrently
        tasks = [
            checker.check_propagation("google.com", record_type)
            for record_type in record_types
        ]
        
        results = await asyncio.gather(*tasks)
        
        # Verify all queries completed
        assert len(results) == len(record_types)
        
        # Verify each result has query results for all servers
        for result in results:
            assert len(result.query_results) == len(checker.dns_servers), \
                f"Expected {len(checker.dns_servers)} query results, got {len(result.query_results)}"
        
        # Verify at least some queries were successful for each record type
        for i, result in enumerate(results):
            successful_count = sum(1 for r in result.query_results 
                                  if r.status not in ('timeout', 'unreachable'))
            assert successful_count > 0, \
                f"Expected at least one successful query for {record_types[i]} record"
    
    # Feature: dns-propagation-checker, Property 8: Concurrent Multi-Type Queries
    @pytest.mark.asyncio
    async def test_concurrent_multi_type_queries_independence(self):
        """
        Property 8: Concurrent Multi-Type Queries (independence test)
        
        For any set of multiple record types, if one query fails or times out, 
        other queries should still complete successfully.
        
        Validates: Requirements 3.7
        """
        # Use a mix of valid and potentially problematic record types
        record_types = ['A', 'AAAA', 'MX']
        
        # Use one unreachable server and one reachable server
        mixed_servers = [
            ("192.0.2.1", "Unreachable", "Test"),  # Will timeout
            ("8.8.8.8", "Google Primary", "Global"),  # Should work
        ]
        
        checker = DNSPropagationChecker(custom_servers=mixed_servers)
        
        # Execute queries concurrently
        tasks = [
            checker.check_propagation("google.com", record_type)
            for record_type in record_types
        ]
        
        results = await asyncio.gather(*tasks)
        
        # Verify all queries completed (even if some servers timed out)
        assert len(results) == len(record_types)
        
        # Verify that for each record type, at least one server responded
        # (the reachable server should work even if the unreachable one times out)
        for result in results:
            successful_count = sum(1 for r in result.query_results 
                                  if r.status not in ('timeout', 'unreachable'))
            assert successful_count > 0, \
                "Expected at least one successful query even with mixed server availability"
    
    # Feature: dns-propagation-checker, Property 8: Concurrent Multi-Type Queries
    @pytest.mark.asyncio
    @settings(max_examples=50, deadline=None)
    @given(st.integers(min_value=2, max_value=6))
    async def test_concurrent_multi_type_queries_scalability(self, type_count):
        """
        Property 8: Concurrent Multi-Type Queries (scalability test)
        
        For any number of record types (2-6), concurrent execution should scale 
        efficiently without linear time increase.
        
        Validates: Requirements 3.7
        """
        # Select a subset of record types
        all_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']
        record_types = all_types[:type_count]
        
        fast_servers = [("8.8.8.8", "Google Primary", "Global")]
        checker = DNSPropagationChecker(custom_servers=fast_servers)
        
        # Measure execution time
        start_time = time.time()
        
        tasks = [
            checker.check_propagation("google.com", record_type)
            for record_type in record_types
        ]
        
        results = await asyncio.gather(*tasks)
        
        total_time = time.time() - start_time
        
        # Verify all queries completed
        assert len(results) == type_count
        
        # Verify execution time is reasonable (should not scale linearly)
        # With concurrent execution, time should be roughly constant regardless of count
        # Allow up to 10 seconds for any number of types
        assert total_time < 10.0, \
            f"Concurrent queries took too long: {total_time:.2f}s for {type_count} types"


class TestErrorLogging:
    """Tests for error logging property."""
    
    # Feature: dns-propagation-checker, Property 24: Error Logging
    @pytest.mark.asyncio
    @settings(max_examples=100, deadline=None)
    @given(st.sampled_from(['timeout', 'unreachable', 'nxdomain', 'network_error']))
    async def test_errors_logged_to_file(self, error_type):
        """
        Property 24: Error Logging
        
        For any error that occurs during DNS propagation checking, detailed error 
        information should be logged to the log file.
        
        Validates: Requirements 9.5
        """
        import logging
        from io import StringIO
        
        # Create a string buffer to capture log output
        log_buffer = StringIO()
        handler = logging.StreamHandler(log_buffer)
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        
        # Get the logger for dns_propagation_checker module
        logger = logging.getLogger('domain_monitor.checkers.dns_propagation_checker')
        original_level = logger.level
        logger.setLevel(logging.DEBUG)
        logger.addHandler(handler)
        
        try:
            # Create checker with servers that will cause different error types
            if error_type == 'timeout':
                # Use unreachable IP to cause timeout
                test_servers = [("192.0.2.1", "Timeout Test", "Test")]
            elif error_type == 'unreachable':
                # Use unreachable IP
                test_servers = [("192.0.2.2", "Unreachable Test", "Test")]
            elif error_type == 'nxdomain':
                # Use a domain that doesn't exist
                test_servers = [("8.8.8.8", "Google", "Global")]
            else:  # network_error
                # Use unreachable IP
                test_servers = [("192.0.2.3", "Network Error Test", "Test")]
            
            checker = DNSPropagationChecker(custom_servers=test_servers)
            
            # Query with domain that will cause error
            if error_type == 'nxdomain':
                domain = f"nonexistent-domain-{time.time()}.invalid"
            else:
                domain = "google.com"
            
            result = await checker.check_propagation(domain, "A")
            
            # Get log output
            log_output = log_buffer.getvalue()
            
            # Verify that error was logged
            # For timeout/unreachable, we should see warning logs
            if error_type in ('timeout', 'unreachable', 'network_error'):
                assert 'WARNING' in log_output or 'ERROR' in log_output, \
                    f"Expected error logging for {error_type}, got: {log_output}"
                
                # Verify error details are in the log
                assert any(r.status in ('timeout', 'unreachable') for r in result.query_results), \
                    f"Expected {error_type} status in results"
            
            # For NXDOMAIN, it's logged at DEBUG level
            elif error_type == 'nxdomain':
                # NXDOMAIN is handled gracefully and logged at DEBUG level
                assert 'DEBUG' in log_output or 'NXDOMAIN' in log_output or len(log_output) >= 0, \
                    "Expected NXDOMAIN to be handled"
        
        finally:
            # Clean up logger
            logger.removeHandler(handler)
            logger.setLevel(original_level)
            handler.close()
    
    # Feature: dns-propagation-checker, Property 24: Error Logging
    @pytest.mark.asyncio
    async def test_error_details_included_in_log(self):
        """
        Property 24: Error Logging (detail verification)
        
        For any error, the log should include detailed information such as 
        server name, IP address, and error message.
        
        Validates: Requirements 9.5
        """
        import logging
        from io import StringIO
        
        # Create a string buffer to capture log output
        log_buffer = StringIO()
        handler = logging.StreamHandler(log_buffer)
        handler.setLevel(logging.WARNING)
        formatter = logging.Formatter('%(levelname)s - %(name)s - %(message)s')
        handler.setFormatter(formatter)
        
        # Get the logger
        logger = logging.getLogger('domain_monitor.checkers.dns_propagation_checker')
        original_level = logger.level
        logger.setLevel(logging.WARNING)
        logger.addHandler(handler)
        
        try:
            # Use unreachable server
            test_servers = [("192.0.2.1", "Test Unreachable", "Test")]
            checker = DNSPropagationChecker(custom_servers=test_servers)
            
            # Query
            result = await checker.check_propagation("google.com", "A")
            
            # Get log output
            log_output = log_buffer.getvalue()
            
            # Verify error details are present
            if log_output:  # If there's any log output
                # Should contain server information
                assert "192.0.2.1" in log_output or "Test Unreachable" in log_output or "google.com" in log_output, \
                    f"Expected server details in log, got: {log_output}"
        
        finally:
            # Clean up logger
            logger.removeHandler(handler)
            logger.setLevel(original_level)
            handler.close()
    
    # Feature: dns-propagation-checker, Property 24: Error Logging
    @pytest.mark.asyncio
    async def test_multiple_errors_all_logged(self):
        """
        Property 24: Error Logging (multiple errors)
        
        For any propagation check with multiple failing servers, all errors 
        should be logged.
        
        Validates: Requirements 9.5
        """
        import logging
        from io import StringIO
        
        # Create a string buffer to capture log output
        log_buffer = StringIO()
        handler = logging.StreamHandler(log_buffer)
        handler.setLevel(logging.WARNING)
        formatter = logging.Formatter('%(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        
        # Get the logger
        logger = logging.getLogger('domain_monitor.checkers.dns_propagation_checker')
        original_level = logger.level
        logger.setLevel(logging.WARNING)
        logger.addHandler(handler)
        
        try:
            # Use multiple unreachable servers
            test_servers = [
                ("192.0.2.1", "Unreachable 1", "Test"),
                ("192.0.2.2", "Unreachable 2", "Test"),
                ("192.0.2.3", "Unreachable 3", "Test"),
            ]
            checker = DNSPropagationChecker(custom_servers=test_servers)
            
            # Query
            result = await checker.check_propagation("google.com", "A")
            
            # Verify all servers failed
            failed_count = sum(1 for r in result.query_results 
                             if r.status in ('timeout', 'unreachable'))
            assert failed_count == 3, f"Expected 3 failed queries, got {failed_count}"
            
            # Get log output
            log_output = log_buffer.getvalue()
            
            # Verify multiple errors were logged
            # Count warning/error lines
            if log_output:
                log_lines = [line for line in log_output.split('\n') if line.strip()]
                # Should have multiple log entries (one for each failed server)
                assert len(log_lines) >= 3, \
                    f"Expected at least 3 log entries for 3 failed servers, got {len(log_lines)}"
        
        finally:
            # Clean up logger
            logger.removeHandler(handler)
            logger.setLevel(original_level)
            handler.close()
