"""
Property-based tests for DNS propagation data models.

Tests correctness properties for PropagationResult calculations.
"""

from datetime import datetime
from hypothesis import given, strategies as st, settings
import pytest

from domain_monitor.models import DNSServerInfo, DNSQueryResult, PropagationResult


# Strategies for generating test data
@st.composite
def dns_server_info(draw):
    """Generate a DNSServerInfo instance."""
    ip = draw(st.ip_addresses(v=4).map(str))
    name = draw(st.text(min_size=1, max_size=50, alphabet=st.characters(blacklist_categories=('Cs',))))
    location = draw(st.text(min_size=1, max_size=30, alphabet=st.characters(blacklist_categories=('Cs',))))
    return DNSServerInfo(ip=ip, name=name, location=location)


@st.composite
def dns_query_result(draw, status=None):
    """Generate a DNSQueryResult instance."""
    server = draw(dns_server_info())
    if status is None:
        status_val = draw(st.sampled_from(['matched', 'mismatched', 'unreachable', 'timeout']))
    else:
        status_val = status
    
    # Generate values based on status
    if status_val in ('unreachable', 'timeout'):
        values = []
        error = draw(st.text(min_size=1, max_size=100))
    else:
        values = draw(st.lists(st.text(min_size=1, max_size=50), min_size=1, max_size=5))
        error = None
    
    response_time = draw(st.floats(min_value=0.001, max_value=10.0))
    
    return DNSQueryResult(
        server=server,
        status=status_val,
        values=values,
        response_time=response_time,
        error=error
    )


@st.composite
def propagation_result(draw, min_results=1, max_results=20):
    """Generate a PropagationResult instance."""
    domain = draw(st.text(min_size=3, max_size=50, alphabet=st.characters(whitelist_categories=('L', 'N'), whitelist_characters='.-')))
    record_type = draw(st.sampled_from(['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']))
    expected_value = draw(st.one_of(st.none(), st.text(min_size=1, max_size=50)))
    query_results = draw(st.lists(dns_query_result(), min_size=min_results, max_size=max_results))
    timestamp = datetime.now()
    
    return PropagationResult(
        domain=domain,
        record_type=record_type,
        expected_value=expected_value,
        query_results=query_results,
        timestamp=timestamp
    )


class TestPropagationRateCalculation:
    """Tests for propagation rate calculation property."""
    
    # Feature: dns-propagation-checker, Property 12: Propagation Rate Calculation
    @settings(max_examples=100)
    @given(propagation_result())
    def test_propagation_rate_formula(self, result: PropagationResult):
        """
        Property 12: Propagation Rate Calculation
        
        For any propagation result, the propagation_rate should equal 
        (matched_count / responsive_count) * 100, where responsive_count 
        excludes servers with 'unreachable' or 'timeout' status.
        
        Validates: Requirements 5.1, 5.3
        """
        # Calculate expected rate
        matched = sum(1 for r in result.query_results if r.status == 'matched')
        responsive = sum(1 for r in result.query_results 
                        if r.status in ('matched', 'mismatched'))
        
        if responsive == 0:
            expected_rate = 0.0
        else:
            expected_rate = (matched / responsive) * 100
        
        # Verify the property holds
        assert result.propagation_rate == expected_rate
        assert result.matched_count == matched
        assert result.responsive_count == responsive
    
    # Feature: dns-propagation-checker, Property 12: Propagation Rate Calculation
    @settings(max_examples=100)
    @given(st.integers(min_value=0, max_value=20), st.integers(min_value=0, max_value=20))
    def test_propagation_rate_with_controlled_counts(self, matched_count: int, mismatched_count: int):
        """
        Property 12: Propagation Rate Calculation (controlled test)
        
        For any combination of matched and mismatched counts, verify the 
        propagation rate calculation is correct.
        
        Validates: Requirements 5.1, 5.3
        """
        # Create query results with specific counts
        query_results = []
        
        # Add matched results
        for i in range(matched_count):
            server = DNSServerInfo(ip=f"1.1.1.{i}", name=f"Server{i}", location="Global")
            query_results.append(DNSQueryResult(
                server=server,
                status='matched',
                values=['192.168.1.1'],
                response_time=0.1,
                error=None
            ))
        
        # Add mismatched results
        for i in range(mismatched_count):
            server = DNSServerInfo(ip=f"2.2.2.{i}", name=f"Server{i+matched_count}", location="Global")
            query_results.append(DNSQueryResult(
                server=server,
                status='mismatched',
                values=['192.168.1.2'],
                response_time=0.1,
                error=None
            ))
        
        result = PropagationResult(
            domain="example.com",
            record_type="A",
            expected_value="192.168.1.1",
            query_results=query_results,
            timestamp=datetime.now()
        )
        
        # Calculate expected values
        responsive = matched_count + mismatched_count
        if responsive == 0:
            expected_rate = 0.0
        else:
            expected_rate = (matched_count / responsive) * 100
        
        # Verify
        assert result.matched_count == matched_count
        assert result.mismatched_count == mismatched_count
        assert result.responsive_count == responsive
        assert result.propagation_rate == expected_rate


class TestPropagationCompletionDetection:
    """Tests for propagation completion detection property."""
    
    # Feature: dns-propagation-checker, Property 15: Propagation Completion Detection
    @settings(max_examples=100)
    @given(propagation_result(min_results=1))
    def test_completion_detection(self, result: PropagationResult):
        """
        Property 15: Propagation Completion Detection
        
        For any propagation result where propagation_rate equals 100% and 
        responsive_count is greater than 0, the is_complete property should be True.
        
        Validates: Requirements 5.5
        """
        # Check the property
        if result.propagation_rate == 100.0 and result.responsive_count > 0:
            assert result.is_complete is True
        else:
            assert result.is_complete is False
    
    # Feature: dns-propagation-checker, Property 15: Propagation Completion Detection
    @settings(max_examples=100)
    @given(st.integers(min_value=1, max_value=20))
    def test_completion_with_all_matched(self, server_count: int):
        """
        Property 15: Propagation Completion Detection (all matched case)
        
        For any number of servers where all are matched, is_complete should be True.
        
        Validates: Requirements 5.5
        """
        # Create all matched results
        query_results = []
        for i in range(server_count):
            server = DNSServerInfo(ip=f"1.1.1.{i}", name=f"Server{i}", location="Global")
            query_results.append(DNSQueryResult(
                server=server,
                status='matched',
                values=['192.168.1.1'],
                response_time=0.1,
                error=None
            ))
        
        result = PropagationResult(
            domain="example.com",
            record_type="A",
            expected_value="192.168.1.1",
            query_results=query_results,
            timestamp=datetime.now()
        )
        
        # Verify completion
        assert result.propagation_rate == 100.0
        assert result.responsive_count == server_count
        assert result.is_complete is True
    
    # Feature: dns-propagation-checker, Property 15: Propagation Completion Detection
    @settings(max_examples=100)
    @given(st.integers(min_value=1, max_value=20), st.integers(min_value=1, max_value=20))
    def test_incomplete_with_mismatched(self, matched_count: int, mismatched_count: int):
        """
        Property 15: Propagation Completion Detection (incomplete case)
        
        For any result with at least one mismatched server, is_complete should be False.
        
        Validates: Requirements 5.5
        """
        # Create mixed results
        query_results = []
        
        # Add matched results
        for i in range(matched_count):
            server = DNSServerInfo(ip=f"1.1.1.{i}", name=f"Server{i}", location="Global")
            query_results.append(DNSQueryResult(
                server=server,
                status='matched',
                values=['192.168.1.1'],
                response_time=0.1,
                error=None
            ))
        
        # Add at least one mismatched result
        for i in range(mismatched_count):
            server = DNSServerInfo(ip=f"2.2.2.{i}", name=f"Server{i+matched_count}", location="Global")
            query_results.append(DNSQueryResult(
                server=server,
                status='mismatched',
                values=['192.168.1.2'],
                response_time=0.1,
                error=None
            ))
        
        result = PropagationResult(
            domain="example.com",
            record_type="A",
            expected_value="192.168.1.1",
            query_results=query_results,
            timestamp=datetime.now()
        )
        
        # Verify not complete
        assert result.propagation_rate < 100.0
        assert result.is_complete is False
    
    # Feature: dns-propagation-checker, Property 15: Propagation Completion Detection
    def test_completion_with_zero_responsive(self):
        """
        Property 15: Propagation Completion Detection (edge case: no responsive servers)
        
        When there are no responsive servers, is_complete should be False even if rate is 0.
        
        Validates: Requirements 5.5
        """
        # Create only unreachable results
        query_results = []
        for i in range(5):
            server = DNSServerInfo(ip=f"1.1.1.{i}", name=f"Server{i}", location="Global")
            query_results.append(DNSQueryResult(
                server=server,
                status='timeout',
                values=[],
                response_time=5.0,
                error="Connection timeout"
            ))
        
        result = PropagationResult(
            domain="example.com",
            record_type="A",
            expected_value="192.168.1.1",
            query_results=query_results,
            timestamp=datetime.now()
        )
        
        # Verify not complete (no responsive servers)
        assert result.responsive_count == 0
        assert result.propagation_rate == 0.0
        assert result.is_complete is False
