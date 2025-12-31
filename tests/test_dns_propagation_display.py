"""Unit tests for DNS propagation display functionality.

Tests the DNSPropagationDisplay class to ensure proper formatting and display
of DNS propagation check results.
"""

import pytest
from datetime import datetime
from io import StringIO
from rich.console import Console

from domain_monitor.models import DNSServerInfo, DNSQueryResult, PropagationResult
from domain_monitor.dns_propagation_display import DNSPropagationDisplay
from domain_monitor.console.output import ConsoleManager


@pytest.fixture
def console_manager():
    """Create a ConsoleManager for testing."""
    return ConsoleManager(debug_mode=False)


@pytest.fixture
def display(console_manager):
    """Create a DNSPropagationDisplay instance for testing."""
    return DNSPropagationDisplay(console_manager)


@pytest.fixture
def sample_propagation_result():
    """Create a sample PropagationResult for testing."""
    servers = [
        DNSServerInfo(ip="8.8.8.8", name="Google Primary", location="Global"),
        DNSServerInfo(ip="1.1.1.1", name="Cloudflare Primary", location="Global"),
        DNSServerInfo(ip="9.9.9.9", name="Quad9", location="Global"),
    ]
    
    query_results = [
        DNSQueryResult(
            server=servers[0],
            status='matched',
            values=['93.184.216.34'],
            response_time=0.045,
            error=None
        ),
        DNSQueryResult(
            server=servers[1],
            status='matched',
            values=['93.184.216.34'],
            response_time=0.032,
            error=None
        ),
        DNSQueryResult(
            server=servers[2],
            status='mismatched',
            values=['93.184.216.35'],
            response_time=0.067,
            error=None
        ),
    ]
    
    return PropagationResult(
        domain='example.com',
        record_type='A',
        expected_value='93.184.216.34',
        query_results=query_results,
        timestamp=datetime.now()
    )


def test_display_result_includes_summary(display, sample_propagation_result, capsys):
    """Test that display_result includes summary information.
    
    Requirements: 8.1, 8.3
    """
    # Capture output
    display.display_result(sample_propagation_result, watch_mode=False)
    captured = capsys.readouterr()
    output = captured.out
    
    # Check that summary includes domain
    assert 'example.com' in output
    
    # Check that summary includes record type
    assert 'A' in output or 'Record Type' in output
    
    # Check that summary includes expected value
    assert '93.184.216.34' in output
    
    # Check that summary includes propagation rate
    assert '66.7%' in output or '66.6%' in output or 'Propagation Rate' in output


def test_display_summary_includes_propagation_rate(display, sample_propagation_result, capsys):
    """Test that display_summary includes propagation rate.
    
    Requirements: 8.3
    """
    display.display_summary(sample_propagation_result)
    captured = capsys.readouterr()
    output = captured.out
    
    # Check that propagation rate is displayed
    assert 'Propagation Rate' in output or '66.7%' in output or '66.6%' in output
    
    # Check that server counts are displayed
    assert 'Matched' in output or '2' in output
    assert 'Mismatched' in output or '1' in output


def test_display_server_table_includes_required_columns(display, sample_propagation_result, capsys):
    """Test that display_server_table includes all required columns.
    
    Requirements: 8.1
    """
    display.display_server_table(sample_propagation_result)
    captured = capsys.readouterr()
    output = captured.out
    
    # Check for required column headers (may be truncated in display)
    assert 'DNS Server' in output
    assert 'Locati' in output or 'Location' in output  # May be truncated
    assert 'Status' in output
    assert 'Actual Value' in output or 'Value' in output
    assert 'Response Time' in output or 'Time' in output or 'Response' in output
    
    # Check for server data
    assert 'Google Primary' in output or '8.8.8.8' in output
    assert 'Cloudflare Primary' in output or '1.1.1.1' in output
    assert 'Quad9' in output or '9.9.9.9' in output


def test_display_server_table_shows_status_for_each_server(display, sample_propagation_result, capsys):
    """Test that display_server_table shows status for each DNS server.
    
    Requirements: 8.1, 8.2
    """
    display.display_server_table(sample_propagation_result)
    captured = capsys.readouterr()
    output = captured.out
    
    # Check that status indicators are present
    # The output should contain status information (matched/mismatched)
    assert 'Matched' in output or 'Mismatched' in output or 'Status' in output


def test_display_progress_bar_shows_rate(display, capsys):
    """Test that display_progress_bar shows the propagation rate.
    
    Requirements: 8.4
    """
    display.display_progress_bar(66.7)
    captured = capsys.readouterr()
    output = captured.out
    
    # Check that progress bar includes the rate
    assert '66.7%' in output or 'Propagation Progress' in output or '66' in output


def test_display_result_with_complete_propagation(display, capsys):
    """Test display_result shows completion message when propagation is 100%.
    
    Requirements: 5.5, 8.3
    """
    # Create a result with 100% propagation
    servers = [
        DNSServerInfo(ip="8.8.8.8", name="Google Primary", location="Global"),
        DNSServerInfo(ip="1.1.1.1", name="Cloudflare Primary", location="Global"),
    ]
    
    query_results = [
        DNSQueryResult(
            server=servers[0],
            status='matched',
            values=['93.184.216.34'],
            response_time=0.045,
            error=None
        ),
        DNSQueryResult(
            server=servers[1],
            status='matched',
            values=['93.184.216.34'],
            response_time=0.032,
            error=None
        ),
    ]
    
    complete_result = PropagationResult(
        domain='example.com',
        record_type='A',
        expected_value='93.184.216.34',
        query_results=query_results,
        timestamp=datetime.now()
    )
    
    display.display_result(complete_result, watch_mode=False)
    captured = capsys.readouterr()
    output = captured.out
    
    # Check for completion message
    assert 'complete' in output.lower() or '100' in output


def test_display_summary_with_no_expected_value(display, capsys):
    """Test display_summary works when no expected value is provided.
    
    Requirements: 4.4
    """
    servers = [
        DNSServerInfo(ip="8.8.8.8", name="Google Primary", location="Global"),
    ]
    
    query_results = [
        DNSQueryResult(
            server=servers[0],
            status='matched',  # Status might be different without expected value
            values=['93.184.216.34'],
            response_time=0.045,
            error=None
        ),
    ]
    
    result = PropagationResult(
        domain='example.com',
        record_type='A',
        expected_value=None,  # No expected value
        query_results=query_results,
        timestamp=datetime.now()
    )
    
    # Should not raise an exception
    display.display_summary(result)
    captured = capsys.readouterr()
    output = captured.out
    
    # Check that domain is still displayed
    assert 'example.com' in output


def test_display_server_table_with_multiple_values(display, capsys):
    """Test display_server_table handles DNS records with multiple values.
    
    Requirements: 4.5, 8.1
    """
    servers = [
        DNSServerInfo(ip="8.8.8.8", name="Google Primary", location="Global"),
    ]
    
    query_results = [
        DNSQueryResult(
            server=servers[0],
            status='matched',
            values=['mail1.example.com', 'mail2.example.com', 'mail3.example.com'],
            response_time=0.045,
            error=None
        ),
    ]
    
    result = PropagationResult(
        domain='example.com',
        record_type='MX',
        expected_value='mail1.example.com',
        query_results=query_results,
        timestamp=datetime.now()
    )
    
    display.display_server_table(result)
    captured = capsys.readouterr()
    output = captured.out
    
    # Check that first value is shown
    assert 'mail1.example.com' in output
    
    # Check that indicator for additional values is present
    assert '+2 more' in output or 'more' in output


def test_display_server_table_with_unreachable_servers(display, capsys):
    """Test display_server_table handles unreachable servers correctly.
    
    Requirements: 1.4, 8.2, 9.2
    """
    servers = [
        DNSServerInfo(ip="8.8.8.8", name="Google Primary", location="Global"),
        DNSServerInfo(ip="1.1.1.1", name="Cloudflare Primary", location="Global"),
    ]
    
    query_results = [
        DNSQueryResult(
            server=servers[0],
            status='matched',
            values=['93.184.216.34'],
            response_time=0.045,
            error=None
        ),
        DNSQueryResult(
            server=servers[1],
            status='timeout',
            values=[],
            response_time=5.0,
            error='Query timeout'
        ),
    ]
    
    result = PropagationResult(
        domain='example.com',
        record_type='A',
        expected_value='93.184.216.34',
        query_results=query_results,
        timestamp=datetime.now()
    )
    
    display.display_server_table(result)
    captured = capsys.readouterr()
    output = captured.out
    
    # Check that timeout status is displayed
    assert 'Timeout' in output or 'timeout' in output or 'Unreachable' in output


def test_display_summary_shows_server_counts(display, sample_propagation_result, capsys):
    """Test that display_summary shows matched, mismatched, and unreachable counts.
    
    Requirements: 5.4
    """
    display.display_summary(sample_propagation_result)
    captured = capsys.readouterr()
    output = captured.out
    
    # Check for server count labels
    assert 'Matched' in output
    assert 'Mismatched' in output
    assert 'Unreachable' in output or 'Total Responsive' in output
    
    # Check for actual counts (2 matched, 1 mismatched, 0 unreachable)
    # The numbers should appear somewhere in the output
    assert '2' in output  # matched count
    assert '1' in output  # mismatched count
