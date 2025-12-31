"""
Property-based tests for DNS propagation monitor (watch mode).

Tests correctness properties for continuous monitoring and auto-exit behavior.
"""

import asyncio
from datetime import datetime
from unittest.mock import Mock, AsyncMock, patch
from hypothesis import given, strategies as st, settings
import pytest

from domain_monitor.checkers.dns_propagation_checker import DNSPropagationChecker
from domain_monitor.dns_propagation_display import DNSPropagationDisplay
from domain_monitor.dns_propagation_monitor import DNSPropagationMonitor
from domain_monitor.models import DNSServerInfo, DNSQueryResult, PropagationResult


# Strategies for generating test data
@st.composite
def propagation_result_with_rate(draw, rate: float):
    """Generate a PropagationResult with a specific propagation rate."""
    domain = draw(st.text(min_size=3, max_size=50, alphabet=st.characters(whitelist_categories=('L', 'N'), whitelist_characters='.-')))
    record_type = draw(st.sampled_from(['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']))
    expected_value = draw(st.text(min_size=1, max_size=50))
    
    # Calculate how many servers we need
    total_servers = draw(st.integers(min_value=5, max_value=15))
    matched_count = int(total_servers * (rate / 100.0))
    mismatched_count = total_servers - matched_count
    
    query_results = []
    
    # Add matched results
    for i in range(matched_count):
        server = DNSServerInfo(ip=f"1.1.1.{i}", name=f"Server{i}", location="Global")
        query_results.append(DNSQueryResult(
            server=server,
            status='matched',
            values=[expected_value],
            response_time=0.1,
            error=None
        ))
    
    # Add mismatched results
    for i in range(mismatched_count):
        server = DNSServerInfo(ip=f"2.2.2.{i}", name=f"Server{i+matched_count}", location="Global")
        query_results.append(DNSQueryResult(
            server=server,
            status='mismatched',
            values=['different.value'],
            response_time=0.1,
            error=None
        ))
    
    return PropagationResult(
        domain=domain,
        record_type=record_type,
        expected_value=expected_value,
        query_results=query_results,
        timestamp=datetime.now()
    )


class TestWatchModeContinuousQuerying:
    """Tests for watch mode continuous querying property."""
    
    # Feature: dns-propagation-checker, Property 19: Watch Mode Continuous Querying
    @settings(max_examples=10, deadline=None)
    @given(
        st.integers(min_value=2, max_value=3),  # Number of iterations
        st.floats(min_value=0.1, max_value=0.5),  # Interval
        propagation_result_with_rate(50.0)  # Incomplete result
    )
    @pytest.mark.asyncio
    async def test_continuous_querying_until_interrupted(self, iterations: int, interval: float, incomplete_result: PropagationResult):
        """
        Property 19: Watch Mode Continuous Querying
        
        For any watch mode execution, DNS queries should repeat at the specified 
        interval until either propagation is complete or the user interrupts.
        
        This test verifies that queries continue at the correct interval until
        shutdown is requested.
        
        Validates: Requirements 7.1
        """
        # Create mock checker and display
        mock_checker = Mock(spec=DNSPropagationChecker)
        mock_display = Mock(spec=DNSPropagationDisplay)
        mock_display.console = Mock()
        mock_display.console.print = Mock()
        mock_display.console.clear = Mock()
        mock_display.display_result = Mock()
        
        # Track query calls
        query_count = 0
        
        async def mock_check_propagation(*args, **kwargs):
            nonlocal query_count
            query_count += 1
            # Return incomplete result to keep monitoring
            return incomplete_result
        
        mock_checker.check_propagation = AsyncMock(side_effect=mock_check_propagation)
        
        # Create monitor
        monitor = DNSPropagationMonitor(
            checker=mock_checker,
            display=mock_display,
            interval=interval
        )
        
        # Start monitoring in background task
        monitor_task = asyncio.create_task(
            monitor.start(
                domain="example.com",
                record_type="A",
                expected_value="192.168.1.1"
            )
        )
        
        # Let it run for expected iterations
        expected_duration = interval * iterations
        await asyncio.sleep(expected_duration + 0.5)  # Add buffer
        
        # Request shutdown
        monitor._shutdown_requested = True
        monitor._running = False
        
        # Wait for monitor to finish
        try:
            await asyncio.wait_for(monitor_task, timeout=2.0)
        except asyncio.TimeoutError:
            monitor_task.cancel()
        
        # Verify queries were made continuously
        # Should have at least 'iterations' queries (may have one more due to timing)
        assert query_count >= iterations, f"Expected at least {iterations} queries, got {query_count}"
        
        # Verify checker was called with correct parameters
        for call in mock_checker.check_propagation.call_args_list:
            args, kwargs = call
            assert kwargs.get('domain') == "example.com" or args[0] == "example.com"
            assert kwargs.get('record_type') == "A" or args[1] == "A"
    
    # Feature: dns-propagation-checker, Property 19: Watch Mode Continuous Querying
    @settings(max_examples=10, deadline=None)
    @given(
        st.floats(min_value=0.5, max_value=1.0),  # Interval
        propagation_result_with_rate(50.0)  # Incomplete result
    )
    @pytest.mark.asyncio
    async def test_interval_timing(self, interval: float, incomplete_result: PropagationResult):
        """
        Property 19: Watch Mode Continuous Querying (interval timing)
        
        For any specified interval, watch mode should wait approximately that
        duration between queries.
        
        Validates: Requirements 7.1, 7.6
        """
        # Create mock checker and display
        mock_checker = Mock(spec=DNSPropagationChecker)
        mock_display = Mock(spec=DNSPropagationDisplay)
        mock_display.console = Mock()
        mock_display.console.print = Mock()
        mock_display.console.clear = Mock()
        mock_display.display_result = Mock()
        
        # Track query timestamps
        query_times = []
        
        async def mock_check_propagation(*args, **kwargs):
            query_times.append(asyncio.get_event_loop().time())
            return incomplete_result
        
        mock_checker.check_propagation = AsyncMock(side_effect=mock_check_propagation)
        
        # Create monitor with specified interval
        monitor = DNSPropagationMonitor(
            checker=mock_checker,
            display=mock_display,
            interval=interval
        )
        
        # Start monitoring
        monitor_task = asyncio.create_task(
            monitor.start(
                domain="example.com",
                record_type="A",
                expected_value="192.168.1.1"
            )
        )
        
        # Let it run for 3 intervals
        await asyncio.sleep(interval * 3 + 1.0)
        
        # Stop monitoring
        monitor._shutdown_requested = True
        monitor._running = False
        
        try:
            await asyncio.wait_for(monitor_task, timeout=2.0)
        except asyncio.TimeoutError:
            monitor_task.cancel()
        
        # Verify timing between queries
        if len(query_times) >= 2:
            for i in range(1, len(query_times)):
                time_diff = query_times[i] - query_times[i-1]
                # Allow 20% tolerance for timing variations
                assert time_diff >= interval * 0.8, f"Interval too short: {time_diff} < {interval * 0.8}"
                assert time_diff <= interval * 1.5, f"Interval too long: {time_diff} > {interval * 1.5}"


class TestWatchModeAutoExit:
    """Tests for watch mode auto-exit on completion property."""
    
    # Feature: dns-propagation-checker, Property 20: Watch Mode Auto-Exit on Completion
    @settings(max_examples=10, deadline=None)
    @given(
        st.integers(min_value=1, max_value=2),  # Iterations before completion
        propagation_result_with_rate(50.0),  # Incomplete result
        propagation_result_with_rate(100.0)  # Complete result
    )
    @pytest.mark.asyncio
    async def test_auto_exit_on_completion(self, iterations_before_complete: int, incomplete_result: PropagationResult, complete_result: PropagationResult):
        """
        Property 20: Watch Mode Auto-Exit on Completion
        
        For any watch mode execution, when propagation reaches 100% (is_complete 
        becomes True), the monitor should stop and display a completion message.
        
        Validates: Requirements 7.3
        """
        # Create mock checker and display
        mock_checker = Mock(spec=DNSPropagationChecker)
        mock_display = Mock(spec=DNSPropagationDisplay)
        mock_display.console = Mock()
        mock_display.console.print = Mock()
        mock_display.console.clear = Mock()
        mock_display.display_result = Mock()
        
        # Track query count
        query_count = 0
        
        async def mock_check_propagation(*args, **kwargs):
            nonlocal query_count
            query_count += 1
            
            # Return incomplete results for first N iterations, then complete
            if query_count <= iterations_before_complete:
                return incomplete_result
            else:
                return complete_result
        
        mock_checker.check_propagation = AsyncMock(side_effect=mock_check_propagation)
        
        # Create monitor
        monitor = DNSPropagationMonitor(
            checker=mock_checker,
            display=mock_display,
            interval=0.1  # Short interval for faster test
        )
        
        # Start monitoring
        start_time = asyncio.get_event_loop().time()
        await monitor.start(
            domain="example.com",
            record_type="A",
            expected_value="192.168.1.1"
        )
        end_time = asyncio.get_event_loop().time()
        
        # Verify monitoring stopped automatically
        assert not monitor._running, "Monitor should have stopped"
        
        # Verify it stopped after seeing complete result
        assert query_count == iterations_before_complete + 1, \
            f"Expected {iterations_before_complete + 1} queries, got {query_count}"
        
        # Verify completion message was displayed
        print_calls = [str(call) for call in mock_display.console.print.call_args_list]
        completion_messages = [call for call in print_calls if 'complete' in call.lower() or 'exiting' in call.lower()]
        assert len(completion_messages) > 0, "Completion message should be displayed"
        
        # Verify it didn't run too long (should stop quickly after completion)
        max_expected_time = (iterations_before_complete + 2) * 0.1 + 2.0  # Add buffer
        elapsed = end_time - start_time
        assert elapsed < max_expected_time, \
            f"Monitor ran too long: {elapsed}s > {max_expected_time}s"
    
    # Feature: dns-propagation-checker, Property 20: Watch Mode Auto-Exit on Completion
    @settings(max_examples=100, deadline=None)
    @given(st.integers(min_value=5, max_value=20))  # Number of servers
    @pytest.mark.asyncio
    async def test_auto_exit_with_all_matched(self, server_count: int):
        """
        Property 20: Watch Mode Auto-Exit on Completion (all matched case)
        
        For any result where all servers are matched (100% propagation), 
        watch mode should exit immediately.
        
        Validates: Requirements 7.3
        """
        # Create mock checker and display
        mock_checker = Mock(spec=DNSPropagationChecker)
        mock_display = Mock(spec=DNSPropagationDisplay)
        mock_display.console = Mock()
        mock_display.console.print = Mock()
        mock_display.console.clear = Mock()
        mock_display.display_result = Mock()
        
        # Create complete result with all matched
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
        
        complete_result = PropagationResult(
            domain="example.com",
            record_type="A",
            expected_value="192.168.1.1",
            query_results=query_results,
            timestamp=datetime.now()
        )
        
        # Verify result is complete
        assert complete_result.is_complete is True
        assert complete_result.propagation_rate == 100.0
        
        # Mock checker to return complete result
        mock_checker.check_propagation = AsyncMock(return_value=complete_result)
        
        # Create monitor
        monitor = DNSPropagationMonitor(
            checker=mock_checker,
            display=mock_display,
            interval=1.0
        )
        
        # Start monitoring
        start_time = asyncio.get_event_loop().time()
        await monitor.start(
            domain="example.com",
            record_type="A",
            expected_value="192.168.1.1"
        )
        end_time = asyncio.get_event_loop().time()
        
        # Verify it stopped quickly (should not wait for another interval)
        elapsed = end_time - start_time
        assert elapsed < 2.0, f"Should exit quickly, but took {elapsed}s"
        
        # Verify only one query was made
        assert mock_checker.check_propagation.call_count == 1
        
        # Verify not running
        assert not monitor._running
    
    # Feature: dns-propagation-checker, Property 20: Watch Mode Auto-Exit on Completion
    @settings(max_examples=10, deadline=None)
    @given(
        st.integers(min_value=1, max_value=3),  # Iterations
        propagation_result_with_rate(75.0)  # Incomplete result
    )
    @pytest.mark.asyncio
    async def test_no_auto_exit_when_incomplete(self, iterations: int, incomplete_result: PropagationResult):
        """
        Property 20: Watch Mode Auto-Exit on Completion (negative case)
        
        For any watch mode execution where propagation never reaches 100%,
        the monitor should continue running until interrupted.
        
        Validates: Requirements 7.3
        """
        # Create mock checker and display
        mock_checker = Mock(spec=DNSPropagationChecker)
        mock_display = Mock(spec=DNSPropagationDisplay)
        mock_display.console = Mock()
        mock_display.console.print = Mock()
        mock_display.console.clear = Mock()
        mock_display.display_result = Mock()
        
        # Verify result is not complete
        assert incomplete_result.is_complete is False
        
        query_count = 0
        
        async def mock_check_propagation(*args, **kwargs):
            nonlocal query_count
            query_count += 1
            return incomplete_result
        
        mock_checker.check_propagation = AsyncMock(side_effect=mock_check_propagation)
        
        # Create monitor
        monitor = DNSPropagationMonitor(
            checker=mock_checker,
            display=mock_display,
            interval=0.1
        )
        
        # Start monitoring in background
        monitor_task = asyncio.create_task(
            monitor.start(
                domain="example.com",
                record_type="A",
                expected_value="192.168.1.1"
            )
        )
        
        # Let it run for expected iterations
        await asyncio.sleep(0.1 * iterations + 0.5)
        
        # Verify it's still running (didn't auto-exit)
        assert monitor._running or query_count >= iterations, \
            "Monitor should still be running since propagation is incomplete"
        
        # Stop it manually
        monitor._shutdown_requested = True
        monitor._running = False
        
        try:
            await asyncio.wait_for(monitor_task, timeout=2.0)
        except asyncio.TimeoutError:
            monitor_task.cancel()
        
        # Verify multiple queries were made (didn't exit early)
        assert query_count >= iterations, \
            f"Should have made at least {iterations} queries, got {query_count}"
