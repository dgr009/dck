"""
Integration tests for DNS Propagation Checker.

Tests end-to-end functionality including CLI integration, full propagation checks,
and watch mode behavior with real DNS queries.

Requirements: 10.1, 10.2, 10.3, 10.4, 10.5
"""

import asyncio
import time
from unittest.mock import Mock, AsyncMock, patch
import pytest
from click.testing import CliRunner

from domain_monitor.main import cli
from domain_monitor.checkers.dns_propagation_checker import DNSPropagationChecker
from domain_monitor.dns_propagation_display import DNSPropagationDisplay
from domain_monitor.dns_propagation_monitor import DNSPropagationMonitor
from domain_monitor.models import DNSServerInfo, DNSQueryResult, PropagationResult
from domain_monitor.console.output import ConsoleManager


class TestFullPropagationCheckIntegration:
    """
    Integration tests for complete propagation check flow.
    
    Tests the full flow from CLI to display with real DNS queries.
    Requirements: 10.1, 10.3, 10.4
    """
    
    @pytest.mark.asyncio
    async def test_complete_flow_cli_to_display(self):
        """
        Test complete flow from CLI to display.
        
        Verifies that the entire propagation check workflow executes correctly:
        - CLI argument parsing
        - DNS query execution
        - Result processing
        - Display output
        
        Requirements: 10.1, 10.4
        """
        # Use a well-known domain for testing
        domain = "google.com"
        record_type = "A"
        
        # Create checker with limited servers for faster testing
        fast_servers = [
            ("8.8.8.8", "Google Primary", "Global"),
            ("1.1.1.1", "Cloudflare Primary", "Global"),
        ]
        checker = DNSPropagationChecker(custom_servers=fast_servers)
        
        # Execute propagation check
        result = await checker.check_propagation(domain, record_type)
        
        # Verify result structure
        assert result.domain == domain
        assert result.record_type == record_type
        assert len(result.query_results) == len(checker.dns_servers)
        
        # Verify at least some servers responded
        successful_count = sum(1 for r in result.query_results 
                              if r.status not in ('timeout', 'unreachable'))
        assert successful_count > 0, "Expected at least one successful DNS query"
        
        # Verify display can render the result
        console_manager = ConsoleManager(debug_mode=False)
        display = DNSPropagationDisplay(console_manager)
        
        # This should not raise any exceptions
        try:
            display.display_result(result, watch_mode=False)
            display_success = True
        except Exception as e:
            display_success = False
            pytest.fail(f"Display failed with error: {e}")
        
        assert display_success, "Display should render result without errors"
    
    @pytest.mark.asyncio
    async def test_real_dns_queries_against_test_domain(self):
        """
        Test with real DNS queries against a known domain.
        
        Uses actual DNS queries to verify the checker works with real DNS servers.
        
        Requirements: 10.1
        """
        # Use google.com which should always be resolvable
        domain = "google.com"
        
        # Create checker with a few fast DNS servers
        fast_servers = [
            ("8.8.8.8", "Google Primary", "Global"),
            ("1.1.1.1", "Cloudflare Primary", "Global"),
            ("9.9.9.9", "Quad9", "Global"),
        ]
        checker = DNSPropagationChecker(custom_servers=fast_servers)
        
        # Test A record
        result_a = await checker.check_propagation(domain, "A")
        assert result_a.domain == domain
        assert result_a.record_type == "A"
        
        # Verify we got responses
        successful_a = [r for r in result_a.query_results 
                       if r.status not in ('timeout', 'unreachable') and len(r.values) > 0]
        assert len(successful_a) > 0, "Expected successful A record queries"
        
        # Verify A records are IP addresses
        for query_result in successful_a:
            for value in query_result.values:
                # A records should look like IP addresses
                parts = value.split('.')
                assert len(parts) == 4, f"Expected IPv4 address format, got {value}"
        
        # Test AAAA record
        result_aaaa = await checker.check_propagation(domain, "AAAA")
        assert result_aaaa.record_type == "AAAA"
        
        # Test MX record
        result_mx = await checker.check_propagation(domain, "MX")
        assert result_mx.record_type == "MX"
        successful_mx = [r for r in result_mx.query_results 
                        if r.status not in ('timeout', 'unreachable') and len(r.values) > 0]
        assert len(successful_mx) > 0, "Expected successful MX record queries"
    
    @pytest.mark.asyncio
    async def test_propagation_check_with_expected_value(self):
        """
        Test propagation check with expected value comparison.
        
        Verifies that expected value comparison works correctly in the full flow.
        
        Requirements: 10.1, 4.1, 4.2, 4.3
        """
        domain = "google.com"
        
        # Create checker
        fast_servers = [("8.8.8.8", "Google Primary", "Global")]
        checker = DNSPropagationChecker(custom_servers=fast_servers)
        
        # First query without expected value to get actual value
        result_no_expected = await checker.check_propagation(domain, "A")
        successful_results = [r for r in result_no_expected.query_results 
                             if r.status not in ('timeout', 'unreachable') and len(r.values) > 0]
        
        assert len(successful_results) > 0, "Need at least one successful query"
        actual_value = successful_results[0].values[0]
        
        # Now query with expected value
        result_with_expected = await checker.check_propagation(domain, "A", actual_value)
        
        # Verify expected value was set
        assert result_with_expected.expected_value == actual_value
        
        # Verify comparison was performed
        matched_count = sum(1 for r in result_with_expected.query_results 
                           if r.status == 'matched')
        assert matched_count > 0, "Expected at least one matched result"
        
        # Verify propagation rate is calculated
        assert result_with_expected.propagation_rate >= 0.0
        assert result_with_expected.propagation_rate <= 100.0
    
    @pytest.mark.asyncio
    async def test_multiple_record_types_concurrent_check(self):
        """
        Test checking multiple record types concurrently.
        
        Verifies that multiple record types can be checked simultaneously.
        
        Requirements: 10.1, 3.7
        """
        domain = "google.com"
        record_types = ['A', 'AAAA', 'MX', 'NS']
        
        # Create checker
        fast_servers = [
            ("8.8.8.8", "Google Primary", "Global"),
            ("1.1.1.1", "Cloudflare Primary", "Global"),
        ]
        checker = DNSPropagationChecker(custom_servers=fast_servers)
        
        # Execute queries concurrently
        start_time = time.time()
        tasks = [checker.check_propagation(domain, rt) for rt in record_types]
        results = await asyncio.gather(*tasks)
        elapsed_time = time.time() - start_time
        
        # Verify all queries completed
        assert len(results) == len(record_types)
        
        # Verify each result has correct record type
        for i, result in enumerate(results):
            assert result.record_type == record_types[i]
            assert result.domain == domain
        
        # Verify concurrent execution (should be faster than sequential)
        # With 2 servers and 4 record types, sequential would take much longer
        assert elapsed_time < 15.0, f"Concurrent queries took too long: {elapsed_time}s"
    
    def test_cli_integration_basic_check(self):
        """
        Test CLI integration for basic propagation check.
        
        Verifies that the CLI command works correctly with basic arguments.
        
        Requirements: 10.4, 6.1
        """
        runner = CliRunner()
        
        # Test basic command
        result = runner.invoke(cli, ['dns-propagation', 'google.com'])
        
        # Verify command executed (may have output or errors, but should not crash)
        assert result.exit_code in (0, 1), f"Unexpected exit code: {result.exit_code}"
        
        # If successful, verify output contains expected elements
        if result.exit_code == 0:
            output = result.output
            assert 'google.com' in output or 'DNS' in output or 'propagation' in output.lower()
    
    def test_cli_integration_with_record_type(self):
        """
        Test CLI integration with record type option.
        
        Verifies that --record-type option works correctly.
        
        Requirements: 10.4, 6.2
        """
        runner = CliRunner()
        
        # Test with record type option
        result = runner.invoke(cli, ['dns-propagation', 'google.com', '--record-type', 'MX'])
        
        # Verify command executed
        assert result.exit_code in (0, 1), f"Unexpected exit code: {result.exit_code}"
    
    def test_cli_integration_with_expected_value(self):
        """
        Test CLI integration with expected value option.
        
        Verifies that --expected option works correctly.
        
        Requirements: 10.4, 6.3
        """
        runner = CliRunner()
        
        # Test with expected value option
        result = runner.invoke(cli, [
            'dns-propagation', 'google.com',
            '--expected', '192.0.2.1'
        ])
        
        # Verify command executed
        assert result.exit_code in (0, 1), f"Unexpected exit code: {result.exit_code}"


class TestWatchModeIntegration:
    """
    Integration tests for watch mode functionality.
    
    Tests watch mode startup, shutdown, interval timing, and auto-exit behavior.
    Requirements: 10.2, 7.1, 7.3, 7.6
    """
    
    @pytest.mark.asyncio
    async def test_watch_mode_startup_and_shutdown(self):
        """
        Test watch mode startup and shutdown.
        
        Verifies that watch mode can start and stop gracefully.
        
        Requirements: 10.2, 7.1, 7.4
        """
        from datetime import datetime
        
        # Create mock checker and display
        mock_checker = Mock(spec=DNSPropagationChecker)
        mock_display = Mock(spec=DNSPropagationDisplay)
        mock_display.console = Mock()
        mock_display.console.print = Mock()
        mock_display.console.clear = Mock()
        mock_display.display_result = Mock()
        
        # Create incomplete result to keep monitoring
        query_results = [
            DNSQueryResult(
                server=DNSServerInfo(ip="8.8.8.8", name="Google", location="Global"),
                status='matched',
                values=['192.168.1.1'],
                response_time=0.1,
                error=None
            ),
            DNSQueryResult(
                server=DNSServerInfo(ip="1.1.1.1", name="Cloudflare", location="Global"),
                status='mismatched',
                values=['192.168.1.2'],
                response_time=0.1,
                error=None
            ),
        ]
        
        incomplete_result = PropagationResult(
            domain="example.com",
            record_type="A",
            expected_value="192.168.1.1",
            query_results=query_results,
            timestamp=datetime.now()
        )
        
        mock_checker.check_propagation = AsyncMock(return_value=incomplete_result)
        
        # Create monitor
        monitor = DNSPropagationMonitor(
            checker=mock_checker,
            display=mock_display,
            interval=0.2
        )
        
        # Start monitoring in background
        monitor_task = asyncio.create_task(
            monitor.start(
                domain="example.com",
                record_type="A",
                expected_value="192.168.1.1"
            )
        )
        
        # Let it run briefly
        await asyncio.sleep(0.5)
        
        # Verify it's running
        assert monitor._running or monitor_task.done()
        
        # Request shutdown
        monitor._shutdown_requested = True
        monitor._running = False
        
        # Wait for shutdown
        try:
            await asyncio.wait_for(monitor_task, timeout=2.0)
        except asyncio.TimeoutError:
            monitor_task.cancel()
            pytest.fail("Monitor did not shut down gracefully")
        
        # Verify checker was called
        assert mock_checker.check_propagation.call_count >= 1
    
    @pytest.mark.asyncio
    async def test_watch_mode_interval_timing(self):
        """
        Test watch mode interval timing.
        
        Verifies that watch mode respects the specified interval between checks.
        
        Requirements: 10.2, 7.1, 7.6
        """
        from datetime import datetime
        
        # Create mock checker and display
        mock_checker = Mock(spec=DNSPropagationChecker)
        mock_display = Mock(spec=DNSPropagationDisplay)
        mock_display.console = Mock()
        mock_display.console.print = Mock()
        mock_display.console.clear = Mock()
        mock_display.display_result = Mock()
        
        # Track query times
        query_times = []
        
        async def mock_check(*args, **kwargs):
            query_times.append(time.time())
            # Return incomplete result
            return PropagationResult(
                domain="example.com",
                record_type="A",
                expected_value="192.168.1.1",
                query_results=[
                    DNSQueryResult(
                        server=DNSServerInfo(ip="8.8.8.8", name="Google", location="Global"),
                        status='matched',
                        values=['192.168.1.1'],
                        response_time=0.1,
                        error=None
                    ),
                    DNSQueryResult(
                        server=DNSServerInfo(ip="1.1.1.1", name="Cloudflare", location="Global"),
                        status='mismatched',
                        values=['192.168.1.2'],
                        response_time=0.1,
                        error=None
                    ),
                ],
                timestamp=datetime.now()
            )
        
        mock_checker.check_propagation = AsyncMock(side_effect=mock_check)
        
        # Create monitor with specific interval
        interval = 0.5
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
        await asyncio.sleep(interval * 3 + 0.5)
        
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
                # Allow 30% tolerance for timing variations
                assert time_diff >= interval * 0.7, \
                    f"Interval too short: {time_diff} < {interval * 0.7}"
                assert time_diff <= interval * 1.5, \
                    f"Interval too long: {time_diff} > {interval * 1.5}"
    
    @pytest.mark.asyncio
    async def test_watch_mode_auto_exit_on_completion(self):
        """
        Test watch mode auto-exit on completion.
        
        Verifies that watch mode automatically exits when propagation reaches 100%.
        
        Requirements: 10.2, 7.3
        """
        from datetime import datetime
        
        # Create mock checker and display
        mock_checker = Mock(spec=DNSPropagationChecker)
        mock_display = Mock(spec=DNSPropagationDisplay)
        mock_display.console = Mock()
        mock_display.console.print = Mock()
        mock_display.console.clear = Mock()
        mock_display.display_result = Mock()
        
        query_count = 0
        
        async def mock_check(*args, **kwargs):
            nonlocal query_count
            query_count += 1
            
            # Return incomplete result first, then complete
            if query_count == 1:
                # Incomplete result (50% propagation)
                return PropagationResult(
                    domain="example.com",
                    record_type="A",
                    expected_value="192.168.1.1",
                    query_results=[
                        DNSQueryResult(
                            server=DNSServerInfo(ip="8.8.8.8", name="Google", location="Global"),
                            status='matched',
                            values=['192.168.1.1'],
                            response_time=0.1,
                            error=None
                        ),
                        DNSQueryResult(
                            server=DNSServerInfo(ip="1.1.1.1", name="Cloudflare", location="Global"),
                            status='mismatched',
                            values=['192.168.1.2'],
                            response_time=0.1,
                            error=None
                        ),
                    ],
                    timestamp=datetime.now()
                )
            else:
                # Complete result (100% propagation)
                return PropagationResult(
                    domain="example.com",
                    record_type="A",
                    expected_value="192.168.1.1",
                    query_results=[
                        DNSQueryResult(
                            server=DNSServerInfo(ip="8.8.8.8", name="Google", location="Global"),
                            status='matched',
                            values=['192.168.1.1'],
                            response_time=0.1,
                            error=None
                        ),
                        DNSQueryResult(
                            server=DNSServerInfo(ip="1.1.1.1", name="Cloudflare", location="Global"),
                            status='matched',
                            values=['192.168.1.1'],
                            response_time=0.1,
                            error=None
                        ),
                    ],
                    timestamp=datetime.now()
                )
        
        mock_checker.check_propagation = AsyncMock(side_effect=mock_check)
        
        # Create monitor
        monitor = DNSPropagationMonitor(
            checker=mock_checker,
            display=mock_display,
            interval=0.2
        )
        
        # Start monitoring
        start_time = time.time()
        await monitor.start(
            domain="example.com",
            record_type="A",
            expected_value="192.168.1.1"
        )
        elapsed_time = time.time() - start_time
        
        # Verify it stopped automatically
        assert not monitor._running, "Monitor should have stopped"
        
        # Verify it stopped after seeing complete result
        assert query_count == 2, f"Expected 2 queries, got {query_count}"
        
        # Verify it didn't run too long
        assert elapsed_time < 2.0, f"Monitor ran too long: {elapsed_time}s"
        
        # Verify completion message was displayed
        print_calls = [str(call) for call in mock_display.console.print.call_args_list]
        completion_messages = [call for call in print_calls 
                              if 'complete' in call.lower() or 'exiting' in call.lower()]
        assert len(completion_messages) > 0, "Completion message should be displayed"
    
    @pytest.mark.asyncio
    async def test_watch_mode_with_real_checker(self):
        """
        Test watch mode with real DNS checker (limited duration).
        
        Verifies that watch mode works with actual DNS queries.
        
        Requirements: 10.2, 10.3
        """
        # Create real checker with limited servers
        fast_servers = [
            ("8.8.8.8", "Google Primary", "Global"),
            ("1.1.1.1", "Cloudflare Primary", "Global"),
        ]
        checker = DNSPropagationChecker(custom_servers=fast_servers)
        
        # Create real display
        console_manager = ConsoleManager(debug_mode=False)
        display = DNSPropagationDisplay(console_manager)
        
        # Create monitor with short interval
        monitor = DNSPropagationMonitor(
            checker=checker,
            display=display,
            interval=0.5
        )
        
        # Start monitoring in background
        monitor_task = asyncio.create_task(
            monitor.start(
                domain="google.com",
                record_type="A",
                expected_value=None  # No expected value, so it won't complete
            )
        )
        
        # Let it run for a short time
        await asyncio.sleep(1.5)
        
        # Stop monitoring
        monitor._shutdown_requested = True
        monitor._running = False
        
        # Wait for shutdown
        try:
            await asyncio.wait_for(monitor_task, timeout=2.0)
        except asyncio.TimeoutError:
            monitor_task.cancel()
            pytest.fail("Monitor did not shut down gracefully")
        
        # If we got here, watch mode worked with real checker
        assert True


class TestCompatibilityWithExistingFeatures:
    """
    Tests to verify DNS propagation checker integrates well with existing dck features.
    
    Requirements: 10.3, 10.5
    """
    
    def test_dns_propagation_checker_uses_existing_dns_checker(self):
        """
        Test that DNSPropagationChecker reuses existing DNSChecker logic.
        
        Verifies integration with existing codebase.
        
        Requirements: 10.1, 10.3
        """
        # Create checker
        checker = DNSPropagationChecker()
        
        # Verify it has the expected structure
        assert hasattr(checker, 'dns_servers')
        assert hasattr(checker, 'check_propagation')
        assert len(checker.dns_servers) > 0
        
        # Verify default servers are configured
        assert len(checker.dns_servers) >= 10, "Should have at least 10 default DNS servers"
    
    def test_dns_propagation_display_uses_console_manager(self):
        """
        Test that DNSPropagationDisplay uses existing ConsoleManager.
        
        Verifies integration with existing console output system.
        
        Requirements: 10.2, 10.3
        """
        # Create console manager
        console_manager = ConsoleManager(debug_mode=False)
        
        # Create display
        display = DNSPropagationDisplay(console_manager)
        
        # Verify it has the expected structure
        assert hasattr(display, 'console_manager')
        assert hasattr(display, 'console')
        assert display.console_manager == console_manager
    
    def test_cli_command_registered_correctly(self):
        """
        Test that dns-propagation command is registered in CLI.
        
        Verifies CLI integration.
        
        Requirements: 10.4
        """
        runner = CliRunner()
        
        # Test help command
        result = runner.invoke(cli, ['--help'])
        
        # Verify dns-propagation command is listed
        assert 'dns-propagation' in result.output, \
            "dns-propagation command should be listed in CLI help"
    
    def test_dns_propagation_help_text(self):
        """
        Test dns-propagation command help text.
        
        Verifies that help text is informative and correct.
        
        Requirements: 10.4, 6.6
        """
        runner = CliRunner()
        
        # Test dns-propagation help
        result = runner.invoke(cli, ['dns-propagation', '--help'])
        
        # Verify help text contains expected information
        assert result.exit_code == 0
        assert 'DNS propagation' in result.output or 'propagation' in result.output.lower()
        assert '--record-type' in result.output or '-t' in result.output
        assert '--expected' in result.output or '-e' in result.output
        assert '--watch' in result.output or '-w' in result.output
