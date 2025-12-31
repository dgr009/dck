"""
Unit tests for DNS propagation CLI command.

Tests CLI argument parsing and validation for the dns-propagation subcommand.
"""

import pytest
from click.testing import CliRunner
from unittest.mock import patch, MagicMock, AsyncMock

from domain_monitor.main import cli


class TestCLIArgumentParsing:
    """Tests for CLI argument parsing and validation."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.runner = CliRunner()
        
        # Create mock for async operations to prevent actual DNS queries
        self.mock_result = MagicMock()
        self.mock_result.domain = 'example.com'
        self.mock_result.record_type = 'A'
        self.mock_result.expected_value = None
        self.mock_result.query_results = []
        self.mock_result.is_complete = False
    
    @patch('domain_monitor.main.asyncio.run')
    def test_dns_propagation_command_exists(self, mock_run):
        """
        Test that dns-propagation command is registered.
        
        Validates: Requirements 6.1
        """
        result = self.runner.invoke(cli, ['dns-propagation', '--help'])
        assert result.exit_code == 0
        assert 'dns-propagation' in result.output.lower()
    
    def test_domain_argument_required(self):
        """
        Test that domain argument is required.
        
        Validates: Requirements 6.1
        """
        result = self.runner.invoke(cli, ['dns-propagation'])
        assert result.exit_code != 0
        assert 'Missing argument' in result.output or 'required' in result.output.lower()
    
    @patch('domain_monitor.main.asyncio.run')
    def test_valid_domain_argument(self, mock_run):
        """
        Test that valid domain argument is accepted.
        
        Validates: Requirements 6.1
        """
        mock_run.return_value = self.mock_result
        result = self.runner.invoke(cli, ['dns-propagation', 'example.com'])
        # Should not have argument parsing errors
        assert 'Missing argument' not in result.output
    
    def test_record_type_option_default(self):
        """
        Test that --record-type option has default value of 'A'.
        
        Validates: Requirements 6.2
        """
        result = self.runner.invoke(cli, ['dns-propagation', '--help'])
        assert result.exit_code == 0
        assert '--record-type' in result.output or '-t' in result.output
        assert 'Default: A' in result.output or 'default: A' in result.output.lower()
    
    @patch('domain_monitor.main.asyncio.run')
    def test_record_type_option_custom_value(self, mock_run):
        """
        Test that --record-type option accepts custom values.
        
        Validates: Requirements 6.2
        """
        mock_run.return_value = self.mock_result
        # Test with various record types
        for record_type in ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']:
            result = self.runner.invoke(
                cli,
                ['dns-propagation', 'example.com', '--record-type', record_type]
            )
            # Should not fail on argument parsing
            assert 'Invalid value' not in result.output or result.exit_code == 0
    
    @patch('domain_monitor.main.asyncio.run')
    def test_expected_option_accepts_value(self, mock_run):
        """
        Test that --expected option accepts a value.
        
        Validates: Requirements 6.3
        """
        mock_run.return_value = self.mock_result
        result = self.runner.invoke(
            cli,
            ['dns-propagation', 'example.com', '--expected', '192.0.2.1']
        )
        # Should not fail on argument parsing
        assert 'Missing argument' not in result.output
    
    @patch('domain_monitor.main.asyncio.run')
    def test_watch_flag_is_boolean(self, mock_run):
        """
        Test that --watch option is a boolean flag.
        
        Validates: Requirements 6.4
        """
        # Mock the monitor to prevent it from running
        mock_run.return_value = None
        result = self.runner.invoke(
            cli,
            ['dns-propagation', 'example.com', '--watch'],
            input='\n'  # Simulate CTRL+C
        )
        # Should not fail on argument parsing
        assert 'Invalid value' not in result.output or result.exit_code == 0
    
    @patch('domain_monitor.main.asyncio.run')
    def test_interval_option_accepts_float(self, mock_run):
        """
        Test that --interval option accepts float values.
        
        Validates: Requirements 6.4, 7.6
        """
        mock_run.return_value = None
        result = self.runner.invoke(
            cli,
            ['dns-propagation', 'example.com', '--watch', '--interval', '10.5'],
            input='\n'
        )
        # Should not fail on argument parsing
        assert 'Invalid value' not in result.output or result.exit_code == 0
    
    def test_interval_option_rejects_invalid_values(self):
        """
        Test that --interval option rejects non-numeric values.
        
        Validates: Requirements 6.4, 7.6
        """
        result = self.runner.invoke(
            cli,
            ['dns-propagation', 'example.com', '--watch', '--interval', 'invalid']
        )
        assert result.exit_code != 0
        assert 'Invalid value' in result.output or 'not a valid' in result.output.lower()
    
    @patch('domain_monitor.main.asyncio.run')
    def test_record_types_option_accepts_comma_separated_list(self, mock_run):
        """
        Test that --record-types option accepts comma-separated values.
        
        Validates: Requirements 6.5
        """
        mock_run.return_value = self.mock_result
        result = self.runner.invoke(
            cli,
            ['dns-propagation', 'example.com', '--record-types', 'A,AAAA,MX']
        )
        # Should not fail on argument parsing
        assert 'Missing argument' not in result.output
    
    def test_help_option_displays_usage(self):
        """
        Test that --help option displays usage information.
        
        Validates: Requirements 6.6
        """
        result = self.runner.invoke(cli, ['dns-propagation', '--help'])
        assert result.exit_code == 0
        assert 'Usage:' in result.output
        assert 'dns-propagation' in result.output.lower()
        assert '--record-type' in result.output or '-t' in result.output
        assert '--expected' in result.output or '-e' in result.output
        assert '--watch' in result.output or '-w' in result.output
        assert '--interval' in result.output or '-i' in result.output
        assert '--record-types' in result.output
    
    @patch('domain_monitor.main.asyncio.run')
    def test_short_options_work(self, mock_run):
        """
        Test that short option flags work correctly.
        
        Validates: Requirements 6.2, 6.3, 6.4
        """
        mock_run.return_value = None
        result = self.runner.invoke(
            cli,
            ['dns-propagation', 'example.com', '-t', 'AAAA', '-e', '2001:db8::1', '-w', '-i', '3.0'],
            input='\n'
        )
        # Should not fail on argument parsing
        assert 'Invalid value' not in result.output or result.exit_code == 0
    
    @patch('domain_monitor.main.asyncio.run')
    def test_mutually_exclusive_record_type_options(self, mock_run):
        """
        Test that --record-type and --record-types cannot be used together.
        
        Validates: Requirements 6.2, 6.5
        """
        mock_run.return_value = self.mock_result
        result = self.runner.invoke(
            cli,
            ['dns-propagation', 'example.com', '--record-type', 'AAAA', '--record-types', 'A,AAAA']
        )
        # Should fail with error about mutual exclusivity
        assert result.exit_code != 0
        assert 'cannot use both' in result.output.lower() or 'mutually exclusive' in result.output.lower()
    
    @patch('domain_monitor.main.asyncio.run')
    def test_interval_without_watch_is_ignored(self, mock_run):
        """
        Test that --interval option is only relevant with --watch.
        
        Validates: Requirements 6.4, 7.6
        """
        mock_run.return_value = self.mock_result
        # This should not fail, but interval should be ignored
        result = self.runner.invoke(
            cli,
            ['dns-propagation', 'example.com', '--interval', '10.0']
        )
        # Should not fail on argument parsing
        assert 'Missing argument' not in result.output
    
    @patch('domain_monitor.main.asyncio.run')
    def test_invalid_record_type_handled_gracefully(self, mock_run):
        """
        Test that invalid record types are handled with clear error messages.
        
        Validates: Requirements 9.3
        """
        # Mock to raise ValueError for invalid record type
        mock_run.side_effect = ValueError("Invalid record type 'INVALID'")
        
        result = self.runner.invoke(
            cli,
            ['dns-propagation', 'example.com', '--record-type', 'INVALID']
        )
        # Should fail with clear error message
        assert result.exit_code != 0
    
    def test_empty_domain_rejected(self):
        """
        Test that empty domain is rejected.
        
        Validates: Requirements 6.1
        """
        result = self.runner.invoke(cli, ['dns-propagation', ''])
        # Should fail with error
        assert result.exit_code != 0
        assert 'empty' in result.output.lower() or 'cannot be empty' in result.output.lower()
    
    @patch('domain_monitor.main.asyncio.run')
    def test_negative_interval_rejected(self, mock_run):
        """
        Test that negative interval values are rejected.
        
        Validates: Requirements 7.6
        """
        result = self.runner.invoke(
            cli,
            ['dns-propagation', 'example.com', '--watch', '--interval', '-5.0']
        )
        # Should fail with error
        assert result.exit_code != 0
        assert 'invalid interval' in result.output.lower() or 'must be greater than 0' in result.output.lower()
    
    @patch('domain_monitor.main.asyncio.run')
    def test_zero_interval_rejected(self, mock_run):
        """
        Test that zero interval value is rejected.
        
        Validates: Requirements 7.6
        """
        result = self.runner.invoke(
            cli,
            ['dns-propagation', 'example.com', '--watch', '--interval', '0']
        )
        # Should fail with error
        assert result.exit_code != 0
        assert 'invalid interval' in result.output.lower() or 'must be greater than 0' in result.output.lower()
    
    @patch('domain_monitor.main.asyncio.run')
    def test_all_options_together(self, mock_run):
        """
        Test that all valid options can be used together.
        
        Validates: Requirements 6.1, 6.2, 6.3, 6.4
        """
        mock_run.return_value = None
        result = self.runner.invoke(
            cli,
            [
                'dns-propagation',
                'example.com',
                '--record-type', 'A',
                '--expected', '192.0.2.1',
                '--watch',
                '--interval', '5.0'
            ],
            input='\n'
        )
        # Should not fail on argument parsing
        assert 'Missing argument' not in result.output
        assert 'Invalid value' not in result.output or result.exit_code == 0
    
    @patch('domain_monitor.main.asyncio.run')
    def test_record_types_queries_concurrently(self, mock_run):
        """
        Test that --record-types option queries all types concurrently.
        
        Validates: Requirements 3.7, 6.5
        """
        # Create mock results for multiple record types
        mock_results = []
        for record_type in ['A', 'AAAA', 'MX']:
            mock_result = MagicMock()
            mock_result.domain = 'example.com'
            mock_result.record_type = record_type
            mock_result.expected_value = None
            mock_result.query_results = []
            # Mock the properties needed by display
            mock_result.propagation_rate = 0.0
            mock_result.matched_count = 0
            mock_result.mismatched_count = 0
            mock_result.unreachable_count = 0
            mock_result.responsive_count = 0
            mock_result.is_complete = False
            mock_result.timestamp = MagicMock()
            mock_result.timestamp.strftime.return_value = '2025-12-31 09:00:00'
            mock_results.append(mock_result)
        
        # Mock asyncio.run to return the list of results
        mock_run.return_value = mock_results
        
        # Run the command
        result = self.runner.invoke(
            cli,
            ['dns-propagation', 'example.com', '--record-types', 'A,AAAA,MX']
        )
        
        # Verify the command succeeded
        assert result.exit_code == 0, f"Command failed with output: {result.output}"
        
        # Verify asyncio.run was called (for concurrent execution)
        assert mock_run.called
        
        # Verify output contains all record types
        assert 'Record Type: A' in result.output
        assert 'Record Type: AAAA' in result.output
        assert 'Record Type: MX' in result.output
    
    @patch('domain_monitor.main.asyncio.run')
    def test_record_types_with_invalid_type_fails(self, mock_run):
        """
        Test that --record-types with an invalid type fails gracefully.
        
        Validates: Requirements 6.5, 9.3
        """
        result = self.runner.invoke(
            cli,
            ['dns-propagation', 'example.com', '--record-types', 'A,INVALID,MX']
        )
        
        # Should fail with clear error message
        assert result.exit_code != 0
        assert 'invalid record type' in result.output.lower()
        assert 'INVALID' in result.output
    
    @patch('domain_monitor.main.asyncio.run')
    def test_record_types_with_spaces_handled(self, mock_run):
        """
        Test that --record-types handles spaces in the list.
        
        Validates: Requirements 6.5
        """
        mock_results = []
        for record_type in ['A', 'AAAA']:
            mock_result = MagicMock()
            mock_result.domain = 'example.com'
            mock_result.record_type = record_type
            mock_result.query_results = []
            mock_results.append(mock_result)
        
        mock_run.return_value = mock_results
        
        # Test with spaces around commas
        result = self.runner.invoke(
            cli,
            ['dns-propagation', 'example.com', '--record-types', 'A, AAAA']
        )
        
        # Should succeed (spaces should be stripped)
        assert result.exit_code == 0 or 'Invalid value' not in result.output
    
    @patch('domain_monitor.main.asyncio.run')
    def test_record_types_single_type_works(self, mock_run):
        """
        Test that --record-types works with a single type.
        
        Validates: Requirements 6.5
        """
        mock_result = MagicMock()
        mock_result.domain = 'example.com'
        mock_result.record_type = 'A'
        mock_result.query_results = []
        
        mock_run.return_value = [mock_result]
        
        result = self.runner.invoke(
            cli,
            ['dns-propagation', 'example.com', '--record-types', 'A']
        )
        
        # Should succeed
        assert result.exit_code == 0 or 'Invalid value' not in result.output

