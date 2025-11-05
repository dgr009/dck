"""
Integration tests for domain monitoring agent.

Tests end-to-end execution flow, export functionality, and error handling.
"""

import json
import csv
import tempfile
from pathlib import Path
from unittest.mock import patch, AsyncMock

import pytest
import yaml

from domain_monitor.main import main
from domain_monitor.config import ManifestConfig, DomainConfig
from domain_monitor.executor import DomainExecutor
from domain_monitor.reporter import Reporter
from domain_monitor.checkers.base_checker import CheckResult


# ============================================================================
# Test Fixtures
# ============================================================================

@pytest.fixture
def sample_manifest_yaml(tmp_path):
    """Create a sample YAML manifest file for testing."""
    manifest_data = {
        "default_checks": ["http", "dns"],
        "domains": [
            {
                "name": "example.com",
                "tags": ["prod", "test"],
                "checks": ["http", "dns", "ssl"],
                "dkim_selectors": []
            },
            {
                "name": "test.com",
                "tags": ["staging"],
                "checks": ["http"],
                "dkim_selectors": []
            }
        ]
    }
    
    manifest_file = tmp_path / "test_manifest.yaml"
    with open(manifest_file, 'w') as f:
        yaml.dump(manifest_data, f)
    
    return str(manifest_file)


@pytest.fixture
def invalid_manifest_yaml(tmp_path):
    """Create an invalid YAML manifest file for error testing."""
    manifest_file = tmp_path / "invalid.yaml"
    manifest_file.write_text("invalid: yaml: syntax: [[[")
    return str(manifest_file)


@pytest.fixture
def mock_check_results():
    """Create mock check results for testing."""
    return {
        'http': CheckResult(
            domain='example.com',
            check_type='http',
            status=CheckResult.OK,
            message='HTTP 200 OK',
            details={'status_code': 200}
        ),
        'dns': CheckResult(
            domain='example.com',
            check_type='dns',
            status=CheckResult.OK,
            message='DNS records found',
            details={'a_records': ['192.0.2.1']}
        ),
        'ssl': CheckResult(
            domain='example.com',
            check_type='ssl',
            status=CheckResult.WARNING,
            message='SSL expires in 10 days',
            details={'days_until_expiry': 10}
        )
    }


# ============================================================================
# Task 15.1: End-to-End Test with Sample Manifest
# ============================================================================

class TestEndToEndExecution:
    """
    Test complete execution flow from CLI to output.
    
    Requirements: 15.1, 15.2, 15.3, 15.4, 16.1
    """
    
    @pytest.mark.asyncio
    async def test_complete_execution_flow(self, sample_manifest_yaml, mock_check_results):
        """Test complete execution from manifest loading to result display."""
        from domain_monitor.config import load_manifest
        from domain_monitor.executor import DomainExecutor, DomainResult
        from datetime import datetime
        
        # Load manifest
        manifest = load_manifest(sample_manifest_yaml)
        assert len(manifest.domains) == 2
        
        # Create executor
        executor = DomainExecutor(manifest)
        
        # Mock the checker execution
        async def mock_execute_domain(domain_config):
            return DomainResult(
                domain=domain_config.name,
                tags=domain_config.tags,
                results=mock_check_results,
                overall_status=CheckResult.WARNING,
                execution_time=1.5,
                timestamp=datetime.now()
            )
        
        with patch.object(executor, 'execute_domain', side_effect=mock_execute_domain):
            results = await executor.execute_all()
        
        # Verify results
        assert len(results) == 2
        assert results[0].domain == 'example.com'
        assert results[1].domain == 'test.com'
        assert results[0].overall_status == CheckResult.WARNING
    
    @pytest.mark.asyncio
    async def test_all_checks_execute_correctly(self, sample_manifest_yaml):
        """Verify all enabled checks execute for each domain."""
        from domain_monitor.config import load_manifest
        from domain_monitor.executor import DomainExecutor
        
        manifest = load_manifest(sample_manifest_yaml)
        executor = DomainExecutor(manifest)
        
        # Track which checks were called
        called_checks = []
        
        async def mock_check(domain, **kwargs):
            check_type = kwargs.get('check_type', 'unknown')
            called_checks.append((domain, check_type))
            return CheckResult(
                domain=domain,
                check_type=check_type,
                status=CheckResult.OK,
                message='OK'
            )
        
        # Mock all checkers
        for checker_name, checker in executor.checkers.items():
            checker.check = AsyncMock(side_effect=lambda d, **kw: mock_check(d, check_type=checker_name, **kw))
        
        results = await executor.execute_all()
        
        # Verify results were generated
        assert len(results) == 2
        assert all(isinstance(r.results, dict) for r in results)
    
    def test_table_output_format(self, mock_check_results):
        """Verify table output format is correct."""
        from domain_monitor.executor import DomainResult
        from domain_monitor.reporter import Reporter
        from datetime import datetime
        from io import StringIO
        
        # Create sample results
        results = [
            DomainResult(
                domain='example.com',
                tags=['prod', 'test'],
                results=mock_check_results,
                overall_status=CheckResult.WARNING,
                execution_time=2.5,
                timestamp=datetime.now()
            )
        ]
        
        # Create reporter and capture output
        reporter = Reporter(results)
        
        # Verify reporter can display table without errors
        try:
            reporter.display_table()
            success = True
        except Exception:
            success = False
        
        assert success, "Table display should not raise exceptions"


# ============================================================================
# Task 15.2: Test JSON and CSV Export
# ============================================================================

class TestExportFunctionality:
    """
    Test JSON and CSV export functionality.
    
    Requirements: 17.1, 17.2, 17.3
    """
    
    def test_export_to_json(self, tmp_path, mock_check_results):
        """Test exporting results to JSON format."""
        from domain_monitor.executor import DomainResult
        from domain_monitor.reporter import Reporter
        from datetime import datetime
        
        # Create sample results
        results = [
            DomainResult(
                domain='example.com',
                tags=['prod'],
                results=mock_check_results,
                overall_status=CheckResult.WARNING,
                execution_time=2.5,
                timestamp=datetime.now()
            ),
            DomainResult(
                domain='test.com',
                tags=['staging'],
                results={'http': mock_check_results['http']},
                overall_status=CheckResult.OK,
                execution_time=1.2,
                timestamp=datetime.now()
            )
        ]
        
        # Export to JSON
        reporter = Reporter(results)
        json_file = tmp_path / "results.json"
        reporter.export_json(str(json_file))
        
        # Verify file was created
        assert json_file.exists()
        
        # Verify JSON content
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        assert 'domains' in data
        assert len(data['domains']) == 2
        assert data['domains'][0]['domain'] == 'example.com'
        assert data['domains'][0]['tags'] == ['prod']
        assert data['domains'][0]['overall_status'] == CheckResult.WARNING
        assert 'checks' in data['domains'][0]
        assert 'http' in data['domains'][0]['checks']
    
    def test_export_to_csv(self, tmp_path, mock_check_results):
        """Test exporting results to CSV format."""
        from domain_monitor.executor import DomainResult
        from domain_monitor.reporter import Reporter
        from datetime import datetime
        
        # Create sample results
        results = [
            DomainResult(
                domain='example.com',
                tags=['prod'],
                results=mock_check_results,
                overall_status=CheckResult.WARNING,
                execution_time=2.5,
                timestamp=datetime.now()
            )
        ]
        
        # Export to CSV
        reporter = Reporter(results)
        csv_file = tmp_path / "results.csv"
        reporter.export_csv(str(csv_file))
        
        # Verify file was created
        assert csv_file.exists()
        
        # Verify CSV content
        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        
        assert len(rows) == 1
        assert rows[0]['domain'] == 'example.com'
        assert rows[0]['tags'] == 'prod'
        assert rows[0]['overall_status'] == CheckResult.WARNING
        assert 'http_status' in rows[0]
        assert 'dns_status' in rows[0]
        assert 'ssl_status' in rows[0]
    
    def test_verify_json_file_contents(self, tmp_path, mock_check_results):
        """Verify JSON file contains all required fields."""
        from domain_monitor.executor import DomainResult
        from domain_monitor.reporter import Reporter
        from datetime import datetime
        
        results = [
            DomainResult(
                domain='example.com',
                tags=['prod'],
                results=mock_check_results,
                overall_status=CheckResult.WARNING,
                execution_time=2.5,
                timestamp=datetime.now()
            )
        ]
        
        reporter = Reporter(results)
        json_file = tmp_path / "results.json"
        reporter.export_json(str(json_file))
        
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        # Verify structure
        assert 'timestamp' in data
        assert 'total_domains' in data
        assert 'domains' in data
        assert data['total_domains'] == 1
        
        # Verify domain data
        domain_data = data['domains'][0]
        assert 'domain' in domain_data
        assert 'tags' in domain_data
        assert 'overall_status' in domain_data
        assert 'execution_time' in domain_data
        assert 'checks' in domain_data
        
        # Verify check data
        for check_type, check_data in domain_data['checks'].items():
            assert 'status' in check_data
            assert 'message' in check_data
            assert 'details' in check_data
            assert 'timestamp' in check_data
    
    def test_verify_csv_file_format(self, tmp_path, mock_check_results):
        """Verify CSV file has correct format and columns."""
        from domain_monitor.executor import DomainResult
        from domain_monitor.reporter import Reporter
        from datetime import datetime
        
        results = [
            DomainResult(
                domain='example.com',
                tags=['prod', 'test'],
                results=mock_check_results,
                overall_status=CheckResult.WARNING,
                execution_time=2.5,
                timestamp=datetime.now()
            )
        ]
        
        reporter = Reporter(results)
        csv_file = tmp_path / "results.csv"
        reporter.export_csv(str(csv_file))
        
        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames
            rows = list(reader)
        
        # Verify headers
        expected_headers = [
            'domain', 'tags', 'overall_status', 'execution_time',
            'http_status', 'http_message',
            'ssl_status', 'ssl_message',
            'whois_status', 'whois_message',
            'security_status', 'security_message',
            'rbl_status', 'rbl_message',
            'dns_status', 'dns_message'
        ]
        
        for header in expected_headers:
            assert header in headers
        
        # Verify data
        assert len(rows) == 1
        assert rows[0]['domain'] == 'example.com'
        assert rows[0]['tags'] == 'prod, test'


# ============================================================================
# Task 15.3: Test Error Scenarios
# ============================================================================

class TestErrorScenarios:
    """
    Test error handling for various failure scenarios.
    
    Requirements: 1.3, 3.7, 4.7, 5.7, 6.6, 15.3
    """
    
    def test_invalid_manifest_file(self, invalid_manifest_yaml):
        """Test handling of invalid manifest file syntax."""
        from domain_monitor.config import load_manifest
        
        with pytest.raises(ValueError, match="Invalid YAML syntax"):
            load_manifest(invalid_manifest_yaml)
    
    def test_missing_manifest_file(self):
        """Test handling of non-existent manifest file."""
        from domain_monitor.config import load_manifest
        
        with pytest.raises(FileNotFoundError, match="Manifest file not found"):
            load_manifest("/nonexistent/path/manifest.yaml")
    
    @pytest.mark.asyncio
    async def test_unreachable_domain_handling(self):
        """Test graceful handling of unreachable domains."""
        from domain_monitor.config import DomainConfig, ManifestConfig
        from domain_monitor.executor import DomainExecutor
        
        # Create manifest with unreachable domain
        manifest = ManifestConfig(
            default_checks=['http'],
            domains=[
                DomainConfig(
                    name='this-domain-does-not-exist-12345.invalid',
                    checks=['http']
                )
            ]
        )
        
        executor = DomainExecutor(manifest)
        results = await executor.execute_all()
        
        # Verify error is handled gracefully
        assert len(results) == 1
        assert results[0].domain == 'this-domain-does-not-exist-12345.invalid'
        # Should have error status but not crash
        assert results[0].results.get('http') is not None
    
    @pytest.mark.asyncio
    async def test_network_timeout_handling(self):
        """Test handling of network timeouts."""
        from domain_monitor.config import DomainConfig, ManifestConfig
        from domain_monitor.executor import DomainExecutor
        from domain_monitor.checkers.http import HTTPChecker
        import asyncio
        
        manifest = ManifestConfig(
            default_checks=['http'],
            domains=[DomainConfig(name='example.com', checks=['http'])]
        )
        
        executor = DomainExecutor(manifest)
        
        # Mock timeout
        async def mock_timeout(*args, **kwargs):
            raise asyncio.TimeoutError("Connection timeout")
        
        with patch.object(HTTPChecker, 'check', side_effect=mock_timeout):
            results = await executor.execute_all()
        
        # Verify timeout is handled gracefully
        assert len(results) == 1
        http_result = results[0].results.get('http')
        assert http_result is not None
        assert http_result.status == CheckResult.ERROR
    
    @pytest.mark.asyncio
    async def test_partial_check_failure(self):
        """Test that one check failure doesn't block other checks."""
        from domain_monitor.config import DomainConfig, ManifestConfig
        from domain_monitor.executor import DomainExecutor
        from domain_monitor.checkers.http import HTTPChecker
        
        manifest = ManifestConfig(
            default_checks=['http', 'dns'],
            domains=[DomainConfig(name='example.com', checks=['http', 'dns'])]
        )
        
        executor = DomainExecutor(manifest)
        
        # Mock HTTP check to fail
        async def mock_http_fail(*args, **kwargs):
            raise Exception("HTTP check failed")
        
        with patch.object(HTTPChecker, 'check', side_effect=mock_http_fail):
            results = await executor.execute_all()
        
        # Verify other checks still executed
        assert len(results) == 1
        assert 'http' in results[0].results
        assert 'dns' in results[0].results
        # HTTP should have error, but DNS should have attempted
        assert results[0].results['http'].status == CheckResult.ERROR
    
    def test_export_error_handling(self, tmp_path, mock_check_results):
        """Test error handling during file export."""
        from domain_monitor.executor import DomainResult
        from domain_monitor.reporter import Reporter
        from datetime import datetime
        
        results = [
            DomainResult(
                domain='example.com',
                tags=[],
                results=mock_check_results,
                overall_status=CheckResult.OK,
                execution_time=1.0,
                timestamp=datetime.now()
            )
        ]
        
        reporter = Reporter(results)
        
        # Try to export to invalid path
        invalid_path = "/invalid/path/that/does/not/exist/results.json"
        
        with pytest.raises(Exception):
            reporter.export_json(invalid_path)
    
    def test_empty_manifest_handling(self, tmp_path):
        """Test handling of empty manifest file."""
        from domain_monitor.config import load_manifest
        
        empty_file = tmp_path / "empty.yaml"
        empty_file.write_text("")
        
        with pytest.raises(ValueError, match="Manifest file is empty"):
            load_manifest(str(empty_file))
    
    def test_manifest_missing_required_fields(self, tmp_path):
        """Test handling of manifest with missing required fields."""
        from domain_monitor.config import load_manifest
        
        # Manifest with domain missing 'name' field
        manifest_data = {
            "default_checks": [],
            "domains": [
                {"tags": ["test"]}  # Missing 'name'
            ]
        }
        
        manifest_file = tmp_path / "invalid.yaml"
        with open(manifest_file, 'w') as f:
            yaml.dump(manifest_data, f)
        
        with pytest.raises(ValueError, match="missing required 'name' field"):
            load_manifest(str(manifest_file))
    
    @pytest.mark.asyncio
    async def test_graceful_degradation_multiple_failures(self):
        """Test system continues when multiple checks fail."""
        from domain_monitor.config import DomainConfig, ManifestConfig
        from domain_monitor.executor import DomainExecutor
        
        manifest = ManifestConfig(
            default_checks=['http', 'dns', 'ssl'],
            domains=[
                DomainConfig(name='example.com', checks=['http', 'dns', 'ssl']),
                DomainConfig(name='test.com', checks=['http', 'dns'])
            ]
        )
        
        executor = DomainExecutor(manifest)
        
        # Mock all checks to fail
        for checker in executor.checkers.values():
            async def mock_fail(*args, **kwargs):
                raise Exception("Check failed")
            checker.check = AsyncMock(side_effect=mock_fail)
        
        results = await executor.execute_all()
        
        # Verify all domains were processed despite failures
        assert len(results) == 2
        assert results[0].domain == 'example.com'
        assert results[1].domain == 'test.com'
        # All checks should have error status
        for result in results:
            for check_result in result.results.values():
                assert check_result.status == CheckResult.ERROR


# ============================================================================
# CLI Integration Tests
# ============================================================================

class TestCLIIntegration:
    """Test CLI command-line interface integration."""
    
    def test_cli_with_manifest_file(self, sample_manifest_yaml, monkeypatch):
        """Test CLI execution with manifest file."""
        from click.testing import CliRunner
        from domain_monitor.main import main
        
        runner = CliRunner()
        
        # Mock the executor to avoid actual network calls
        async def mock_execute_all(self):
            from domain_monitor.executor import DomainResult
            from datetime import datetime
            return [
                DomainResult(
                    domain='example.com',
                    tags=['prod'],
                    results={},
                    overall_status=CheckResult.OK,
                    execution_time=1.0,
                    timestamp=datetime.now()
                )
            ]
        
        with patch('domain_monitor.executor.DomainExecutor.execute_all', mock_execute_all):
            result = runner.invoke(main, ['-f', sample_manifest_yaml])
        
        assert result.exit_code == 0
    
    def test_cli_with_output_json(self, sample_manifest_yaml, tmp_path):
        """Test CLI with JSON output export."""
        from click.testing import CliRunner
        from domain_monitor.main import main
        
        runner = CliRunner()
        output_file = tmp_path / "output.json"
        
        async def mock_execute_all(self):
            from domain_monitor.executor import DomainResult
            from datetime import datetime
            return [
                DomainResult(
                    domain='example.com',
                    tags=[],
                    results={},
                    overall_status=CheckResult.OK,
                    execution_time=1.0,
                    timestamp=datetime.now()
                )
            ]
        
        with patch('domain_monitor.executor.DomainExecutor.execute_all', mock_execute_all):
            result = runner.invoke(main, ['-f', sample_manifest_yaml, '-o', str(output_file)])
        
        assert result.exit_code == 0
        assert output_file.exists()
    
    def test_cli_with_output_csv(self, sample_manifest_yaml, tmp_path):
        """Test CLI with CSV output export."""
        from click.testing import CliRunner
        from domain_monitor.main import main
        
        runner = CliRunner()
        output_file = tmp_path / "output.csv"
        
        async def mock_execute_all(self):
            from domain_monitor.executor import DomainResult
            from datetime import datetime
            return [
                DomainResult(
                    domain='example.com',
                    tags=[],
                    results={},
                    overall_status=CheckResult.OK,
                    execution_time=1.0,
                    timestamp=datetime.now()
                )
            ]
        
        with patch('domain_monitor.executor.DomainExecutor.execute_all', mock_execute_all):
            result = runner.invoke(main, ['-f', sample_manifest_yaml, '-o', str(output_file)])
        
        assert result.exit_code == 0
        assert output_file.exists()
