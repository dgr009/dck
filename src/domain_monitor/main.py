"""
CLI entry point for domain monitoring agent.

Provides command-line interface for running domain checks with various options
including manifest file specification, ad-hoc domain checks, output export,
and logging configuration.
"""

import asyncio
import logging
import sys
from pathlib import Path
from typing import Optional

import click

from .config import (
    ManifestConfig,
    DomainConfig,
    load_manifest,
    load_endpoints_config,
    get_default_manifest_path,
    VALID_CHECK_TYPES
)
from .executor import DomainExecutor
from .reporter import Reporter
from .console.output import ConsoleManager
from .live_monitor import LiveMonitor


# Configure module logger
logger = logging.getLogger(__name__)


def setup_logging(log_level: str, debug_mode: bool = False) -> None:
    """
    Configure logging with specified level and debug mode.
    
    Sets up both file and console logging with appropriate formats.
    In normal mode, only ERROR and CRITICAL logs are shown on console.
    In debug mode, all logs (INFO, WARNING, DEBUG, ERROR, CRITICAL) are shown.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        debug_mode: If True, display all logs to console; if False, only ERROR/CRITICAL
        
    Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 20.1, 20.2, 20.3, 20.4, 20.5
    """
    # Convert string level to logging constant
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Set up file handler - always logs everything (Requirements: 1.4, 20.1)
    file_handler = logging.FileHandler('domain-monitor.log', encoding='utf-8')
    file_handler.setLevel(numeric_level)
    file_handler.setFormatter(formatter)
    
    # Set up console handler based on debug mode (Requirements: 1.1, 1.2, 1.3, 1.5)
    console_handler = logging.StreamHandler()
    if debug_mode:
        # Debug mode: show all logs to console (Requirements: 1.2)
        console_handler.setLevel(numeric_level)
        console_handler.setFormatter(formatter)
    else:
        # Normal mode: suppress all console logs (Requirements: 1.1, 1.3, 1.5)
        console_handler.setLevel(logging.CRITICAL + 1)  # Suppress all logs
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    # Log startup message (Requirements: 20.5)
    logger.info(f"Logging initialized at {log_level} level (debug_mode={debug_mode})")


def resolve_manifest_file(file_path: Optional[str]) -> str:
    """
    Resolve manifest file path.
    
    If file_path is provided, use it. Otherwise, search for default
    manifest files (domains.yaml or domains.json).
    
    Args:
        file_path: Optional path to manifest file
        
    Returns:
        Path to manifest file
        
    Raises:
        click.ClickException: If no manifest file found
        
    Requirements: 18.2, 18.3, 18.4
    """
    if file_path:
        # Use provided file path
        return file_path
    
    # Search for default manifest file (Requirements: 18.2, 18.3)
    default_path = get_default_manifest_path()
    
    if default_path is None:
        # No manifest file found (Requirements: 18.4)
        raise click.ClickException(
            "No manifest file found. Please either:\n"
            "  1. Create a 'domains.yaml' or 'domains.json' file in the current directory, or\n"
            "  2. Specify a manifest file using the -f/--file option\n\n"
            "Example: domain-monitor -f /path/to/manifest.yaml"
        )
    
    return default_path


def create_adhoc_manifest(domain: str) -> ManifestConfig:
    """
    Create temporary manifest for ad-hoc domain check.
    
    Creates a ManifestConfig with a single domain and all default checks enabled.
    
    Args:
        domain: Domain name to check
        
    Returns:
        ManifestConfig with single domain
        
    Requirements: 19.1, 19.2
    """
    # Apply all default checks (Requirements: 19.2)
    default_checks = list(VALID_CHECK_TYPES)
    
    domain_config = DomainConfig(
        name=domain,
        tags=['ad-hoc'],
        checks=default_checks,
        dkim_selectors=[]
    )
    
    return ManifestConfig(
        default_checks=default_checks,
        domains=[domain_config]
    )


@click.group()
def cli() -> None:
    """
    Domain & NetUtils Monitoring Agent
    
    Monitor multiple domains for WHOIS expiration, SSL certificates, HTTP status,
    DNS records, security configurations, and RBL listings.
    """
    pass


@cli.command(name='check')
@click.option(
    '-f', '--file',
    type=click.Path(exists=True),
    help='Path to manifest file (YAML/JSON)'
)
@click.option(
    '-d', '--domain',
    type=str,
    help='Single domain to check (ad-hoc mode)'
)
@click.option(
    '-o', '--output',
    type=click.Path(),
    help='Output file path (.json or .csv)'
)
@click.option(
    '--log-level',
    type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR'], case_sensitive=False),
    default='INFO',
    help='Logging level (default: INFO)'
)
@click.option(
    '--debug',
    is_flag=True,
    default=False,
    help='Enable debug mode with verbose console output'
)
@click.option(
    '--view',
    type=click.Choice(['summary', 'detailed', 'table'], case_sensitive=False),
    default='table',
    help='Display view mode (default: table)'
)
def check_command(
    file: Optional[str],
    domain: Optional[str],
    output: Optional[str],
    log_level: str,
    debug: bool,
    view: str
) -> None:
    """
    Run domain checks and display results.
    
    Monitor multiple domains for WHOIS expiration, SSL certificates, HTTP status,
    DNS records, security configurations, and RBL listings.
    
    Examples:
    
        # Use default manifest file (domains.yaml or domains.json)
        domain-monitor check
        
        # Specify manifest file
        domain-monitor check -f /path/to/domains.yaml
        
        # Check single domain ad-hoc
        domain-monitor check -d example.com
        
        # Export results to JSON
        domain-monitor check -f domains.yaml -o report.json
        
        # Enable debug logging
        domain-monitor check --log-level DEBUG
        
        # Enable debug mode with verbose console output
        domain-monitor check --debug
    
    Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 18.1, 19.1, 17.1, 17.2, 20.2
    """
    # Configure logging first (Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 20.2, 20.3)
    setup_logging(log_level, debug_mode=debug)
    
    # Create ConsoleManager instance (Requirements: 1.1, 1.2, 9.1)
    console_manager = ConsoleManager(debug_mode=debug)
    
    try:
        # Validate mutual exclusivity of -f and -d flags (Requirements: 19.3)
        if file and domain:
            raise click.ClickException(
                "Cannot use both -f/--file and -d/--domain options together. "
                "Please specify only one."
            )
        
        # Load or create manifest configuration
        if domain:
            # Ad-hoc domain check mode (Requirements: 19.1)
            logger.info(f"Running ad-hoc check for domain: {domain}")
            manifest = create_adhoc_manifest(domain)
            manifest_path = f"ad-hoc: {domain}"
        else:
            # Load manifest from file (Requirements: 18.2, 18.3, 18.4)
            manifest_path = resolve_manifest_file(file)
            logger.info(f"Loading manifest from: {manifest_path}")
            manifest = load_manifest(manifest_path)
        
        # Get enabled check types for banner
        enabled_checks = set()
        for domain_config in manifest.domains:
            enabled_checks.update(domain_config.checks)
        
        # Display application banner (Requirements: 9.1, 9.2, 9.3, 9.4, 9.5)
        console_manager.print_banner(
            version="0.1.0",
            manifest_path=manifest_path,
            domain_count=len(manifest.domains),
            check_types=sorted(enabled_checks)
        )
        
        # Create executor and run checks (Requirements: 15.1, 15.2)
        logger.info(f"Starting checks for {len(manifest.domains)} domain(s)")
        
        executor = DomainExecutor(manifest, console_manager=console_manager)
        
        # Run async execution
        results = asyncio.run(executor.execute_all())
        
        # Create reporter and display results (Requirements: 3.1)
        reporter = Reporter(results, console_manager=console_manager)
        
        # Display results based on view mode
        if view == 'summary':
            reporter.display_summary()
        elif view == 'detailed':
            reporter.display_detailed()
        else:  # table
            reporter.display_table()
        
        # Export to file if requested (Requirements: 17.1, 17.2)
        if output:
            output_path = Path(output)
            suffix = output_path.suffix.lower()
            
            if suffix == '.json':
                reporter.export_json(output)
            elif suffix == '.csv':
                reporter.export_csv(output)
            else:
                raise click.ClickException(
                    f"Unsupported output format: {suffix}. "
                    "Please use .json or .csv extension."
                )
        
        logger.info("Monitoring completed successfully")
        
    except click.ClickException:
        # Re-raise click exceptions (they handle their own display)
        raise
        
    except FileNotFoundError as e:
        # Handle file not found errors with context (Requirements: 7.1, 7.2, 7.5)
        logger.error(f"File not found: {str(e)}", exc_info=True)
        
        try:
            console_manager.print_error(
                f"File not found: {str(e)}",
                details={'error_type': 'FileNotFoundError'},
                exception=e
            )
        except:
            click.echo(f"\n{click.style('✗', fg='red')} File not found: {str(e)}", err=True)
        
        sys.exit(1)
        
    except Exception as e:
        # Handle all other errors with user-friendly messages (Requirements: 7.1, 7.2, 7.3)
        error_msg = str(e) if str(e) else f"{type(e).__name__} occurred"
        logger.error(f"Unexpected error: {error_msg}", exc_info=True)
        
        # Use ConsoleManager for error display with context (Requirements: 7.1, 7.2, 7.3)
        try:
            console_manager.print_error(
                error_msg,
                details={
                    'error_type': type(e).__name__,
                    'log_file': 'domain-monitor.log'
                },
                exception=e
            )
            console_manager.print_info("Check 'domain-monitor.log' for detailed error information.")
        except:
            # Fallback to click if ConsoleManager not available
            click.echo(f"\n{click.style('✗', fg='red')} {error_msg}", err=True)
            click.echo(f"\nCheck 'domain-monitor.log' for detailed error information.", err=True)
        
        sys.exit(1)


@cli.command(name='watch')
@click.option(
    '-f', '--file',
    type=click.Path(exists=True),
    help='Path to endpoint configuration file (YAML/JSON)'
)
@click.option(
    '--interval',
    type=float,
    default=1.0,
    help='Check interval in seconds (default: 1.0)'
)
@click.option(
    '--log-file',
    type=click.Path(),
    default='logs/live-monitor.log',
    help='Path to status change log file'
)
def watch_command(
    file: Optional[str],
    interval: float,
    log_file: str
) -> None:
    """
    Live monitoring mode - continuously check endpoint status.
    
    Displays a live-updating table showing real-time endpoint health with support
    for custom HTTP methods, headers, and request bodies. Logs status changes to
    file for historical analysis.
    
    The endpoint configuration file should define endpoints with the following structure:
    
    \b
    endpoints:
      - name: example.com
        url: https://example.com
        method: GET  # Optional: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS
        headers:  # Optional custom headers
          Authorization: Bearer token
          Accept: application/json
        body: '{"key": "value"}'  # Optional request body
        timeout: 5.0  # Optional timeout in seconds
    
    Examples:
    
        # Monitor endpoints from default configuration (endpoints.yaml)
        domain-monitor watch
        
        # Monitor with custom endpoint configuration
        domain-monitor watch -f my-endpoints.yaml
        
        # Custom check interval (2 seconds)
        domain-monitor watch --interval 2.0
        
        # Custom log file location
        domain-monitor watch --log-file /var/log/monitor.log
    
    Requirements: 5.1, 5.2, 6.1
    """
    try:
        # Validate interval parameter (must be > 0)
        if interval <= 0:
            raise click.ClickException(
                f"Invalid interval: {interval}. Interval must be greater than 0."
            )
        
        # Validate interval is reasonable (warn if too small)
        if interval < 0.5:
            click.echo(
                f"⚠️  Warning: Very short interval ({interval}s) may cause high CPU usage "
                "and network load.",
                err=True
            )
        
        # Validate log file path
        log_path = Path(log_file)
        
        # Check if log file path is valid (parent directory must be writable)
        try:
            # Ensure logs directory exists
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Test write permissions by attempting to create/open the file
            with open(log_file, 'a', encoding='utf-8') as f:
                pass
        except PermissionError:
            raise click.ClickException(
                f"Permission denied: Cannot write to log file '{log_file}'. "
                "Please check file permissions or specify a different location."
            )
        except OSError as e:
            raise click.ClickException(
                f"Invalid log file path '{log_file}': {e}"
            )
        
        # Resolve endpoint configuration file path
        if file:
            config_path = file
        else:
            # Look for default endpoints.yaml or endpoints.json
            yaml_path = Path('endpoints.yaml')
            json_path = Path('endpoints.json')
            
            if yaml_path.exists():
                config_path = str(yaml_path)
            elif json_path.exists():
                config_path = str(json_path)
            else:
                raise click.ClickException(
                    "No endpoint configuration file found. Please either:\n"
                    "  1. Create an 'endpoints.yaml' or 'endpoints.json' file in the current directory, or\n"
                    "  2. Specify a configuration file using the -f/--file option\n\n"
                    "Example configuration:\n"
                    "  endpoints:\n"
                    "    - name: example.com\n"
                    "      url: https://example.com\n"
                    "      method: GET\n"
                    "    - name: api.example.com/users\n"
                    "      url: https://api.example.com/users\n"
                    "      method: GET\n"
                    "      headers:\n"
                    "        Authorization: Bearer token\n\n"
                    "See examples/endpoints.yaml for more examples."
                )
        
        # Load endpoint configuration
        click.echo(f"Loading endpoint configuration from: {config_path}")
        endpoints = load_endpoints_config(config_path)
        
        if not endpoints:
            raise click.ClickException(
                "No endpoints found in configuration file. "
                "Please add at least one endpoint to monitor."
            )
        
        # Display startup information
        click.echo(f"Starting live monitor for {len(endpoints)} endpoint(s)")
        click.echo(f"Check interval: {interval}s")
        click.echo(f"Log file: {log_file}")
        click.echo("\nPress CTRL+C to stop monitoring\n")
        
        # Initialize and start LiveMonitor
        monitor = LiveMonitor(
            endpoints=endpoints,
            interval=interval,
            log_file=log_file
        )
        
        # Run the monitor (blocks until CTRL+C)
        asyncio.run(monitor.start())
        
        # Display shutdown message
        click.echo("\n\nMonitoring stopped.")
        click.echo(f"Status changes logged to: {log_file}")
        
    except click.ClickException:
        # Re-raise click exceptions (they handle their own display)
        raise
        
    except FileNotFoundError as e:
        # Handle file not found errors
        logger.error(f"File not found: {str(e)}", exc_info=True)
        raise click.ClickException(f"Endpoint configuration file not found: {str(e)}")
        
    except ValueError as e:
        # Handle validation errors from endpoint configuration loading
        logger.error(f"Configuration error: {str(e)}", exc_info=True)
        raise click.ClickException(f"Endpoint configuration error: {str(e)}")
        
    except KeyboardInterrupt:
        # Handle CTRL+C gracefully (already handled by signal handler)
        click.echo("\n\nMonitoring stopped.")
        click.echo(f"Status changes logged to: {log_file}")
        
    except Exception as e:
        # Handle all other errors
        error_msg = str(e) if str(e) else f"{type(e).__name__} occurred"
        logger.error(f"Unexpected error: {error_msg}", exc_info=True)
        raise click.ClickException(
            f"Unexpected error: {error_msg}\n"
            f"Check logs for detailed error information."
        )


def main() -> None:
    """Entry point for CLI."""
    cli()


if __name__ == '__main__':
    main()
