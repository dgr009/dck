"""Central console output manager for Rich-formatted output.

This module provides the ConsoleManager class that coordinates all Rich console
output throughout the application, ensuring consistent formatting and handling
debug mode appropriately.
"""

from typing import Optional, Dict, List, Any, Union
import json
import traceback
from collections import defaultdict
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.text import Text
from rich.table import Table
from .themes import get_theme, ICONS, STATUS_COLORS


class ConsoleManager:
    """Central console output manager.
    
    This class manages all Rich console output, providing methods for displaying
    banners, errors, success messages, warnings, and debug information with
    consistent formatting.
    
    Attributes:
        console: Rich Console instance
        debug_mode: Whether debug mode is enabled
        theme: Rich Theme for consistent styling
    """
    
    def __init__(self, debug_mode: bool = False):
        """Initialize the ConsoleManager.
        
        Args:
            debug_mode: If True, display info and debug messages to console
        """
        self.debug_mode = debug_mode
        self.theme = get_theme()
        self.console = Console(theme=self.theme)
    
    def print_banner(
        self,
        version: str,
        manifest_path: str,
        domain_count: int,
        check_types: List[str]
    ) -> None:
        """Display application startup banner.
        
        Shows application name, version, configuration details, and enabled
        check types in a formatted panel.
        
        Args:
            version: Application version string
            manifest_path: Path to the manifest file being used
            domain_count: Number of domains to be checked
            check_types: List of enabled check type names
        """
        banner_text = Text()
        banner_text.append("Domain & NetUtils Monitoring Agent\n", style="bold cyan")
        banner_text.append(f"Version: {version}\n\n", style="dim")
        
        banner_text.append(f"{ICONS['domain']} Manifest: ", style="info")
        banner_text.append(f"{manifest_path}\n", style="white")
        
        banner_text.append(f"{ICONS['check']} Domains: ", style="info")
        banner_text.append(f"{domain_count}\n", style="white")
        
        banner_text.append(f"{ICONS['info']} Check Types: ", style="info")
        banner_text.append(", ".join(check_types), style="check_type")
        
        if self.debug_mode:
            banner_text.append("\n\n", style="white")
            banner_text.append(f"{ICONS['warning']} Debug Mode: ", style="warning")
            banner_text.append("ENABLED", style="bold yellow")
        
        panel = Panel(
            banner_text,
            title="[bold]Application Startup[/bold]",
            border_style="cyan",
            padding=(1, 2)
        )
        
        self.console.print(panel)
        self.console.print()  # Add blank line after banner
    
    def print_error(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        exception: Optional[Exception] = None,
        show_traceback: bool = False
    ) -> None:
        """Display error message in Rich Panel format.
        
        Shows error message with optional context details and stack trace
        in a formatted error panel. In debug mode, automatically shows
        stack traces with syntax highlighting.
        
        Args:
            message: Error message to display
            details: Optional dictionary with additional context (domain, check_type, etc.)
            exception: Optional exception object for extracting traceback
            show_traceback: Force showing traceback even in non-debug mode
            
        Requirements: 7.1, 7.2, 7.3, 7.5
        """
        error_text = Text()
        error_text.append(f"{ICONS['error']} ", style="error")
        error_text.append(message, style="error")
        
        # Add context information (Requirements: 7.2)
        if details:
            error_text.append("\n\n", style="white")
            error_text.append("Context:\n", style="bold dim")
            for key, value in details.items():
                error_text.append(f"  {key.replace('_', ' ').title()}: ", style="dim")
                error_text.append(f"{value}\n", style="white")
        
        # Add actionable suggestions for common errors (Requirements: 7.5)
        suggestion = self._get_error_suggestion(message, details)
        if suggestion:
            error_text.append("\n", style="white")
            error_text.append(f"{ICONS['info']} Suggestion: ", style="info")
            error_text.append(suggestion, style="cyan")
        
        panel = Panel(
            error_text,
            title="[bold red]Error[/bold red]",
            border_style="red",
            padding=(1, 2)
        )
        
        self.console.print(panel)
        
        # Display stack trace in debug mode with syntax highlighting (Requirements: 7.3)
        if (self.debug_mode or show_traceback) and exception:
            self._print_traceback(exception)
    
    def _get_error_suggestion(self, message: str, details: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """Get actionable suggestion for common errors.
        
        Analyzes error message and context to provide helpful suggestions
        for resolving common issues.
        
        Args:
            message: Error message
            details: Optional context details
            
        Returns:
            Suggestion string or None if no suggestion available
            
        Requirements: 7.5
        """
        message_lower = message.lower()
        
        # File not found errors
        if 'file not found' in message_lower or 'no such file' in message_lower:
            return "Check that the file path is correct and the file exists. Use absolute paths if needed."
        
        # Network timeout errors
        if 'timeout' in message_lower or 'timed out' in message_lower:
            return "Check your network connection and firewall settings. The domain may be unreachable or slow to respond."
        
        # DNS resolution errors
        if 'failed to resolve' in message_lower or 'name or service not known' in message_lower:
            return "Verify the domain name is correct and has valid DNS records. Check your DNS server settings."
        
        # Connection refused errors
        if 'connection refused' in message_lower:
            return "The server is not accepting connections on this port. Verify the service is running and the port is correct."
        
        # SSL/TLS errors
        if 'ssl' in message_lower or 'certificate' in message_lower:
            return "Check the SSL certificate configuration. The certificate may be invalid, expired, or self-signed."
        
        # Permission errors
        if 'permission denied' in message_lower or 'access denied' in message_lower:
            return "Check file/directory permissions. You may need elevated privileges to access this resource."
        
        # WHOIS errors
        if 'whois' in message_lower:
            return "WHOIS queries may be rate-limited or blocked. Try again later or check if the domain is registered."
        
        # Invalid domain errors
        if 'invalid domain' in message_lower or 'invalid hostname' in message_lower:
            return "Verify the domain name format is correct (e.g., example.com without http:// or trailing slashes)."
        
        # Rate limiting
        if 'rate limit' in message_lower or 'too many requests' in message_lower:
            return "You've exceeded the rate limit. Wait a few minutes before trying again."
        
        return None
    
    def _print_traceback(self, exception: Exception) -> None:
        """Print exception traceback with syntax highlighting.
        
        Displays the full stack trace with Python syntax highlighting
        for easier debugging.
        
        Args:
            exception: Exception object to display traceback for
            
        Requirements: 7.3
        """
        if not hasattr(exception, '__traceback__'):
            return
        
        # Format the traceback
        tb_lines = traceback.format_exception(
            type(exception),
            exception,
            exception.__traceback__
        )
        tb_text = ''.join(tb_lines)
        
        # Create syntax-highlighted traceback
        syntax = Syntax(
            tb_text,
            "python",
            theme="monokai",
            line_numbers=True,
            word_wrap=True
        )
        
        # Display in a panel
        self.console.print()
        self.console.print(Panel(
            syntax,
            title="[bold red]Stack Trace[/bold red]",
            border_style="red",
            padding=(1, 2)
        ))
    
    def print_error_group(self, errors: List[Dict[str, Any]]) -> None:
        """Display multiple errors grouped by error type.
        
        Groups errors by their type and displays them in a formatted table
        for easier analysis of multiple failures.
        
        Args:
            errors: List of error dictionaries with keys:
                - message: Error message
                - error_type: Type of error (e.g., 'TimeoutError', 'SSLError')
                - domain: Optional domain name
                - check_type: Optional check type
                - exception: Optional exception object
                
        Requirements: 7.4
        """
        if not errors:
            return
        
        # Group errors by type (Requirements: 7.4)
        grouped = defaultdict(list)
        for error in errors:
            error_type = error.get('error_type', 'Unknown')
            grouped[error_type].append(error)
        
        # Display header
        self.console.print()
        self.console.print(Panel(
            f"[bold red]{ICONS['error']} {len(errors)} Error(s) Occurred[/bold red]",
            border_style="red"
        ))
        self.console.print()
        
        # Display each error group
        for error_type, error_list in grouped.items():
            # Create table for this error type
            table = Table(
                title=f"[bold red]{error_type}[/bold red] ({len(error_list)} occurrence(s))",
                show_header=True,
                header_style="bold cyan",
                border_style="red"
            )
            
            table.add_column("Domain", style="cyan", no_wrap=True)
            table.add_column("Check Type", style="magenta")
            table.add_column("Message", style="white")
            
            for error in error_list:
                domain = error.get('domain', 'N/A')
                check_type = error.get('check_type', 'N/A')
                message = error.get('message', 'Unknown error')
                
                # Truncate long messages
                if len(message) > 80:
                    message = message[:77] + "..."
                
                table.add_row(domain, check_type, message)
            
            self.console.print(table)
            self.console.print()
            
            # Show suggestion for the first error in this group
            if error_list:
                first_error = error_list[0]
                suggestion = self._get_error_suggestion(
                    first_error.get('message', ''),
                    first_error
                )
                if suggestion:
                    self.console.print(f"  {ICONS['info']} [cyan]Suggestion: {suggestion}[/cyan]")
                    self.console.print()
    
    def print_success(self, message: str) -> None:
        """Display success message.
        
        Args:
            message: Success message to display
        """
        self.console.print(f"{ICONS['success']} {message}", style="success")
    
    def print_warning(self, message: str) -> None:
        """Display warning message.
        
        Args:
            message: Warning message to display
        """
        self.console.print(f"{ICONS['warning']} {message}", style="warning")
    
    def print_info(self, message: str) -> None:
        """Display info message (only in debug mode).
        
        Args:
            message: Info message to display
        """
        if self.debug_mode:
            self.console.print(f"{ICONS['info']} {message}", style="info")
    
    def print_debug(self, message: str, data: Any = None) -> None:
        """Display debug message with optional data (only in debug mode).
        
        If data is provided, it will be formatted with syntax highlighting.
        Supports dict, list, and other JSON-serializable types.
        
        Args:
            message: Debug message to display
            data: Optional data to display with syntax highlighting
        """
        if not self.debug_mode:
            return
        
        self.console.print(f"[dim]DEBUG:[/dim] {message}", style="info")
        
        if data is not None:
            # Format data as JSON with syntax highlighting
            try:
                if isinstance(data, (dict, list)):
                    json_str = json.dumps(data, indent=2, default=str)
                    syntax = Syntax(
                        json_str,
                        "json",
                        theme="monokai",
                        line_numbers=False,
                        word_wrap=True
                    )
                    self.console.print(syntax)
                else:
                    # For non-JSON data, just print it
                    self.console.print(f"  {data}", style="dim")
            except Exception:
                # If formatting fails, just print the data as-is
                self.console.print(f"  {data}", style="dim")
