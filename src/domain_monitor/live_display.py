"""Live display component for real-time domain status monitoring."""

from typing import List, Optional, Dict
from datetime import datetime
import sys
import logging

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text

from domain_monitor.models import DomainStatus, EndpointStatus

logger = logging.getLogger(__name__)


class LiveDisplay:
    """Manages the terminal UI using Rich library's Live display feature."""

    def __init__(self, console: Optional[Console] = None):
        """
        Initialize display with Rich console.
        
        Args:
            console: Rich Console instance. If None, creates a new one.
        """
        self.console = console or Console()
        self.live: Optional[Live] = None
        self.fallback_mode = False
        self._check_terminal_size()

    def _check_terminal_size(self) -> None:
        """Check terminal size and warn if too small."""
        try:
            width, height = self.console.size
            
            # Minimum recommended size for readable display
            min_width = 80
            min_height = 10
            
            if width < min_width or height < min_height:
                logger.warning(
                    f"Terminal size ({width}x{height}) is smaller than recommended "
                    f"({min_width}x{min_height}). Display may be truncated."
                )
                # Print warning to stderr before starting live display
                print(
                    f"⚠️  Warning: Terminal size ({width}x{height}) is smaller than "
                    f"recommended ({min_width}x{min_height})",
                    file=sys.stderr
                )
        except Exception as e:
            logger.debug(f"Could not detect terminal size: {e}")

    def start(self) -> None:
        """Start the live display context."""
        if self.live is None:
            try:
                # Create initial empty table
                initial_table = self._create_table([])
                self.live = Live(
                    initial_table,
                    console=self.console,
                    refresh_per_second=1,
                    screen=False
                )
                self.live.start()
                self.fallback_mode = False
            except Exception as e:
                # Fallback to simple text output if Rich fails
                logger.error(f"Failed to start Rich live display: {e}")
                logger.info("Falling back to simple text output mode")
                print(
                    "⚠️  Warning: Could not initialize live display. "
                    "Using fallback text mode.",
                    file=sys.stderr
                )
                self.fallback_mode = True

    def stop(self) -> None:
        """Stop the live display and restore terminal."""
        if self.live is not None:
            try:
                self.live.stop()
            except Exception as e:
                logger.debug(f"Error stopping live display: {e}")
            finally:
                self.live = None

    def update(self, statuses: List[DomainStatus]) -> None:
        """
        Update the display with new status data.
        
        Args:
            statuses: List of current domain statuses (DomainStatus or EndpointStatus)
        """
        if self.fallback_mode:
            # Use simple text output in fallback mode
            self._fallback_update(statuses)
        elif self.live is not None:
            try:
                table = self._create_table(statuses)
                self.live.update(table)
            except Exception as e:
                logger.error(f"Error updating live display: {e}")
                # Switch to fallback mode
                self.fallback_mode = True
                self._fallback_update(statuses)

    def _create_table(self, statuses: List[DomainStatus]) -> Table:
        """
        Create Rich table from status data.
        
        Args:
            statuses: List of domain statuses to display (DomainStatus or EndpointStatus)
            
        Returns:
            Rich Table object with formatted status data
        """
        # Check if we're dealing with EndpointStatus objects
        is_endpoint_status = statuses and isinstance(statuses[0], EndpointStatus)
        
        if is_endpoint_status:
            title = "Live Endpoint Status Monitor"
            caption = (
                f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                "Press CTRL+C to stop monitoring\n"
                "Headers abbreviations: Auth=Authorization, CT=Content-Type, Accept=Accept"
            )
        else:
            title = "Live Domain Status Monitor"
            caption = f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\nPress CTRL+C to stop monitoring"
        
        table = Table(
            title=title,
            caption=caption,
            show_header=True,
            header_style="bold cyan",
            border_style="blue",
            title_style="bold magenta"
        )

        if is_endpoint_status:
            # Add columns for endpoint monitoring with Method and Headers
            table.add_column("Method", style="cyan", width=8, no_wrap=True)
            table.add_column("Endpoint", style="white", no_wrap=True)
            table.add_column("Status", justify="center", width=12)
            table.add_column("Response", justify="right", width=10)
            table.add_column("Headers", style="dim", width=12, no_wrap=True)
            table.add_column("Error/Info", style="dim", width=40)

            # Add rows for each endpoint
            for status in statuses:
                table.add_row(
                    status.method,
                    status.endpoint_name,
                    self._format_status_code(status.status_code),
                    self._format_response_time(status.response_time),
                    self._format_headers(status.config.headers),
                    self._format_error(status.error, max_length=40)
                )
        else:
            # Add columns for domain monitoring (legacy format)
            table.add_column("Domain", style="white", no_wrap=True)
            table.add_column("Status", justify="center", width=12)
            table.add_column("Response", justify="right", width=12)
            table.add_column("Error/Info", style="dim", width=50)

            # Add rows for each domain
            for status in statuses:
                table.add_row(
                    status.domain,
                    self._format_status_code(status.status_code),
                    self._format_response_time(status.response_time),
                    self._format_error(status.error, max_length=50)
                )

        return table

    def _format_status_code(self, status_code: Optional[int]) -> Text:
        """
        Format status code with color coding and icon.
        
        Args:
            status_code: HTTP status code or None for errors
            
        Returns:
            Rich Text object with colored status code and icon
        """
        if status_code is None:
            # Network error
            return Text("🔴 ERROR", style="bold red")
        elif 200 <= status_code < 300:
            # Success - green
            return Text(f"🟢 {status_code}", style="bold green")
        elif 300 <= status_code < 500:
            # Redirect or client error - yellow
            return Text(f"🟡 {status_code}", style="bold yellow")
        else:
            # Server error - red
            return Text(f"🔴 {status_code}", style="bold red")

    def _format_response_time(self, response_time: float) -> str:
        """
        Format response time for display.
        
        Args:
            response_time: Response time in seconds
            
        Returns:
            Formatted response time string
        """
        return f"{response_time:.3f}s"

    def _format_headers(self, headers: Optional[Dict[str, str]], mask_sensitive: bool = True) -> str:
        """
        Format headers as abbreviated list (e.g., 'Auth,CT').
        
        Args:
            headers: Dictionary of HTTP headers or None
            mask_sensitive: Whether to mask sensitive header values (default: True)
            
        Returns:
            Comma-separated abbreviated header keys or "-" if no headers
        """
        if not headers:
            return "-"
        
        # Mask sensitive headers if requested (for security)
        # Note: We only show header keys, not values, so masking is not strictly needed
        # but we import the function for consistency
        from domain_monitor.models import mask_sensitive_headers
        
        # Header abbreviation mapping
        abbreviations = {
            "authorization": "Auth",
            "content-type": "CT",
            "accept": "Accept",
            "user-agent": "UA",
            "x-api-key": "API-Key",
            "api-key": "API-Key",
            "content-length": "CL",
            "cache-control": "Cache",
            "accept-encoding": "Enc",
            "accept-language": "Lang",
            "connection": "Conn",
            "host": "Host",
            "referer": "Ref",
            "cookie": "Cookie",
            "set-cookie": "SetCookie",
        }
        
        # Abbreviate each header key (we only show keys, not values for security)
        abbreviated = []
        for key in headers.keys():
            key_lower = key.lower()
            # Use abbreviation if available, otherwise use first 8 chars of key
            abbr = abbreviations.get(key_lower, key[:8])
            abbreviated.append(abbr)
        
        # Join with commas and truncate if too long
        result = ",".join(abbreviated)
        if len(result) > 12:
            # Truncate to fit column width
            result = result[:9] + "..."
        
        return result

    def _format_error(self, error: Optional[str], max_length: int = 50) -> str:
        """
        Truncate error message to fit in table.
        
        Args:
            error: Error message or None
            max_length: Maximum length for error message
            
        Returns:
            Truncated error message or "-" if no error
        """
        if error is None:
            return "-"
        
        if len(error) <= max_length:
            return error
        
        # Truncate and add ellipsis
        return error[:max_length - 3] + "..."

    def _fallback_update(self, statuses: List[DomainStatus]) -> None:
        """
        Simple text-based fallback update when Rich library fails.
        
        Args:
            statuses: List of current domain statuses (DomainStatus or EndpointStatus)
        """
        # Clear screen (simple approach)
        print("\033[2J\033[H", end="")
        
        # Check if we're dealing with EndpointStatus objects
        is_endpoint_status = statuses and isinstance(statuses[0], EndpointStatus)
        
        # Print header
        print("=" * 100)
        if is_endpoint_status:
            print("Live Endpoint Status Monitor (Fallback Mode)")
        else:
            print("Live Domain Status Monitor (Fallback Mode)")
        print(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("Press CTRL+C to stop monitoring")
        print("=" * 100)
        print()
        
        # Print status for each domain/endpoint
        for status in statuses:
            # Format status indicator
            if status.status_code is None:
                status_str = "ERROR"
            elif 200 <= status.status_code < 300:
                status_str = f"{status.status_code} OK"
            elif 300 <= status.status_code < 500:
                status_str = f"{status.status_code} WARN"
            else:
                status_str = f"{status.status_code} ERROR"
            
            # Format error message
            error_str = status.error if status.error else "-"
            if len(error_str) > 40:
                error_str = error_str[:37] + "..."
            
            if is_endpoint_status:
                # Format headers
                headers_str = self._format_headers(status.config.headers)
                
                # Print endpoint status line with method and headers
                print(
                    f"{status.method:8s} | {status.endpoint_name:30s} | {status_str:12s} | "
                    f"{status.response_time:6.3f}s | {headers_str:12s} | {error_str}"
                )
            else:
                # Print domain status line (legacy format)
                print(
                    f"{status.domain:30s} | {status_str:12s} | "
                    f"{status.response_time:6.3f}s | {error_str}"
                )
        
        print()
        sys.stdout.flush()
