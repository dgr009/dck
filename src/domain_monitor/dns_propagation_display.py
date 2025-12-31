"""Display manager for DNS propagation check results.

This module provides the DNSPropagationDisplay class for formatting and displaying
DNS propagation check results using Rich library components.
"""

from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn

from domain_monitor.models import PropagationResult
from domain_monitor.console.output import ConsoleManager
from domain_monitor.console.themes import ICONS, STATUS_COLORS


class DNSPropagationDisplay:
    """Display manager for DNS propagation check results.
    
    Provides methods to format and display DNS propagation results using
    Rich library components including tables, panels, and progress bars.
    
    Attributes:
        console_manager: ConsoleManager instance for output
        console: Rich Console instance
    """
    
    def __init__(self, console_manager: ConsoleManager):
        """Initialize display with console manager.
        
        Args:
            console_manager: ConsoleManager instance for output
        """
        self.console_manager = console_manager
        self.console = console_manager.console
    
    def display_result(self, result: PropagationResult, watch_mode: bool = False) -> None:
        """Display propagation check result.
        
        Shows complete propagation check results including summary statistics,
        progress bar, and detailed server table.
        
        Args:
            result: PropagationResult to display
            watch_mode: If True, use live display format
            
        Requirements: 1.5, 5.2, 5.4, 8.1, 8.2, 8.3, 8.4, 8.6
        """
        # Display summary with propagation rate
        self.display_summary(result)
        
        # Display progress bar
        self.display_progress_bar(result.propagation_rate)
        
        # Display detailed server table
        self.display_server_table(result)
        
        # Display completion message if propagation is complete
        if result.is_complete:
            self.console.print()
            completion_text = Text()
            completion_text.append(f"{ICONS['success']} ", style="bold green")
            completion_text.append("DNS propagation complete! ", style="bold green")
            completion_text.append("All responsive servers have the expected value.", style="green")
            
            panel = Panel(
                completion_text,
                title="[bold green]Propagation Complete[/bold green]",
                border_style="green",
                padding=(1, 2)
            )
            self.console.print(panel)
    
    def display_summary(self, result: PropagationResult) -> None:
        """Display propagation summary with rate and counts.
        
        Shows high-level statistics including propagation rate, matched/mismatched/
        unreachable server counts, and domain/record type information.
        
        Args:
            result: PropagationResult to summarize
            
        Requirements: 5.2, 5.4, 8.3
        """
        summary_text = Text()
        
        # Domain and record type
        summary_text.append(f"{ICONS['domain']} Domain: ", style="info")
        summary_text.append(f"{result.domain}\n", style="bold cyan")
        
        summary_text.append(f"{ICONS['info']} Record Type: ", style="info")
        summary_text.append(f"{result.record_type}\n", style="bold white")
        
        # Expected value if provided
        if result.expected_value:
            summary_text.append(f"{ICONS['check']} Expected Value: ", style="info")
            summary_text.append(f"{result.expected_value}\n", style="bold white")
        
        summary_text.append("\n", style="white")
        
        # Propagation rate (Requirements: 5.2)
        rate = result.propagation_rate
        rate_color = self._get_rate_color(rate)
        summary_text.append("Propagation Rate: ", style="bold")
        summary_text.append(f"{rate:.1f}%", style=rate_color)
        
        # Completion status
        if result.is_complete:
            summary_text.append(f" {ICONS['success']}", style="bold green")
        
        summary_text.append("\n\n", style="white")
        
        # Server counts (Requirements: 5.4)
        summary_text.append("Server Status:\n", style="bold")
        summary_text.append(f"  {ICONS['success']} Matched: ", style="green")
        summary_text.append(f"{result.matched_count}\n", style="white")
        summary_text.append(f"  {ICONS['error']} Mismatched: ", style="red")
        summary_text.append(f"{result.mismatched_count}\n", style="white")
        summary_text.append(f"  {ICONS['warning']} Unreachable: ", style="yellow")
        summary_text.append(f"{result.unreachable_count}\n", style="white")
        summary_text.append(f"  {ICONS['info']} Total Responsive: ", style="info")
        summary_text.append(f"{result.responsive_count}\n", style="white")
        
        # Timestamp
        summary_text.append("\n", style="white")
        summary_text.append(f"{ICONS['time']} Checked: ", style="dim")
        summary_text.append(f"{result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}", style="white")
        
        # Determine border color based on propagation rate
        if rate == 100.0:
            border_style = "green"
        elif rate >= 50.0:
            border_style = "yellow"
        else:
            border_style = "red"
        
        panel = Panel(
            summary_text,
            title="[bold]DNS Propagation Summary[/bold]",
            border_style=border_style,
            padding=(1, 2)
        )
        
        self.console.print(panel)
        self.console.print()
    
    def display_server_table(self, result: PropagationResult) -> None:
        """Display detailed table of DNS server results.
        
        Shows a formatted table with columns for DNS server name, location,
        status, actual values, and response time. Uses color coding for
        status indicators.
        
        Args:
            result: PropagationResult with server query results
            
        Requirements: 1.5, 8.1, 8.2, 8.6
        """
        # Create table with Unicode box-drawing characters (Requirements: 8.6)
        table = Table(
            title="DNS Server Results",
            show_header=True,
            header_style="bold cyan",
            border_style="blue",
            show_lines=True
        )
        
        # Add columns (Requirements: 8.1)
        table.add_column("DNS Server", style="cyan", no_wrap=True, width=20)
        table.add_column("Location", style="white", width=12)
        table.add_column("Status", justify="center", width=12)
        table.add_column("Actual Value", style="white", width=30)
        table.add_column("Response Time", justify="right", width=14)
        
        # Add rows for each DNS server
        for query_result in result.query_results:
            server = query_result.server
            
            # Format status with color coding (Requirements: 8.2)
            status_text = self._format_status(query_result.status)
            
            # Format values
            if query_result.values:
                # Show first value, indicate if there are more
                value_str = query_result.values[0]
                if len(query_result.values) > 1:
                    value_str += f" (+{len(query_result.values) - 1} more)"
            else:
                value_str = "[dim]No records[/dim]"
            
            # Format response time
            if query_result.status in ('timeout', 'unreachable'):
                response_time_str = "[dim]N/A[/dim]"
            else:
                response_time_str = f"{query_result.response_time:.3f}s"
            
            # Add row
            table.add_row(
                f"{server.name}\n[dim]{server.ip}[/dim]",
                server.location,
                status_text,
                value_str,
                response_time_str
            )
        
        self.console.print(table)
        self.console.print()
    
    def display_progress_bar(self, rate: float) -> None:
        """Display progress bar for propagation rate.
        
        Shows a visual progress bar representing the propagation percentage
        with color coding based on completion level.
        
        Args:
            rate: Propagation rate as percentage (0-100)
            
        Requirements: 8.4
        """
        # Determine color based on rate
        if rate == 100.0:
            bar_color = "green"
        elif rate >= 50.0:
            bar_color = "yellow"
        else:
            bar_color = "red"
        
        # Create progress bar
        progress = Progress(
            TextColumn("[bold]Propagation Progress:[/bold]"),
            BarColumn(bar_width=40, complete_style=bar_color, finished_style=bar_color),
            TextColumn(f"[bold {bar_color}]{rate:.1f}%[/bold {bar_color}]"),
        )
        
        with progress:
            task = progress.add_task("", total=100, completed=rate)
            # Just display, no actual progress tracking needed
        
        self.console.print()
    
    def _format_status(self, status: str) -> Text:
        """Format status with color coding and icon.
        
        Args:
            status: Status string ('matched', 'mismatched', 'unreachable', 'timeout')
            
        Returns:
            Rich Text object with colored status and icon
            
        Requirements: 8.2
        """
        status_text = Text()
        
        if status == 'matched':
            status_text.append(f"{ICONS['success']} ", style="bold green")
            status_text.append("Matched", style="bold green")
        elif status == 'mismatched':
            status_text.append(f"{ICONS['error']} ", style="bold red")
            status_text.append("Mismatched", style="bold red")
        elif status == 'timeout':
            status_text.append(f"{ICONS['warning']} ", style="bold yellow")
            status_text.append("Timeout", style="bold yellow")
        elif status == 'unreachable':
            status_text.append(f"{ICONS['warning']} ", style="bold yellow")
            status_text.append("Unreachable", style="bold yellow")
        else:
            status_text.append(f"{ICONS['info']} ", style="dim")
            status_text.append(status, style="dim")
        
        return status_text
    
    def _get_rate_color(self, rate: float) -> str:
        """Get color style for propagation rate.
        
        Args:
            rate: Propagation rate as percentage (0-100)
            
        Returns:
            Color style string for Rich
        """
        if rate == 100.0:
            return "bold green"
        elif rate >= 75.0:
            return "green"
        elif rate >= 50.0:
            return "yellow"
        elif rate >= 25.0:
            return "bold yellow"
        else:
            return "bold red"
