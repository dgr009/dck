"""
Reporter layer for domain monitoring.

Formats and outputs check results in various formats including
rich table display, JSON export, and CSV export.
"""

import csv
import json
import logging
from pathlib import Path
from typing import List, Dict, Any

from rich.console import Console
from rich.table import Table
from rich.text import Text

from .executor import DomainResult
from .checkers.base_checker import CheckResult
from .console.output import ConsoleManager
from .console.formatters import ResultFormatter


logger = logging.getLogger(__name__)


class Reporter:
    """
    Reporter for formatting and outputting domain check results.
    
    Handles display of results in table format with color coding,
    and export to JSON and CSV formats.
    """
    
    def __init__(self, results: List[DomainResult], console_manager: ConsoleManager = None):
        """
        Initialize the reporter with aggregated domain results.
        
        Args:
            results: List of DomainResult objects from executor
            console_manager: ConsoleManager instance for Rich output (optional for backward compatibility)
            
        Requirements: 16.1, 3.1
        """
        self.results = results
        self.console_manager = console_manager or ConsoleManager()
        self.console = self.console_manager.console
        self.formatter = ResultFormatter()
    
    def display_table(self) -> None:
        """
        Display results as a tree structure in the console.
        
        Creates a formatted tree with domains and their check results.
        Applies color coding based on status with full message visibility.
        Enhanced with better formatting and visual indicators.
        
        Requirements: 16.1, 16.2, 16.3, 16.4, 16.5, 16.6, 3.1, 3.2, 4.5
        """
        from rich.tree import Tree
        from rich.panel import Panel
        
        # Sort results by status priority (Requirements: 4.5)
        status_priority = {
            CheckResult.CRITICAL: 0,
            CheckResult.ERROR: 1,
            CheckResult.WARNING: 2,
            CheckResult.OK: 3
        }
        
        sorted_results = sorted(
            self.results,
            key=lambda r: status_priority.get(r.overall_status, 4)
        )
        
        # Create main tree
        self.console.print()
        self.console.print("[bold magenta]Domain Monitoring Results[/bold magenta]")
        self.console.print()
        
        # Group by status
        previous_status = None
        for domain_result in sorted_results:
            # Add visual separator between status groups
            if previous_status is not None and previous_status != domain_result.overall_status:
                self.console.print()
            
            # Create domain tree
            status_icon = self.formatter._get_status_icon(domain_result.overall_status)
            status_color = self._get_status_color(domain_result.overall_status)
            
            domain_label = f"[{status_color}]{status_icon} {domain_result.domain}[/{status_color}]"
            if domain_result.tags:
                domain_label += f" [dim]({', '.join(domain_result.tags)})[/dim]"
            domain_label += f" [dim]- {domain_result.execution_time:.2f}s[/dim]"
            
            tree = Tree(domain_label)
            
            # Add check results as branches
            check_order = ['http', 'ssl', 'whois', 'dns', 'security', 'rbl']
            for check_type in check_order:
                check_result = domain_result.results.get(check_type)
                if check_result:
                    check_color = self._get_status_color(check_result.status)
                    check_icon = self.formatter._get_status_icon(check_result.status)
                    
                    # Format check name
                    check_name = check_type.upper()
                    
                    # Special handling for security check to show details
                    if check_type == 'security' and check_result.details:
                        branch_label = f"[{check_color}]{check_icon} {check_name}:[/{check_color}]"
                        security_branch = tree.add(branch_label)
                        
                        # Add individual security checks
                        details = check_result.details
                        
                        # SPF
                        if 'spf' in details:
                            spf = details['spf']
                            spf_icon = "✓" if spf['status'] == 'OK' else "✗"
                            spf_color = "green" if spf['status'] == 'OK' else "red"
                            security_branch.add(f"[{spf_color}]{spf_icon} SPF:[/{spf_color}] {spf['message']}")
                        
                        # DMARC
                        if 'dmarc' in details:
                            dmarc = details['dmarc']
                            dmarc_icon = "✓" if dmarc['status'] == 'OK' else "✗"
                            dmarc_color = "green" if dmarc['status'] == 'OK' else "red"
                            security_branch.add(f"[{dmarc_color}]{dmarc_icon} DMARC:[/{dmarc_color}] {dmarc['message']}")
                        
                        # DKIM
                        if 'dkim' in details and details['dkim']['status'] != 'SKIPPED':
                            dkim = details['dkim']
                            dkim_icon = "✓" if dkim['status'] == 'OK' else "✗"
                            dkim_color = "green" if dkim['status'] == 'OK' else "red"
                            security_branch.add(f"[{dkim_color}]{dkim_icon} DKIM:[/{dkim_color}] {dkim['message']}")
                        
                        # DNSSEC
                        if 'dnssec' in details:
                            dnssec = details['dnssec']
                            dnssec_icon = "✓" if dnssec['status'] == 'OK' else "✗"
                            dnssec_color = "green" if dnssec['status'] == 'OK' else "red"
                            security_branch.add(f"[{dnssec_color}]{dnssec_icon} DNSSEC:[/{dnssec_color}] {dnssec['message']}")
                        
                        # Security Headers
                        if 'security_headers' in details:
                            headers = details['security_headers']
                            headers_icon = "✓" if headers['status'] == 'OK' else "✗"
                            headers_color = "green" if headers['status'] == 'OK' else "yellow" if headers['status'] == 'WARNING' else "red"
                            security_branch.add(f"[{headers_color}]{headers_icon} Security Headers:[/{headers_color}] {headers['message']}")
                    else:
                        # Full message without truncation
                        message = check_result.message
                        
                        branch_label = f"[{check_color}]{check_icon} {check_name}:[/{check_color}] {message}"
                        tree.add(branch_label)
            
            self.console.print(tree)
            previous_status = domain_result.overall_status
        
        # Display summary
        self.console.print()
        self._display_summary()
    
    def _format_table_row(self, domain_result: DomainResult) -> List[Text]:
        """
        Format a single domain result as a table row.
        
        Args:
            domain_result: DomainResult to format
            
        Returns:
            List of Text objects for each column
            
        Requirements: 16.3, 16.4, 16.5, 16.6, 3.2
        """
        row = []
        
        # Domain name
        row.append(Text(domain_result.domain))
        
        # Overall status with icon (Requirements: 3.2)
        status_icon = self.formatter._get_status_icon(domain_result.overall_status)
        status_color = self._get_status_color(domain_result.overall_status)
        status_text = Text(f"{status_icon} {domain_result.overall_status}", style=status_color)
        row.append(status_text)
        
        # Tags
        tags_str = ", ".join(domain_result.tags) if domain_result.tags else "-"
        row.append(Text(tags_str, style="dim"))
        
        # HTTP Status
        row.append(self._format_check_result(domain_result.results.get('http')))
        
        # SSL Expiry
        row.append(self._format_check_result(domain_result.results.get('ssl')))
        
        # WHOIS Expiry
        row.append(self._format_check_result(domain_result.results.get('whois')))
        
        # Security Issues
        row.append(self._format_check_result(domain_result.results.get('security')))
        
        # RBL Status
        row.append(self._format_check_result(domain_result.results.get('rbl')))
        
        # Execution time (Requirements: 10.1)
        time_text = Text(f"{domain_result.execution_time:.2f}s")
        if domain_result.execution_time > 5.0:
            time_text.stylize("yellow")
        row.append(time_text)
        
        return row
    
    def _format_check_result(self, check_result: CheckResult) -> Text:
        """
        Format a single check result with color coding.
        
        Args:
            check_result: CheckResult to format, or None if check not enabled
            
        Returns:
            Text object with appropriate color coding
            
        Requirements: 16.3, 16.4, 16.5, 16.6, 6.5
        """
        if check_result is None:
            # Display "N/A" for checks not enabled (Requirements: 16.6)
            return Text("N/A", style="dim")
        
        # Apply color coding based on status (Requirements: 16.3, 16.4, 16.5)
        color = self._get_status_color(check_result.status)
        
        # Format message with proper truncation (Requirements: 6.5)
        message = self.formatter.truncate_message(check_result.message, max_length=40)
        
        return Text(message, style=color)
    
    def _get_status_color(self, status: str) -> str:
        """
        Get the color for a given status.
        
        Args:
            status: Status string (OK, WARNING, ERROR, CRITICAL)
            
        Returns:
            Color name for rich library
            
        Requirements: 16.3, 16.4, 16.5
        """
        color_map = {
            CheckResult.OK: "green",        # GREEN for OK (Requirements: 16.3)
            CheckResult.WARNING: "yellow",  # YELLOW for WARNING (Requirements: 16.4)
            CheckResult.ERROR: "red",       # RED for ERROR (Requirements: 16.5)
            CheckResult.CRITICAL: "red",    # RED for CRITICAL (Requirements: 16.5)
        }
        return color_map.get(status, "white")
    
    def _display_summary(self) -> None:
        """Display summary statistics."""
        total = len(self.results)
        ok_count = sum(1 for r in self.results if r.overall_status == CheckResult.OK)
        warning_count = sum(1 for r in self.results if r.overall_status == CheckResult.WARNING)
        error_count = sum(1 for r in self.results if r.overall_status in [CheckResult.ERROR, CheckResult.CRITICAL])
        
        self.console.print()
        self.console.print(f"[bold]Summary:[/bold] {total} domain(s) checked")
        self.console.print(f"  [green]✓ OK:[/green] {ok_count}")
        self.console.print(f"  [yellow]⚠ Warning:[/yellow] {warning_count}")
        self.console.print(f"  [red]✗ Error/Critical:[/red] {error_count}")
    
    def display_results(self, view_mode: str = 'summary') -> None:
        """
        Display results in specified view mode.
        
        Args:
            view_mode: Display mode - 'summary', 'detailed', or 'table'
            
        Requirements: 3.1, 3.2, 3.3, 5.1, 5.2, 5.3
        """
        if view_mode == 'summary':
            self.display_summary()
        elif view_mode == 'detailed':
            self.display_detailed()
        elif view_mode == 'table':
            self.display_table()
        else:
            logger.warning(f"Unknown view mode: {view_mode}, defaulting to summary")
            self.display_summary()
    
    def display_summary(self) -> None:
        """
        Display summary view with overall statistics.
        
        Shows aggregate statistics using format_summary_panel and displays
        key metrics for all domain checks.
        
        Requirements: 3.1, 5.1, 5.2, 5.3, 5.4, 5.5
        """
        # Display summary panel (Requirements: 5.1, 5.2, 5.3)
        summary_panel = self.formatter.format_summary_panel(self.results)
        self.console.print(summary_panel)
        self.console.print()
    
    def display_detailed(self) -> None:
        """
        Display detailed view with domain-by-domain results.
        
        Shows individual domain panels with check result trees for
        comprehensive information about each domain. Results are grouped
        by status with visual separators between groups.
        
        Requirements: 3.1, 3.2, 3.3, 4.5, 5.3
        """
        # Sort results by status priority (CRITICAL/ERROR first, then WARNING, then OK)
        # Requirements: 4.5, 5.3
        status_priority = {
            CheckResult.CRITICAL: 0,
            CheckResult.ERROR: 1,
            CheckResult.WARNING: 2,
            CheckResult.OK: 3
        }
        
        sorted_results = sorted(
            self.results,
            key=lambda r: status_priority.get(r.overall_status, 4)
        )
        
        # Group results by status for visual separation
        grouped_results = {}
        for result in sorted_results:
            status = result.overall_status
            if status not in grouped_results:
                grouped_results[status] = []
            grouped_results[status].append(result)
        
        # Display each status group with visual separators (Requirements: 4.5)
        status_order = [CheckResult.CRITICAL, CheckResult.ERROR, CheckResult.WARNING, CheckResult.OK]
        
        for status in status_order:
            if status not in grouped_results:
                continue
            
            results_in_group = grouped_results[status]
            
            # Add visual separator between status groups (Requirements: 4.5)
            if status == CheckResult.CRITICAL or status == CheckResult.ERROR:
                separator_style = "bold red"
                separator_char = "═"
            elif status == CheckResult.WARNING:
                separator_style = "bold yellow"
                separator_char = "─"
            else:
                separator_style = "bold green"
                separator_char = "─"
            
            # Print status group header
            status_icon = self.formatter._get_status_icon(status)
            group_header = f"{separator_char * 20} {status_icon} {status} ({len(results_in_group)}) {separator_char * 20}"
            self.console.print(f"[{separator_style}]{group_header}[/{separator_style}]")
            self.console.print()
            
            # Display each domain in this status group
            for result in results_in_group:
                # Display domain panel (Requirements: 3.1, 3.2, 3.3)
                domain_panel = self.formatter.format_domain_panel(result, detailed=True)
                self.console.print(domain_panel)
                
                # Display check results as tree (Requirements: 3.4)
                if result.results:
                    check_tree = self.formatter.format_check_tree(result.results)
                    self.console.print(check_tree)
                
                # Display specialized formatters for specific check types
                for check_type, check_result in result.results.items():
                    if check_type == 'dns' and check_result.details:
                        # Display DNS records table (Requirements: 4.1)
                        dns_table = self.formatter.format_dns_table(check_result.details)
                        self.console.print(dns_table)
                    
                    elif check_type == 'rbl' and check_result.details:
                        # Display RBL results table (Requirements: 4.2)
                        rbl_table = self.formatter.format_rbl_table(check_result.details)
                        self.console.print(rbl_table)
                    
                    elif check_type == 'security' and check_result.details:
                        # Display security findings tree (Requirements: 4.3)
                        security_tree = self.formatter.format_security_tree(check_result.details)
                        self.console.print(security_tree)
                    
                    elif check_type == 'ssl' and check_result.details:
                        # Display SSL certificate info table (Requirements: 4.4)
                        ssl_table = self.formatter.format_ssl_info(check_result.details)
                        self.console.print(ssl_table)
                
                # Add visual separator between domains within group
                self.console.print()
            
            # Add extra spacing between status groups
            self.console.print()
    
    def display_performance_metrics(self) -> None:
        """
        Display performance metrics for all domain checks.
        
        Shows execution time statistics, highlights slow checks,
        and displays aggregate performance data.
        
        Requirements: 10.1, 10.2, 10.3, 10.4, 10.5
        """
        performance_table = self.formatter.format_performance_table(self.results)
        self.console.print(performance_table)
        self.console.print()
    
    def export_json(self, file_path: str) -> None:
        """
        Export results to JSON file.
        
        Saves all check results and details to a JSON file with
        proper error handling and Rich feedback.
        
        Args:
            file_path: Path where JSON file should be created
            
        Requirements: 17.1, 17.3, 17.5, 8.1, 8.2, 8.5
        """
        try:
            # Display export format and destination (Requirements: 8.5)
            self.console.print(f"[cyan]Exporting to JSON:[/cyan] {file_path}")
            
            # Show progress spinner during export (Requirements: 8.4)
            with self.console.status("[cyan]Exporting results to JSON...", spinner="dots"):
                # Convert results to JSON-serializable format
                data = self._results_to_dict()
                
                # Write to file (Requirements: 17.1)
                output_path = Path(file_path)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, default=str)
                
                # Get file size
                file_size = output_path.stat().st_size
            
            # Display success message with file path and size (Requirements: 8.1)
            size_kb = file_size / 1024
            if size_kb < 1024:
                size_str = f"{size_kb:.2f} KB"
            else:
                size_str = f"{size_kb / 1024:.2f} MB"
            
            logger.info(f"Results exported to JSON: {file_path}")
            self.console_manager.print_success(
                f"Results exported to: {file_path} ({size_str})"
            )
            
        except Exception as e:
            # Handle file creation errors (Requirements: 17.5, 8.3)
            error_msg = f"Failed to export JSON: {str(e)}"
            logger.error(error_msg, exc_info=True)
            self.console_manager.print_error(
                error_msg,
                details={'file_path': file_path}
            )
            raise
    
    def export_csv(self, file_path: str) -> None:
        """
        Export results to CSV file.
        
        Flattens nested data and saves to CSV format with
        proper error handling and Rich feedback.
        
        Args:
            file_path: Path where CSV file should be created
            
        Requirements: 17.2, 17.3, 17.5, 8.2, 8.3, 8.4, 8.5
        """
        try:
            # Display export format and destination (Requirements: 8.5)
            self.console.print(f"[cyan]Exporting to CSV:[/cyan] {file_path}")
            
            # Show progress spinner during export (Requirements: 8.4)
            with self.console.status("[cyan]Exporting results to CSV...", spinner="dots"):
                # Flatten data for CSV format (Requirements: 17.2)
                rows = self._results_to_csv_rows()
                
                if not rows:
                    logger.warning("No results to export")
                    self.console_manager.print_warning("No results to export")
                    return
                
                # Write to file (Requirements: 17.2)
                output_path = Path(file_path)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                
                with open(output_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                    writer.writeheader()
                    writer.writerows(rows)
                
                row_count = len(rows)
            
            # Display success message with row count (Requirements: 8.2)
            logger.info(f"Results exported to CSV: {file_path}")
            self.console_manager.print_success(
                f"Results exported to: {file_path} ({row_count} row{'s' if row_count != 1 else ''})"
            )
            
        except Exception as e:
            # Handle file creation errors (Requirements: 17.5, 8.3)
            error_msg = f"Failed to export CSV: {str(e)}"
            logger.error(error_msg, exc_info=True)
            self.console_manager.print_error(
                error_msg,
                details={'file_path': file_path}
            )
            raise
    
    def _results_to_dict(self) -> Dict[str, Any]:
        """
        Convert results to JSON-serializable dictionary.
        
        Returns:
            Dictionary containing all results and metadata
            
        Requirements: 17.3
        """
        return {
            "timestamp": self.results[0].timestamp.isoformat() if self.results else None,
            "total_domains": len(self.results),
            "domains": [
                {
                    "domain": result.domain,
                    "tags": result.tags,
                    "overall_status": result.overall_status,
                    "execution_time": result.execution_time,
                    "checks": {
                        check_type: {
                            "status": check_result.status,
                            "message": check_result.message,
                            "details": check_result.details,
                            "timestamp": check_result.timestamp.isoformat()
                        }
                        for check_type, check_result in result.results.items()
                    }
                }
                for result in self.results
            ]
        }
    
    def _results_to_csv_rows(self) -> List[Dict[str, Any]]:
        """
        Convert results to flattened CSV rows.
        
        Returns:
            List of dictionaries, one per domain
            
        Requirements: 17.3
        """
        rows = []
        
        for result in self.results:
            row = {
                "domain": result.domain,
                "tags": ", ".join(result.tags) if result.tags else "",
                "overall_status": result.overall_status,
                "execution_time": f"{result.execution_time:.2f}",
            }
            
            # Add columns for each check type
            check_types = ['http', 'ssl', 'whois', 'security', 'rbl', 'dns']
            for check_type in check_types:
                check_result = result.results.get(check_type)
                if check_result:
                    row[f"{check_type}_status"] = check_result.status
                    row[f"{check_type}_message"] = check_result.message
                else:
                    row[f"{check_type}_status"] = "N/A"
                    row[f"{check_type}_message"] = "Not enabled"
            
            rows.append(row)
        
        return rows
