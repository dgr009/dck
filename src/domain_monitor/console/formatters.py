"""Result formatters for Rich console output.

This module provides the ResultFormatter class with static methods for formatting
domain check results into various Rich components (Panels, Tables, Trees).
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from ..executor import DomainResult
from ..checkers.base_checker import CheckResult
from .themes import STATUS_COLORS, ICONS


class ResultFormatter:
    """Formatter for domain check results.
    
    Provides static methods to format check results into Rich components
    for display in the console. Handles summary panels, domain panels,
    and various data presentation formats.
    """
    
    @staticmethod
    def truncate_message(message: str, max_length: int = 40) -> str:
        """Truncate message with proper Unicode handling.
        
        Truncates a message to the specified maximum length, adding ellipsis
        if truncation occurs. Properly handles Unicode characters to avoid
        breaking multi-byte characters.
        
        Args:
            message: Message string to truncate
            max_length: Maximum length before truncation (default: 40)
            
        Returns:
            str: Truncated message with ellipsis if needed
            
        Requirements: 6.5
        """
        if not message:
            return message
        
        # Handle Unicode properly by working with the string directly
        # Python 3 strings are Unicode by default, so len() counts characters correctly
        if len(message) <= max_length:
            return message
        
        # Truncate to max_length - 3 to leave room for ellipsis
        # This ensures we don't break in the middle of a Unicode character
        truncated = message[:max_length - 3]
        
        # Add ellipsis
        return truncated + "..."
    
    @staticmethod
    def format_summary_panel(results: List[DomainResult]) -> Panel:
        """Create overall summary Panel with statistics.
        
        Displays aggregate statistics across all domain checks including
        total counts by status, execution time metrics, and highlights
        for domains requiring attention.
        
        Args:
            results: List of DomainResult objects from all domain checks
            
        Returns:
            Panel: Rich Panel containing formatted summary
            
        Requirements: 3.1, 5.1, 5.2, 5.3
        """
        if not results:
            return Panel(
                Text("No results to display", style="dim"),
                title="[bold]Summary[/bold]",
                border_style="cyan"
            )
        
        # Calculate statistics
        total = len(results)
        ok_count = sum(1 for r in results if r.overall_status == CheckResult.OK)
        warning_count = sum(1 for r in results if r.overall_status == CheckResult.WARNING)
        error_count = sum(
            1 for r in results 
            if r.overall_status in [CheckResult.ERROR, CheckResult.CRITICAL]
        )
        
        # Calculate execution time metrics
        total_time = sum(r.execution_time for r in results)
        avg_time = total_time / total if total > 0 else 0
        
        # Build summary text
        summary_text = Text()
        
        # Total domains
        summary_text.append(f"{ICONS['domain']} Total Domains: ", style="info")
        summary_text.append(f"{total}\n\n", style="bold white")
        
        # Status breakdown with color coding (Requirements: 3.1, 3.2)
        summary_text.append("Status Breakdown:\n", style="bold")
        summary_text.append(f"  {ICONS['success']} OK: ", style=STATUS_COLORS['OK'])
        summary_text.append(f"{ok_count}\n", style="white")
        summary_text.append(f"  {ICONS['warning']} Warning: ", style=STATUS_COLORS['WARNING'])
        summary_text.append(f"{warning_count}\n", style="white")
        summary_text.append(f"  {ICONS['error']} Error/Critical: ", style=STATUS_COLORS['ERROR'])
        summary_text.append(f"{error_count}\n\n", style="white")
        
        # Execution time metrics (Requirements: 5.4)
        summary_text.append(f"{ICONS['time']} Execution Time:\n", style="info")
        summary_text.append(f"  Total: {total_time:.2f}s\n", style="white")
        summary_text.append(f"  Average: {avg_time:.2f}s per domain\n", style="white")
        
        # Highlight domains requiring attention (Requirements: 5.3)
        critical_domains = [
            r for r in results 
            if r.overall_status in [CheckResult.ERROR, CheckResult.CRITICAL]
        ]
        
        if critical_domains:
            summary_text.append("\n", style="white")
            summary_text.append("═" * 40 + "\n", style="bold red")
            summary_text.append(f"{ICONS['error']} DOMAINS REQUIRING IMMEDIATE ATTENTION\n", style="bold red")
            summary_text.append("═" * 40 + "\n", style="bold red")
            
            for domain_result in critical_domains[:5]:  # Show up to 5
                status_icon = ICONS['error'] if domain_result.overall_status in [CheckResult.ERROR, CheckResult.CRITICAL] else ICONS['warning']
                summary_text.append(f"  {status_icon} ", style="bold red")
                summary_text.append(f"{domain_result.domain}", style="bold red")
                summary_text.append(f" - {domain_result.overall_status}\n", style="red")
            
            if len(critical_domains) > 5:
                summary_text.append(f"  ... and {len(critical_domains) - 5} more domain(s)\n", style="bold red")
        
        # Create panel with appropriate border color based on overall health
        border_style = "green" if error_count == 0 else "red" if error_count > 0 else "yellow"
        
        return Panel(
            summary_text,
            title="[bold]Summary[/bold]",
            border_style=border_style,
            padding=(1, 2)
        )
    
    @staticmethod
    def format_domain_panel(result: DomainResult, detailed: bool = False) -> Panel:
        """Create individual domain result Panel.
        
        Displays check results for a single domain with status indicators,
        messages, and optional detailed information.
        
        Args:
            result: DomainResult for a single domain
            detailed: If True, include full details; if False, show summary only
            
        Returns:
            Panel: Rich Panel containing formatted domain results
            
        Requirements: 3.1, 3.2, 3.3
        """
        panel_text = Text()
        
        # Domain name and tags
        panel_text.append(f"{ICONS['domain']} ", style="info")
        panel_text.append(f"{result.domain}\n", style="bold cyan")
        
        if result.tags:
            panel_text.append("Tags: ", style="dim")
            panel_text.append(", ".join(result.tags), style="dim")
            panel_text.append("\n", style="white")
        
        panel_text.append("\n", style="white")
        
        # Overall status (Requirements: 3.2)
        status_icon = ResultFormatter._get_status_icon(result.overall_status)
        status_color = STATUS_COLORS.get(result.overall_status, "white")
        panel_text.append("Overall Status: ", style="bold")
        panel_text.append(f"{status_icon} {result.overall_status}", style=status_color)
        panel_text.append("\n\n", style="white")
        
        # Execution time
        panel_text.append(f"{ICONS['time']} Execution Time: ", style="dim")
        panel_text.append(f"{result.execution_time:.2f}s\n", style="white")
        
        # Timestamp (Requirements: 6.4)
        timestamp_str = ResultFormatter._format_timestamp(result.timestamp)
        panel_text.append("Checked: ", style="dim")
        panel_text.append(f"{timestamp_str}\n\n", style="white")
        
        # Check results
        if result.results:
            panel_text.append("Check Results:\n", style="bold")
            
            for check_type, check_result in result.results.items():
                status_icon = ResultFormatter._get_status_icon(check_result.status)
                status_color = STATUS_COLORS.get(check_result.status, "white")
                
                panel_text.append(f"  {status_icon} ", style=status_color)
                panel_text.append(f"{check_type.upper()}: ", style="check_type")
                
                # Truncate message if not detailed, show full message in detailed view (Requirements: 6.5)
                message = check_result.message
                if not detailed:
                    message = ResultFormatter.truncate_message(message, max_length=40)
                
                panel_text.append(f"{message}\n", style="white")
        else:
            panel_text.append("No checks performed\n", style="dim")
        
        # Determine border color based on overall status
        border_style = STATUS_COLORS.get(result.overall_status, "white")
        
        return Panel(
            panel_text,
            title=f"[bold]{result.domain}[/bold]",
            border_style=border_style,
            padding=(1, 2)
        )
    
    @staticmethod
    def _get_status_icon(status: str) -> str:
        """Return appropriate icon for status.
        
        Maps status strings to corresponding Unicode icons for visual
        representation in the console.
        
        Args:
            status: Status string (OK, WARNING, ERROR, CRITICAL)
            
        Returns:
            str: Unicode icon character
            
        Requirements: 6.3
        """
        icon_map = {
            CheckResult.OK: ICONS['success'],
            CheckResult.WARNING: ICONS['warning'],
            CheckResult.ERROR: ICONS['error'],
            CheckResult.CRITICAL: ICONS['error'],
        }
        return icon_map.get(status, ICONS['info'])
    
    @staticmethod
    def _format_timestamp(timestamp: datetime) -> str:
        """Format timestamps in human-readable format.
        
        Converts datetime objects to relative time strings (e.g., "2 minutes ago")
        or absolute format if too old.
        
        Args:
            timestamp: Datetime object to format
            
        Returns:
            str: Formatted timestamp string
            
        Requirements: 6.4
        """
        now = datetime.now()
        
        # Handle timezone-aware vs naive datetime
        if timestamp.tzinfo is not None and now.tzinfo is None:
            from datetime import timezone
            now = now.replace(tzinfo=timezone.utc)
        elif timestamp.tzinfo is None and now.tzinfo is not None:
            timestamp = timestamp.replace(tzinfo=now.tzinfo)
        
        delta = now - timestamp
        
        # Calculate relative time
        seconds = delta.total_seconds()
        
        if seconds < 60:
            return "just now"
        elif seconds < 3600:
            minutes = int(seconds / 60)
            return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
        elif seconds < 86400:
            hours = int(seconds / 3600)
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        elif seconds < 604800:
            days = int(seconds / 86400)
            return f"{days} day{'s' if days != 1 else ''} ago"
        else:
            # For older timestamps, use absolute format
            return timestamp.strftime("%Y-%m-%d %H:%M:%S")
    
    @staticmethod
    def format_check_tree(results: Dict[str, CheckResult]) -> Tree:
        """Display check results as Tree structure.
        
        Creates a hierarchical tree view of all check results with status
        indicators, messages, and expandable details.
        
        Args:
            results: Dictionary mapping check types to CheckResult objects
            
        Returns:
            Tree: Rich Tree containing formatted check results
            
        Requirements: 3.4
        """
        tree = Tree("[bold]Check Results[/bold]")
        
        if not results:
            tree.add("[dim]No checks performed[/dim]")
            return tree
        
        # Add each check result as a branch
        for check_type, check_result in results.items():
            status_icon = ResultFormatter._get_status_icon(check_result.status)
            status_color = STATUS_COLORS.get(check_result.status, "white")
            
            # Create branch for this check
            branch_label = Text()
            branch_label.append(f"{status_icon} ", style=status_color)
            branch_label.append(f"{check_type.upper()}: ", style="check_type")
            branch_label.append(check_result.message, style="white")
            
            branch = tree.add(branch_label)
            
            # Add details if available
            if check_result.details:
                # Add a few key details as sub-items
                details_shown = 0
                max_details = 3
                
                for key, value in check_result.details.items():
                    if details_shown >= max_details:
                        break
                    
                    # Skip internal or complex fields
                    if key.startswith('_') or isinstance(value, (dict, list)):
                        continue
                    
                    # Format the detail
                    detail_text = Text()
                    detail_text.append(f"{key}: ", style="dim")
                    detail_text.append(str(value), style="white")
                    branch.add(detail_text)
                    details_shown += 1
        
        return tree
    
    @staticmethod
    def format_dns_table(dns_records: Dict[str, List[str]]) -> Table:
        """Display DNS records in Table format.
        
        Creates a formatted table showing DNS record types, names, and values
        with proper column alignment and styling.
        
        Args:
            dns_records: Dictionary mapping record types to lists of values
                        (e.g., {'a_records': ['1.2.3.4'], 'mx_records': ['10 mail.example.com']})
            
        Returns:
            Table: Rich Table containing formatted DNS records
            
        Requirements: 4.1
        """
        table = Table(title="DNS Records", show_header=True, header_style="bold cyan")
        table.add_column("Type", style="cyan", width=10)
        table.add_column("Value", style="white")
        
        if not dns_records:
            table.add_row("[dim]No records[/dim]", "")
            return table
        
        # Map internal field names to display names
        record_type_map = {
            'a_records': 'A',
            'aaaa_records': 'AAAA',
            'mx_records': 'MX',
            'ns_records': 'NS',
            'txt_records': 'TXT',
            'cname_records': 'CNAME'
        }
        
        # Add rows for each record type
        for field_name, display_name in record_type_map.items():
            if field_name in dns_records:
                values = dns_records[field_name]
                if values:
                    for value in values:
                        table.add_row(display_name, value)
                else:
                    table.add_row(display_name, "[dim]None[/dim]")
        
        return table
    
    @staticmethod
    def format_rbl_table(rbl_results: Dict[str, Any]) -> Table:
        """Display RBL check results in Table format.
        
        Creates a formatted table showing RBL listing status with IP addresses
        and which RBL servers flagged them.
        
        Args:
            rbl_results: Dictionary containing RBL check results with keys:
                        - ips_checked: List of IPs that were checked
                        - listings: List of dicts with 'ip' and 'rbl_server' keys
            
        Returns:
            Table: Rich Table containing formatted RBL results
            
        Requirements: 4.2
        """
        table = Table(title="RBL Check Results", show_header=True, header_style="bold cyan")
        table.add_column("IP Address", style="cyan", width=20)
        table.add_column("Status", style="white", width=15)
        table.add_column("Listed In", style="white")
        
        ips_checked = rbl_results.get('ips_checked', [])
        listings = rbl_results.get('listings', [])
        
        if not ips_checked:
            table.add_row("[dim]No IPs checked[/dim]", "", "")
            return table
        
        # Create a map of IP to RBL servers where it's listed
        ip_to_rbls = {}
        for listing in listings:
            ip = listing.get('ip')
            rbl_server = listing.get('rbl_server')
            if ip not in ip_to_rbls:
                ip_to_rbls[ip] = []
            ip_to_rbls[ip].append(rbl_server)
        
        # Add rows for each IP
        for ip in ips_checked:
            if ip in ip_to_rbls:
                # IP is listed
                rbls = ip_to_rbls[ip]
                status_text = Text(f"{ICONS['error']} LISTED", style="red")
                table.add_row(ip, status_text, ", ".join(rbls))
            else:
                # IP is not listed
                status_text = Text(f"{ICONS['success']} Clean", style="green")
                table.add_row(ip, status_text, "[dim]None[/dim]")
        
        return table
    
    @staticmethod
    def format_security_tree(security_details: Dict[str, Any]) -> Tree:
        """Display security findings in hierarchical Tree structure.
        
        Creates a tree view of security check results including SPF, DMARC,
        DKIM, DNSSEC, and security headers with status indicators.
        
        Args:
            security_details: Dictionary containing security check results with keys:
                            - spf: SPF check results
                            - dmarc: DMARC check results
                            - dkim: DKIM check results
                            - dnssec: DNSSEC check results
                            - security_headers: HTTP security headers results
            
        Returns:
            Tree: Rich Tree containing formatted security findings
            
        Requirements: 4.3
        """
        tree = Tree("[bold]Security Checks[/bold]")
        
        if not security_details:
            tree.add("[dim]No security checks performed[/dim]")
            return tree
        
        # SPF Check
        if 'spf' in security_details:
            spf = security_details['spf']
            status = spf.get('status', 'UNKNOWN')
            message = spf.get('message', 'No message')
            
            status_icon = ICONS['success'] if status == 'OK' else ICONS['warning'] if status == 'WARNING' else ICONS['error']
            status_color = STATUS_COLORS.get(status, "white")
            
            spf_label = Text()
            spf_label.append(f"{status_icon} ", style=status_color)
            spf_label.append("SPF: ", style="bold")
            spf_label.append(message, style="white")
            
            spf_branch = tree.add(spf_label)
            if spf.get('record'):
                spf_branch.add(Text(f"Record: {spf['record']}", style="dim"))
        
        # DMARC Check
        if 'dmarc' in security_details:
            dmarc = security_details['dmarc']
            status = dmarc.get('status', 'UNKNOWN')
            message = dmarc.get('message', 'No message')
            
            status_icon = ICONS['success'] if status == 'OK' else ICONS['warning'] if status == 'WARNING' else ICONS['error']
            status_color = STATUS_COLORS.get(status, "white")
            
            dmarc_label = Text()
            dmarc_label.append(f"{status_icon} ", style=status_color)
            dmarc_label.append("DMARC: ", style="bold")
            dmarc_label.append(message, style="white")
            
            dmarc_branch = tree.add(dmarc_label)
            if dmarc.get('record'):
                dmarc_branch.add(Text(f"Record: {dmarc['record']}", style="dim"))
        
        # DKIM Check
        if 'dkim' in security_details:
            dkim = security_details['dkim']
            status = dkim.get('status', 'UNKNOWN')
            message = dkim.get('message', 'No message')
            
            status_icon = ICONS['success'] if status == 'OK' else ICONS['warning'] if status == 'WARNING' else ICONS['info']
            status_color = STATUS_COLORS.get(status, "white") if status != 'SKIPPED' else "dim"
            
            dkim_label = Text()
            dkim_label.append(f"{status_icon} ", style=status_color)
            dkim_label.append("DKIM: ", style="bold")
            dkim_label.append(message, style="white" if status != 'SKIPPED' else "dim")
            
            dkim_branch = tree.add(dkim_label)
            
            # Show selector details if available
            if 'selectors' in dkim and dkim['selectors']:
                for selector, selector_info in dkim['selectors'].items():
                    found = selector_info.get('found', False)
                    selector_icon = ICONS['success'] if found else ICONS['error']
                    selector_color = "green" if found else "red"
                    selector_text = Text()
                    selector_text.append(f"{selector_icon} ", style=selector_color)
                    selector_text.append(f"{selector}: ", style="dim")
                    selector_text.append("Found" if found else "Not found", style=selector_color)
                    dkim_branch.add(selector_text)
        
        # DNSSEC Check
        if 'dnssec' in security_details:
            dnssec = security_details['dnssec']
            status = dnssec.get('status', 'UNKNOWN')
            message = dnssec.get('message', 'No message')
            
            status_icon = ICONS['success'] if status == 'OK' else ICONS['warning'] if status == 'WARNING' else ICONS['error']
            status_color = STATUS_COLORS.get(status, "white")
            
            dnssec_label = Text()
            dnssec_label.append(f"{status_icon} ", style=status_color)
            dnssec_label.append("DNSSEC: ", style="bold")
            dnssec_label.append(message, style="white")
            
            tree.add(dnssec_label)
        
        # Security Headers Check
        if 'security_headers' in security_details:
            headers = security_details['security_headers']
            status = headers.get('status', 'UNKNOWN')
            message = headers.get('message', 'No message')
            
            status_icon = ICONS['success'] if status == 'OK' else ICONS['warning'] if status == 'WARNING' else ICONS['error']
            status_color = STATUS_COLORS.get(status, "white")
            
            headers_label = Text()
            headers_label.append(f"{status_icon} ", style=status_color)
            headers_label.append("Security Headers: ", style="bold")
            headers_label.append(message, style="white")
            
            headers_branch = tree.add(headers_label)
            
            # Show missing headers if any
            if 'missing_headers' in headers and headers['missing_headers']:
                for header in headers['missing_headers']:
                    header_text = Text()
                    header_text.append(f"{ICONS['error']} ", style="red")
                    header_text.append(f"Missing: {header}", style="dim")
                    headers_branch.add(header_text)
        
        return tree
    
    @staticmethod
    def format_ssl_info(ssl_details: Dict[str, Any]) -> Table:
        """Display SSL certificate information in Table format with expiry countdown.
        
        Creates a formatted table showing SSL certificate details including
        issuer, subject, SANs, expiration date, and days until expiry with
        color-coded countdown.
        
        Args:
            ssl_details: Dictionary containing SSL certificate details with keys:
                        - issuer: Certificate issuer
                        - subject: Certificate subject
                        - sans: List of Subject Alternative Names
                        - expiration_date: Expiration date (ISO format string)
                        - days_until_expiry: Days until certificate expires
            
        Returns:
            Table: Rich Table containing formatted SSL certificate information
            
        Requirements: 4.4
        """
        table = Table(title="SSL Certificate Information", show_header=True, header_style="bold cyan")
        table.add_column("Property", style="cyan", width=20)
        table.add_column("Value", style="white")
        
        if not ssl_details:
            table.add_row("[dim]No SSL information[/dim]", "")
            return table
        
        # Issuer
        if 'issuer' in ssl_details:
            table.add_row("Issuer", ssl_details['issuer'])
        
        # Subject
        if 'subject' in ssl_details:
            table.add_row("Subject", ssl_details['subject'])
        
        # SANs (Subject Alternative Names)
        if 'sans' in ssl_details:
            sans = ssl_details['sans']
            if sans:
                sans_text = ", ".join(sans[:3])  # Show first 3
                if len(sans) > 3:
                    sans_text += f" (+{len(sans) - 3} more)"
                table.add_row("SANs", sans_text)
            else:
                table.add_row("SANs", "[dim]None[/dim]")
        
        # Expiration Date
        if 'expiration_date' in ssl_details:
            expiration_str = ssl_details['expiration_date']
            # Parse ISO format and display in readable format
            try:
                expiration_dt = datetime.fromisoformat(expiration_str.replace('Z', '+00:00'))
                formatted_date = expiration_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                table.add_row("Expires", formatted_date)
            except (ValueError, AttributeError):
                table.add_row("Expires", expiration_str)
        
        # Days Until Expiry (with color coding)
        if 'days_until_expiry' in ssl_details:
            days = ssl_details['days_until_expiry']
            
            # Color code based on days remaining
            if days < 0:
                expiry_text = Text(f"{abs(days)} days ago (EXPIRED)", style="bold red")
            elif days < 7:
                expiry_text = Text(f"{days} days (CRITICAL)", style="bold red")
            elif days < 14:
                expiry_text = Text(f"{days} days (WARNING)", style="yellow")
            elif days < 30:
                expiry_text = Text(f"{days} days", style="white")
            else:
                expiry_text = Text(f"{days} days", style="green")
            
            table.add_row("Days Until Expiry", expiry_text)
        
        return table
    
    @staticmethod
    def format_whois_info(whois_details: Dict[str, Any]) -> Table:
        """Display WHOIS information in Table format.
        
        Creates a formatted table showing WHOIS registration details including
        registrar, country, status, expiration date, and days until expiry with
        color-coded countdown.
        
        Args:
            whois_details: Dictionary containing WHOIS details with keys:
                          - registrar: Domain registrar name
                          - country: Country code or name
                          - status: Domain status
                          - expiration_date: Expiration date (ISO format string)
                          - days_until_expiry: Days until domain expires
            
        Returns:
            Table: Rich Table containing formatted WHOIS information
        """
        table = Table(title="WHOIS Information", show_header=True, header_style="bold cyan")
        table.add_column("Property", style="cyan", width=20)
        table.add_column("Value", style="white")
        
        if not whois_details:
            table.add_row("[dim]No WHOIS information[/dim]", "")
            return table
        
        # Registrar (등록 대행사)
        if 'registrar' in whois_details and whois_details['registrar']:
            table.add_row("Registrar", whois_details['registrar'])
        else:
            table.add_row("Registrar", "[dim]Not available[/dim]")
        
        # Country (국가)
        if 'country' in whois_details and whois_details['country']:
            table.add_row("Country", whois_details['country'])
        else:
            table.add_row("Country", "[dim]Not available[/dim]")
        
        # Status
        if 'status' in whois_details and whois_details['status']:
            table.add_row("Status", whois_details['status'])
        
        # Expiration Date
        if 'expiration_date' in whois_details:
            expiration_str = whois_details['expiration_date']
            # Parse ISO format and display in readable format
            try:
                expiration_dt = datetime.fromisoformat(expiration_str.replace('Z', '+00:00'))
                formatted_date = expiration_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                table.add_row("Expires", formatted_date)
            except (ValueError, AttributeError):
                table.add_row("Expires", expiration_str)
        
        # Days Until Expiry (with color coding)
        if 'days_until_expiry' in whois_details:
            days = whois_details['days_until_expiry']
            
            # Color code based on days remaining
            if days < 0:
                expiry_text = Text(f"{abs(days)} days ago (EXPIRED)", style="bold red")
            elif days < 30:
                expiry_text = Text(f"{days} days (CRITICAL)", style="bold red")
            elif days < 60:
                expiry_text = Text(f"{days} days (WARNING)", style="yellow")
            elif days < 90:
                expiry_text = Text(f"{days} days", style="white")
            else:
                expiry_text = Text(f"{days} days", style="green")
            
            table.add_row("Days Until Expiry", expiry_text)
        
        return table
    
    @staticmethod
    def format_performance_table(results: List[DomainResult]) -> Table:
        """Display execution time metrics in Table format.
        
        Creates a formatted table showing performance metrics for all domain checks
        including execution times, highlighting slow checks, and displaying aggregate
        statistics (average, min, max, fastest, slowest).
        
        Args:
            results: List of DomainResult objects from all domain checks
            
        Returns:
            Table: Rich Table containing formatted performance metrics
            
        Requirements: 10.1, 10.2, 10.3, 10.4, 10.5
        """
        table = Table(
            title="Performance Metrics",
            show_header=True,
            header_style="bold cyan"
        )
        table.add_column("Domain", style="cyan", width=30)
        table.add_column("Execution Time", style="white", justify="right", width=20)
        table.add_column("Status", style="white", width=15)
        
        if not results:
            table.add_row("[dim]No results[/dim]", "", "")
            return table
        
        # Calculate aggregate statistics (Requirements: 10.3, 10.4)
        execution_times = [r.execution_time for r in results]
        total_time = sum(execution_times)
        avg_time = total_time / len(results)
        min_time = min(execution_times)
        max_time = max(execution_times)
        
        # Find fastest and slowest domains (Requirements: 10.4)
        fastest_result = min(results, key=lambda r: r.execution_time)
        slowest_result = max(results, key=lambda r: r.execution_time)
        
        # Identify slow checks (> 5 seconds) (Requirements: 10.2)
        slow_checks = [r for r in results if r.execution_time > 5.0]
        
        # Add rows for each domain (Requirements: 10.1)
        for result in sorted(results, key=lambda r: r.execution_time, reverse=True):
            domain_name = result.domain
            exec_time = result.execution_time
            
            # Format execution time
            time_text = Text(f"{exec_time:.2f}s")
            
            # Highlight slow checks (Requirements: 10.2)
            if exec_time > 5.0:
                status_text = Text(f"{ICONS['warning']} SLOW", style="yellow")
                time_text.stylize("yellow")
            else:
                status_text = Text(f"{ICONS['success']} OK", style="green")
            
            # Highlight fastest and slowest (Requirements: 10.4)
            if result.domain == fastest_result.domain:
                domain_text = Text(f"{domain_name} ", style="cyan")
                domain_text.append(f"{ICONS['success']} Fastest", style="green")
                table.add_row(domain_text, time_text, status_text)
            elif result.domain == slowest_result.domain:
                domain_text = Text(f"{domain_name} ", style="cyan")
                domain_text.append(f"{ICONS['time']} Slowest", style="red")
                table.add_row(domain_text, time_text, status_text)
            else:
                table.add_row(domain_name, time_text, status_text)
        
        # Add separator
        table.add_row("", "", "")
        
        # Add aggregate statistics (Requirements: 10.3)
        table.add_row(
            Text("Average", style="bold"),
            Text(f"{avg_time:.2f}s", style="bold white"),
            ""
        )
        table.add_row(
            Text("Minimum", style="bold"),
            Text(f"{min_time:.2f}s", style="bold green"),
            ""
        )
        table.add_row(
            Text("Maximum", style="bold"),
            Text(f"{max_time:.2f}s", style="bold red"),
            ""
        )
        table.add_row(
            Text("Total", style="bold"),
            Text(f"{total_time:.2f}s", style="bold white"),
            ""
        )
        
        # Add slow checks summary if any (Requirements: 10.2)
        if slow_checks:
            table.add_row("", "", "")
            table.add_row(
                Text(f"Slow Checks (>{5}s)", style="bold yellow"),
                Text(f"{len(slow_checks)}", style="bold yellow"),
                ""
            )
        
        return table
