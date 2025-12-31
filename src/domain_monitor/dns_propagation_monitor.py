"""
DNS Propagation Monitor for real-time DNS propagation monitoring in watch mode.

This module provides the DNSPropagationMonitor class that orchestrates continuous
DNS propagation checking until propagation is complete or the user interrupts.
"""

import asyncio
import signal
import time
from datetime import datetime
from typing import Optional
import logging

from .checkers.dns_propagation_checker import DNSPropagationChecker
from .dns_propagation_display import DNSPropagationDisplay
from .models import PropagationResult

logger = logging.getLogger(__name__)


class DNSPropagationMonitor:
    """Orchestrates real-time DNS propagation monitoring in watch mode.
    
    This class manages the continuous monitoring loop, handles graceful shutdown
    on CTRL+C, and automatically exits when propagation reaches 100%.
    
    Attributes:
        checker: DNSPropagationChecker instance for performing DNS queries
        display: DNSPropagationDisplay instance for output formatting
        interval: Check interval in seconds between queries
        _running: Flag indicating if monitoring is active
        _shutdown_requested: Flag indicating if shutdown was requested
        _start_time: Timestamp when monitoring started
    """
    
    def __init__(
        self,
        checker: DNSPropagationChecker,
        display: DNSPropagationDisplay,
        interval: float = 5.0
    ):
        """Initialize monitor.
        
        Args:
            checker: DNSPropagationChecker instance
            display: DNSPropagationDisplay instance
            interval: Check interval in seconds (Requirements: 7.5, 7.6)
        """
        self.checker = checker
        self.display = display
        self.interval = interval
        self._running = False
        self._shutdown_requested = False
        self._start_time: Optional[datetime] = None
        self._setup_signal_handlers()
        
        logger.debug(f"Initialized DNSPropagationMonitor with {interval}s interval")
    
    def _setup_signal_handlers(self) -> None:
        """Register signal handlers for graceful shutdown.
        
        Requirements: 7.4
        """
        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)
    
    def _handle_shutdown(self, signum, frame) -> None:
        """Handle CTRL+C gracefully.
        
        Sets shutdown flag to stop monitoring loop and display final results.
        
        Args:
            signum: Signal number
            frame: Current stack frame
            
        Requirements: 7.4
        """
        if not self._shutdown_requested:
            self._shutdown_requested = True
            self._running = False
            logger.info("Shutdown requested by user (CTRL+C)")
            self.display.console.print("\n[yellow]Stopping monitoring...[/yellow]")
    
    async def start(
        self,
        domain: str,
        record_type: str,
        expected_value: Optional[str] = None
    ) -> None:
        """Start monitoring DNS propagation.
        
        Continuously queries DNS servers at the specified interval until either:
        - Propagation reaches 100% (auto-exit)
        - User presses CTRL+C (graceful shutdown)
        
        Args:
            domain: Domain name to monitor
            record_type: DNS record type
            expected_value: Optional expected value for comparison
            
        Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6
        """
        if self._running:
            logger.warning("Monitor is already running")
            return
        
        self._running = True
        self._shutdown_requested = False
        self._start_time = datetime.now()
        
        logger.info(f"Starting DNS propagation monitoring for {domain} ({record_type})")
        if expected_value:
            logger.info(f"Expected value: {expected_value}")
        
        # Display initial message
        self.display.console.print(
            f"\n[bold cyan]Starting DNS propagation monitoring...[/bold cyan]"
        )
        self.display.console.print(
            f"[dim]Press CTRL+C to stop monitoring[/dim]\n"
        )
        
        try:
            # Run the monitoring loop
            await self._monitoring_loop(domain, record_type, expected_value)
        finally:
            # Ensure cleanup happens
            self._running = False
            logger.info("DNS propagation monitoring stopped")
    
    async def _monitoring_loop(
        self,
        domain: str,
        record_type: str,
        expected_value: Optional[str]
    ) -> None:
        """Main monitoring loop that runs every interval.
        
        Continuously checks DNS propagation and updates display until:
        - Propagation is complete (100%)
        - User requests shutdown (CTRL+C)
        
        Args:
            domain: Domain name to monitor
            record_type: DNS record type
            expected_value: Optional expected value for comparison
            
        Requirements: 7.1, 7.2, 7.3, 8.5
        """
        iteration = 0
        last_result: Optional[PropagationResult] = None
        
        while self._running and not self._shutdown_requested:
            iteration += 1
            loop_start = time.time()
            
            try:
                # Check DNS propagation
                result = await self.checker.check_propagation(
                    domain=domain,
                    record_type=record_type,
                    expected_value=expected_value
                )
                
                last_result = result
                
                # Clear screen for clean update (Requirements: 7.2)
                if iteration > 1:
                    # Move cursor up to overwrite previous output
                    # This provides in-place updates without scrolling
                    self.display.console.clear()
                
                # Display elapsed time and update info (Requirements: 8.5)
                elapsed = datetime.now() - self._start_time
                elapsed_str = str(elapsed).split('.')[0]  # Remove microseconds
                
                self.display.console.print(
                    f"[bold]Watch Mode[/bold] - "
                    f"Elapsed: [cyan]{elapsed_str}[/cyan] | "
                    f"Last Update: [cyan]{result.timestamp.strftime('%H:%M:%S')}[/cyan] | "
                    f"Interval: [cyan]{self.interval}s[/cyan]"
                )
                self.display.console.print()
                
                # Display propagation result
                self.display.display_result(result, watch_mode=True)
                
                # Check if propagation is complete (Requirements: 7.3)
                if result.is_complete:
                    logger.info("DNS propagation complete - auto-exiting")
                    self.display.console.print(
                        "\n[bold green]Propagation complete! Exiting watch mode.[/bold green]"
                    )
                    break
                
                # Calculate sleep time to maintain interval
                elapsed_time = time.time() - loop_start
                sleep_time = max(0, self.interval - elapsed_time)
                
                if sleep_time > 0 and self._running and not self._shutdown_requested:
                    # Display next check countdown
                    self.display.console.print(
                        f"\n[dim]Next check in {sleep_time:.1f}s...[/dim]"
                    )
                    
                    try:
                        await asyncio.sleep(sleep_time)
                    except asyncio.CancelledError:
                        break
                        
            except Exception as e:
                logger.error(f"Error during monitoring iteration: {e}", exc_info=True)
                self.display.console.print(
                    f"\n[bold red]Error:[/bold red] {e}"
                )
                
                # Wait before retrying
                if self._running and not self._shutdown_requested:
                    try:
                        await asyncio.sleep(self.interval)
                    except asyncio.CancelledError:
                        break
        
        # Display final results if shutdown was requested
        if self._shutdown_requested and last_result:
            self.display.console.print("\n[bold yellow]Final Results:[/bold yellow]\n")
            self.display.display_result(last_result, watch_mode=False)
