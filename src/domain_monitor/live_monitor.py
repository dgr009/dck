"""Live monitoring orchestrator for real-time domain status monitoring."""

import asyncio
import signal
import time
from datetime import datetime
from typing import List
import logging
import aiohttp

from .live_display import LiveDisplay
from .models import EndpointConfig, EndpointStatus
from .state_tracker import StateTracker

logger = logging.getLogger(__name__)


class LiveMonitor:
    """Orchestrates the live monitoring process, managing the monitoring loop and coordinating between components."""
    
    def __init__(
        self,
        endpoints: List[EndpointConfig],
        interval: float = 1.0,
        log_file: str = "logs/live-monitor.log"
    ):
        """Initialize live monitor with endpoint configurations and settings.
        
        Args:
            endpoints: List of EndpointConfig objects to monitor
            interval: Check interval in seconds (default: 1.0)
            log_file: Path to status change log file
        """
        self.endpoints = endpoints
        self.interval = interval
        self.log_file = log_file
        
        # Initialize components
        self.state_tracker = StateTracker(log_file)
        self.live_display = LiveDisplay()
        
        # Control flags
        self._running = False
        self._shutdown_requested = False
        
        # Setup signal handlers for graceful shutdown
        self._setup_signal_handlers()
    
    def _setup_signal_handlers(self) -> None:
        """Register signal handlers for graceful shutdown."""
        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)
    
    def _handle_shutdown(self, signum, frame) -> None:
        """Handle CTRL+C gracefully.
        
        Args:
            signum: Signal number
            frame: Current stack frame
        """
        if not self._shutdown_requested:
            self._shutdown_requested = True
            self._running = False

    async def start(self) -> None:
        """Start the live monitoring loop."""
        if self._running:
            return
        
        self._running = True
        self._shutdown_requested = False
        
        # Start the live display
        self.live_display.start()
        
        try:
            # Run the monitoring loop
            await self._monitoring_loop()
        finally:
            # Ensure cleanup happens
            await self.stop()
    
    async def stop(self) -> None:
        """Stop monitoring and cleanup."""
        self._running = False
        
        # Stop the live display
        self.live_display.stop()
        
        # Write final summary to log
        self.state_tracker.write_summary()
    
    async def _monitoring_loop(self) -> None:
        """Main monitoring loop that runs every interval."""
        while self._running and not self._shutdown_requested:
            loop_start = time.time()
            
            # Check all endpoints concurrently
            statuses = await self._check_all_endpoints()
            
            # Update state tracker with new statuses
            for status in statuses:
                endpoint_id = status.config.get_identifier()
                self.state_tracker.update(endpoint_id, status)
            
            # Update live display
            self.live_display.update(statuses)
            
            # Calculate sleep time to maintain interval
            elapsed = time.time() - loop_start
            sleep_time = max(0, self.interval - elapsed)
            
            if sleep_time > 0 and self._running and not self._shutdown_requested:
                try:
                    await asyncio.sleep(sleep_time)
                except asyncio.CancelledError:
                    break
    
    async def _check_all_endpoints(self) -> List[EndpointStatus]:
        """Check all endpoints concurrently and return results.
        
        Returns:
            List of EndpointStatus objects for all endpoints
        """
        # Create tasks for all endpoints
        tasks = [self._check_endpoint(config) for config in self.endpoints]
        
        # Run all checks concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and return valid statuses
        statuses = []
        for result in results:
            if isinstance(result, EndpointStatus):
                statuses.append(result)
            elif isinstance(result, Exception):
                # Log exception but continue with other endpoints
                logger.warning(f"Exception during endpoint check: {result}")
        
        return statuses
    
    async def _check_endpoint(self, config: EndpointConfig) -> EndpointStatus:
        """Perform HTTP check on a single endpoint with custom configuration.
        
        Note: This method does NOT log or store request/response bodies for security.
        Only status codes and sanitized error messages are captured.
        
        Args:
            config: EndpointConfig object with request configuration
            
        Returns:
            EndpointStatus object with check results
        """
        start_time = time.time()
        timestamp = datetime.now()
        
        try:
            # Create aiohttp session and perform request
            # Note: We do NOT read or log the response body for security
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method=config.method,
                    url=config.url,
                    headers=config.headers,
                    data=config.body,
                    timeout=aiohttp.ClientTimeout(total=config.timeout),
                    ssl=False  # Disable SSL verification (same as existing checker)
                ) as response:
                    response_time = time.time() - start_time
                    
                    # Do NOT read response body - we only care about status code
                    return EndpointStatus(
                        config=config,
                        status_code=response.status,
                        response_time=response_time,
                        error=None,
                        timestamp=timestamp
                    )
            
        except asyncio.TimeoutError:
            # Handle connection timeout
            response_time = time.time() - start_time
            logger.debug(f"Timeout checking {config.get_identifier()}")
            return EndpointStatus(
                config=config,
                status_code=None,
                response_time=response_time,
                error="Connection timeout",
                timestamp=timestamp
            )
            
        except aiohttp.ClientConnectorError as e:
            # Handle connection errors (refused, DNS failures, etc.)
            # Sanitize error message to prevent sensitive data exposure
            from .models import sanitize_string
            
            response_time = time.time() - start_time
            error_msg = str(e)
            
            # Provide more specific error messages for common cases
            if "Name or service not known" in error_msg or "nodename nor servname provided" in error_msg:
                error_msg = "DNS resolution failed"
            elif "Connection refused" in error_msg:
                error_msg = "Connection refused"
            elif "Network is unreachable" in error_msg:
                error_msg = "Network unreachable"
            else:
                # Sanitize and truncate error messages
                error_msg = sanitize_string(error_msg, max_length=100)
            
            logger.debug(f"Connection error checking {config.get_identifier()}: {error_msg}")
            return EndpointStatus(
                config=config,
                status_code=None,
                response_time=response_time,
                error=error_msg,
                timestamp=timestamp
            )
            
        except aiohttp.ClientError as e:
            # Handle other aiohttp client errors
            # Sanitize error message to prevent sensitive data exposure
            from .models import sanitize_string
            
            response_time = time.time() - start_time
            error_msg = str(e) if str(e) else type(e).__name__
            error_msg = sanitize_string(error_msg, max_length=100)
            
            logger.debug(f"Client error checking {config.get_identifier()}: {error_msg}")
            return EndpointStatus(
                config=config,
                status_code=None,
                response_time=response_time,
                error=error_msg,
                timestamp=timestamp
            )
            
        except Exception as e:
            # Handle any other unexpected errors
            # Sanitize error message to prevent sensitive data exposure
            from .models import sanitize_string
            
            response_time = time.time() - start_time
            error_msg = str(e) if str(e) else type(e).__name__
            error_msg = sanitize_string(error_msg, max_length=100)
            
            logger.warning(f"Unexpected error checking {config.get_identifier()}: {error_msg}")
            return EndpointStatus(
                config=config,
                status_code=None,
                response_time=response_time,
                error=error_msg,
                timestamp=timestamp
            )
