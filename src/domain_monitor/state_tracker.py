"""State tracking and logging for live monitoring."""

from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Union
import logging

from .models import DomainStatus, EndpointStatus, StateChange

logger = logging.getLogger(__name__)


class StateTracker:
    """Tracks status changes and writes logs when changes occur."""
    
    def __init__(self, log_file: str):
        """Initialize state tracker with log file path.
        
        Args:
            log_file: Path to the log file for recording state changes
        """
        self.log_file = log_file
        self._previous_statuses: Dict[str, Union[DomainStatus, EndpointStatus]] = {}
        self._change_count = 0
        self._log_write_failed = False
        
        # Ensure log directory exists
        try:
            log_dir = Path(log_file).parent
            log_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            logger.error(f"Failed to create log directory: {e}")
            self._log_write_failed = True
        
        # Initialize log file with header
        self._write_log(f"[START] Monitoring started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    def update(self, endpoint_id: str, status: Union[DomainStatus, EndpointStatus]) -> None:
        """Update status and log if changed.
        
        Args:
            endpoint_id: Endpoint identifier (method + name for EndpointStatus, domain for DomainStatus)
            status: Current status information (EndpointStatus or DomainStatus)
        """
        if self._has_changed(endpoint_id, status):
            old_status = self._previous_statuses.get(endpoint_id)
            self._log_change(endpoint_id, old_status, status)
            self._change_count += 1
        
        # Update stored status
        self._previous_statuses[endpoint_id] = status
    
    def _has_changed(self, endpoint_id: str, status: Union[DomainStatus, EndpointStatus]) -> bool:
        """Check if status has changed from previous.
        
        Args:
            endpoint_id: Endpoint identifier
            status: Current status information
            
        Returns:
            True if status has changed, False otherwise
        """
        if endpoint_id not in self._previous_statuses:
            # First check for this endpoint - not considered a change
            return False
        
        old_status = self._previous_statuses[endpoint_id]
        
        # Check if status code changed
        if old_status.status_code != status.status_code:
            return True
        
        # Check if error state changed
        old_has_error = old_status.error is not None
        new_has_error = status.error is not None
        
        if old_has_error != new_has_error:
            return True
        
        # If both have errors, check if error message changed significantly
        if old_has_error and new_has_error:
            # Consider it a change if error type changed (simple heuristic)
            old_error_type = old_status.error.split(':')[0] if old_status.error else ""
            new_error_type = status.error.split(':')[0] if status.error else ""
            if old_error_type != new_error_type:
                return True
        
        return False
    
    def _log_change(
        self,
        endpoint_id: str,
        old_status: Optional[Union[DomainStatus, EndpointStatus]],
        new_status: Union[DomainStatus, EndpointStatus]
    ) -> None:
        """Write status change to log file.
        
        Note: This method does NOT log request/response bodies for security.
        Only status codes and sanitized error messages are logged.
        
        Args:
            endpoint_id: Endpoint identifier (includes method for EndpointStatus)
            old_status: Previous status (None if first check)
            new_status: Current status
        """
        # Sanitize error messages before logging
        from .models import sanitize_string
        
        old_error = sanitize_string(old_status.error, max_length=100) if old_status and old_status.error else None
        new_error = sanitize_string(new_status.error, max_length=100) if new_status.error else None
        
        change = StateChange(
            endpoint_id=endpoint_id,
            timestamp=new_status.timestamp,
            old_status_code=old_status.status_code if old_status else None,
            new_status_code=new_status.status_code,
            old_error=old_error,
            new_error=new_error
        )
        
        log_entry = change.format_log_entry()
        self._write_log(log_entry)
    
    def _write_log(self, message: str) -> None:
        """Write message to log file.
        
        Args:
            message: Log message to write
        """
        # Skip if previous write failed
        if self._log_write_failed:
            return
        
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(message + '\n')
                f.flush()  # Ensure immediate write
        except PermissionError as e:
            # Permission denied - log once and disable further writes
            if not self._log_write_failed:
                logger.error(f"Permission denied writing to log file '{self.log_file}': {e}")
                print(f"⚠️  Warning: Cannot write to log file (permission denied)", flush=True)
                self._log_write_failed = True
        except OSError as e:
            # Disk full or other OS error - log once and disable further writes
            if not self._log_write_failed:
                logger.error(f"Failed to write to log file '{self.log_file}': {e}")
                print(f"⚠️  Warning: Cannot write to log file: {e}", flush=True)
                self._log_write_failed = True
        except Exception as e:
            # Unexpected error - log but don't disable writes
            logger.warning(f"Unexpected error writing to log file: {e}")
    
    def write_summary(self) -> None:
        """Write final summary on shutdown."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        summary = f"{timestamp} [SUMMARY] Monitoring stopped. Total changes: {self._change_count}"
        self._write_log(summary)
