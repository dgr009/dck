"""
Executor layer for domain monitoring.

Orchestrates parallel execution of all checks for all domains,
handles timeouts and errors gracefully, and aggregates results.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, TYPE_CHECKING

from .config import ManifestConfig, DomainConfig
from .checkers.base_checker import BaseChecker, CheckResult
from .checkers.whois import WhoisChecker
from .checkers.ssl import SSLChecker
from .checkers.http import HTTPChecker
from .checkers.dns import DNSChecker
from .checkers.security import SecurityChecker
from .checkers.rbl import RBLChecker

if TYPE_CHECKING:
    from .console.output import ConsoleManager


logger = logging.getLogger(__name__)


@dataclass
class DomainResult:
    """
    Aggregated result for all checks on a single domain.
    
    Attributes:
        domain: The domain name
        tags: Tags associated with the domain
        results: Dictionary mapping check types to CheckResult objects
        overall_status: Worst status among all checks
        execution_time: Time taken to execute all checks in seconds
        timestamp: When the checks were executed
    """
    domain: str
    tags: List[str]
    results: Dict[str, CheckResult]
    overall_status: str
    execution_time: float
    timestamp: datetime = field(default_factory=datetime.now)


class DomainExecutor:
    """
    Executor for running domain checks in parallel.
    
    Manages the execution of all enabled checks for all domains,
    with concurrency limits and graceful error handling.
    """
    
    # Maximum number of domains to check concurrently
    MAX_CONCURRENT_DOMAINS = 20
    
    def __init__(self, config: ManifestConfig, console_manager: Optional['ConsoleManager'] = None):
        """
        Initialize the executor with manifest configuration.
        
        Args:
            config: ManifestConfig containing domains and check settings
            console_manager: Optional ConsoleManager for progress display
            
        Requirements: 15.1, 2.1
        """
        self.config = config
        self.console_manager = console_manager
        self.checkers = self._initialize_checkers()
    
    def _initialize_checkers(self) -> Dict[str, BaseChecker]:
        """
        Create instances of all checker classes.
        
        Instantiates one instance of each checker type that can be
        reused for all domain checks.
        
        Returns:
            Dictionary mapping check type names to checker instances
            
        Requirements: 15.1
        """
        return {
            'whois': WhoisChecker(timeout=5),
            'ssl': SSLChecker(timeout=5),
            'http': HTTPChecker(timeout=5),
            'dns': DNSChecker(timeout=5),
            'security': SecurityChecker(timeout=5),
            'rbl': RBLChecker(timeout=5),
        }

    async def execute_all(self) -> List[DomainResult]:
        """
        Execute all checks for all domains concurrently.
        
        Runs checks for all domains in parallel with a semaphore to limit
        concurrent executions. Returns aggregated results for all domains.
        Displays progress using ProgressTracker if ConsoleManager is available.
        
        Returns:
            List of DomainResult objects, one per domain
            
        Requirements: 15.1, 15.2, 2.1, 2.2, 2.3, 2.4, 2.5
        """
        logger.info(f"Starting checks for {len(self.config.domains)} domain(s)")
        start_time = time.time()
        
        # Create ProgressTracker if ConsoleManager is available (Requirements: 2.1)
        progress_tracker = None
        if self.console_manager:
            from .console.progress import ProgressTracker
            progress_tracker = ProgressTracker(
                self.console_manager.console,
                len(self.config.domains)
            )
            progress_tracker.start()
        
        # Create semaphore to limit concurrent domain checks (Requirements: 15.2)
        semaphore = asyncio.Semaphore(self.MAX_CONCURRENT_DOMAINS)
        
        async def bounded_execute(domain: DomainConfig) -> DomainResult:
            """Execute domain checks with semaphore limit and progress updates."""
            async with semaphore:
                # Update progress when starting domain check (Requirements: 2.2)
                if progress_tracker:
                    progress_tracker.update_domain(domain.name)
                
                result = await self.execute_domain(domain)
                
                # Update progress when completing domain check (Requirements: 2.3)
                if progress_tracker:
                    progress_tracker.complete_domain(domain.name, result.overall_status)
                
                return result
        
        # Execute all domain checks in parallel (Requirements: 15.1)
        tasks = [bounded_execute(domain) for domain in self.config.domains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and log them (Requirements: 7.1, 7.2, 7.4)
        domain_results = []
        execution_errors = []
        
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                domain_name = self.config.domains[i].name
                logger.error(f"Failed to execute checks for {domain_name}: {str(result)}", exc_info=True)
                
                # Collect error for grouped display (Requirements: 7.4)
                execution_errors.append({
                    'message': str(result),
                    'error_type': type(result).__name__,
                    'domain': domain_name,
                    'check_type': 'execution',
                    'exception': result
                })
                
                # Create error result for this domain
                error_result = DomainResult(
                    domain=domain_name,
                    tags=self.config.domains[i].tags,
                    results={},
                    overall_status=CheckResult.ERROR,
                    execution_time=0.0
                )
                domain_results.append(error_result)
            else:
                domain_results.append(result)
        
        # Display grouped errors if any occurred (Requirements: 7.4)
        if execution_errors and self.console_manager:
            self.console_manager.print_error_group(execution_errors)
        
        total_time = time.time() - start_time
        
        # Display total execution time (Requirements: 2.5)
        if progress_tracker:
            progress_tracker.finish(total_time)
        
        logger.info(f"Completed all checks in {total_time:.2f}s")
        
        return domain_results
    
    async def execute_domain(self, domain: DomainConfig) -> DomainResult:
        """
        Execute all enabled checks for a single domain in parallel.
        
        Runs all enabled checks concurrently, handles failures gracefully,
        and aggregates the results.
        
        Args:
            domain: DomainConfig for the domain to check
            
        Returns:
            DomainResult with all check results and aggregated status
            
        Requirements: 15.3
        """
        logger.debug(f"Starting checks for domain: {domain.name}")
        start_time = time.time()
        
        # Determine which checks to run
        checks_to_run = domain.checks if domain.checks else self.config.default_checks
        
        # Create tasks for all enabled checks (Requirements: 15.3)
        tasks = []
        check_types = []
        
        for check_type in checks_to_run:
            if check_type not in self.checkers:
                logger.warning(f"Unknown check type '{check_type}' for domain {domain.name}")
                continue
            
            checker = self.checkers[check_type]
            
            # Prepare kwargs for the check
            kwargs = {}
            if check_type == 'security' and domain.dkim_selectors:
                kwargs['dkim_selectors'] = domain.dkim_selectors
            
            # Wrap check in safe_check for error handling
            task = safe_check(checker, domain.name, **kwargs)
            tasks.append(task)
            check_types.append(check_type)
        
        # Execute all checks in parallel (Requirements: 15.3)
        check_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Build results dictionary and collect errors (Requirements: 7.1, 7.2)
        results = {}
        check_errors = []
        
        for check_type, result in zip(check_types, check_results):
            if isinstance(result, Exception):
                # Create error result for failed check
                error_msg = str(result) if str(result) else f"{type(result).__name__} occurred"
                logger.error(f"Check {check_type} failed for {domain.name}: {error_msg}", exc_info=True)
                
                # Collect error details (Requirements: 7.2)
                check_errors.append({
                    'message': error_msg,
                    'error_type': type(result).__name__,
                    'domain': domain.name,
                    'check_type': check_type,
                    'exception': result
                })
                
                results[check_type] = CheckResult(
                    domain=domain.name,
                    check_type=check_type,
                    status=CheckResult.ERROR,
                    message=f"Check failed: {error_msg}",
                    details={'error_type': type(result).__name__}
                )
            else:
                results[check_type] = result
        
        # Log check errors for debugging (Requirements: 7.1)
        if check_errors:
            logger.debug(f"Domain {domain.name} had {len(check_errors)} check error(s)")
        
        # Calculate overall status (Requirements: 15.4)
        overall_status = self._calculate_overall_status(results)
        
        # Measure execution time (Requirements: 15.4)
        execution_time = time.time() - start_time
        
        logger.debug(f"Completed checks for {domain.name} in {execution_time:.2f}s")
        
        return DomainResult(
            domain=domain.name,
            tags=domain.tags,
            results=results,
            overall_status=overall_status,
            execution_time=execution_time
        )
    
    def _calculate_overall_status(self, results: Dict[str, CheckResult]) -> str:
        """
        Calculate overall status based on critical checks and overall health.
        
        Critical checks: HTTP, SSL, WHOIS
        - If any critical check is ERROR/CRITICAL -> Overall is ERROR/CRITICAL
        - If critical checks are OK/WARNING and no other ERROR/CRITICAL -> Overall is OK
        - If critical checks are OK but have WARNINGs -> Overall is WARNING
        
        Args:
            results: Dictionary of check results
            
        Returns:
            Overall status string
            
        Requirements: 15.4
        """
        if not results:
            return CheckResult.OK
        
        # Define critical checks that must pass
        critical_checks = ['http', 'ssl', 'whois']
        
        # Check critical checks first
        has_critical_error = False
        has_critical_warning = False
        
        for check_type in critical_checks:
            if check_type in results:
                status = results[check_type].status
                if status in [CheckResult.ERROR, CheckResult.CRITICAL]:
                    has_critical_error = True
                elif status == CheckResult.WARNING:
                    has_critical_warning = True
        
        # If critical checks have errors, overall is error
        if has_critical_error:
            return CheckResult.ERROR
        
        # Check for any CRITICAL status in non-critical checks
        for check_type, check_result in results.items():
            if check_result.status == CheckResult.CRITICAL:
                return CheckResult.CRITICAL
        
        # Check for any ERROR status in non-critical checks
        for check_type, check_result in results.items():
            if check_result.status == CheckResult.ERROR:
                return CheckResult.ERROR
        
        # If we have warnings (critical or non-critical), return WARNING
        if has_critical_warning:
            return CheckResult.WARNING
        
        for check_result in results.values():
            if check_result.status == CheckResult.WARNING:
                return CheckResult.WARNING
        
        # All checks passed
        return CheckResult.OK


async def safe_check(checker: BaseChecker, domain: str, **kwargs) -> CheckResult:
    """
    Wrapper to handle checker calls with timeout and error handling.
    
    Wraps checker execution with timeout and exception handling to ensure
    that failures in one check don't block other checks. Provides detailed
    error context for debugging.
    
    Args:
        checker: The checker instance to execute
        domain: The domain name to check
        **kwargs: Additional parameters for the check
        
    Returns:
        CheckResult from the checker, or ERROR CheckResult on failure
        
    Requirements: 15.3, 7.1, 7.2
    """
    check_type = checker.__class__.__name__.replace('Checker', '').lower()
    
    try:
        # Execute check with timeout
        result = await asyncio.wait_for(
            checker.check(domain, **kwargs),
            timeout=checker.timeout
        )
        return result
        
    except asyncio.TimeoutError:
        # Check timed out (Requirements: 15.3, 7.2)
        error_msg = f"Check timed out after {checker.timeout}s"
        logger.error(f"{check_type} check timed out for {domain} after {checker.timeout}s")
        return CheckResult(
            domain=domain,
            check_type=check_type,
            status=CheckResult.ERROR,
            message=error_msg,
            details={
                "error_type": "TimeoutError",
                "timeout_seconds": checker.timeout
            }
        )
    
    except ConnectionRefusedError as e:
        # Connection refused (Requirements: 7.2, 7.5)
        error_msg = f"Connection refused: {str(e)}"
        logger.error(f"{check_type} check failed for {domain}: {error_msg}", exc_info=True)
        return CheckResult(
            domain=domain,
            check_type=check_type,
            status=CheckResult.ERROR,
            message=error_msg,
            details={
                "error_type": "ConnectionRefusedError",
                "suggestion": "The server is not accepting connections. Verify the service is running."
            }
        )
    
    except TimeoutError as e:
        # Network timeout (Requirements: 7.2, 7.5)
        error_msg = f"Network timeout: {str(e)}"
        logger.error(f"{check_type} check failed for {domain}: {error_msg}", exc_info=True)
        return CheckResult(
            domain=domain,
            check_type=check_type,
            status=CheckResult.ERROR,
            message=error_msg,
            details={
                "error_type": "TimeoutError",
                "suggestion": "Check network connectivity and firewall settings."
            }
        )
        
    except Exception as e:
        # Check failed with exception (Requirements: 15.3, 7.1, 7.2)
        error_msg = str(e) if str(e) else f"{type(e).__name__} occurred"
        logger.error(
            f"{check_type} check failed for {domain}: {error_msg}",
            exc_info=True
        )
        return CheckResult(
            domain=domain,
            check_type=check_type,
            status=CheckResult.ERROR,
            message=f"Check failed: {error_msg}",
            details={
                "error_type": type(e).__name__,
                "full_error": str(e)
            }
        )
