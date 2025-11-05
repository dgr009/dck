"""
HTTP/HTTPS status checker for domain monitoring.

Checks HTTP/HTTPS accessibility, status codes, and redirect chains.
"""

import asyncio
import logging
import time
from typing import Any, List, Tuple

import aiohttp

from .base_checker import BaseChecker, CheckResult

logger = logging.getLogger(__name__)


class HTTPChecker(BaseChecker):
    """
    Checker for HTTP/HTTPS status and accessibility.
    
    Sends HTTP GET requests to domains, follows redirects, and evaluates
    status codes to determine domain accessibility.
    """
    
    async def check(self, domain: str, **kwargs) -> CheckResult:
        """
        Check HTTP/HTTPS status for the specified domain.
        
        Sends a GET request to the domain's root URL, follows redirects,
        and evaluates the final status code.
        
        Args:
            domain: The domain name to check
            **kwargs: Additional parameters (unused)
            
        Returns:
            CheckResult with HTTP status and redirect information
            
        Requirements: 5.1, 5.2
        """
        check_start_time = time.time()
        logger.debug(f"Starting HTTP check for domain: {domain}")
        
        try:
            # Try HTTPS first, fall back to HTTP if needed
            for protocol in ['https', 'http']:
                url = f"{protocol}://{domain}"
                logger.debug(f"Attempting {protocol.upper()} request to {url}")
                
                try:
                    request_start = time.time()
                    status_code, redirect_chain, response_headers = await self._make_request(url)
                    request_time = time.time() - request_start
                    
                    logger.debug(f"HTTP request to {url} completed: status={status_code}, time={request_time:.3f}s")
                    
                    # Log response details in debug mode
                    if redirect_chain:
                        logger.debug(f"Redirect chain for {domain}: {' -> '.join(redirect_chain)}")
                    
                    logger.debug(f"Response headers for {domain}: {dict(response_headers)}")
                    
                    # Determine status based on status code
                    status = self._determine_status(status_code)
                    
                    # Create appropriate message
                    if redirect_chain:
                        message = f"HTTP {status_code} (followed {len(redirect_chain)} redirect(s))"
                    else:
                        message = f"HTTP {status_code}"
                    
                    # Build details
                    details = {
                        'status_code': status_code,
                        'protocol': protocol,
                        'final_url': redirect_chain[-1] if redirect_chain else url,
                        'request_time': request_time,
                        'total_check_time': time.time() - check_start_time
                    }
                    
                    if redirect_chain:
                        details['redirect_chain'] = redirect_chain
                    
                    # Include response headers in debug mode
                    details['response_headers'] = dict(response_headers)
                    
                    logger.debug(f"HTTP check completed for {domain} in {details['total_check_time']:.3f}s")
                    
                    return self._create_result(
                        domain=domain,
                        status=status,
                        message=message,
                        details=details
                    )
                    
                except aiohttp.ClientSSLError as e:
                    logger.debug(f"SSL error on {protocol.upper()} for {domain}: {str(e)}")
                    # SSL error on HTTPS, try HTTP
                    if protocol == 'https':
                        continue
                    raise
                except aiohttp.ClientConnectorError as e:
                    logger.debug(f"Connection error on {protocol.upper()} for {domain}: {str(e)}")
                    # Connection error, try next protocol
                    if protocol == 'https':
                        continue
                    raise
            
            # If we get here, both protocols failed
            logger.warning(f"Failed to connect to {domain} via both HTTPS and HTTP")
            return self._create_result(
                domain=domain,
                status=CheckResult.ERROR,
                message="Failed to connect via HTTPS or HTTP"
            )
            
        except asyncio.TimeoutError:
            logger.warning(f"HTTP request to {domain} timed out after {self.timeout}s")
            return self._create_result(
                domain=domain,
                status=CheckResult.ERROR,
                message=f"Request timed out after {self.timeout}s"
            )
        except aiohttp.ClientError as e:
            logger.error(f"HTTP request failed for {domain}: {str(e)}", exc_info=True)
            return self._create_result(
                domain=domain,
                status=CheckResult.ERROR,
                message=f"HTTP request failed: {str(e)}"
            )
        except Exception as e:
            logger.error(f"HTTP check failed for {domain}: {str(e)}", exc_info=True)
            return self._create_result(
                domain=domain,
                status=CheckResult.ERROR,
                message=f"HTTP check failed: {str(e)}"
            )
    
    async def _make_request(self, url: str) -> Tuple[int, List[str], Any]:
        """
        Send HTTP GET request and track redirect chain.
        
        Sends a GET request to the specified URL, follows redirects,
        and returns the final status code along with the redirect chain.
        
        Args:
            url: The URL to request
            
        Returns:
            Tuple of (final_status_code, redirect_chain, response_headers)
            redirect_chain is a list of URLs in the redirect path
            
        Raises:
            aiohttp.ClientError: If request fails
            asyncio.TimeoutError: If request times out
            
        Requirements: 5.1, 5.2, 5.3
        """
        redirect_chain = []
        
        # Configure timeout
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(timeout=timeout) as session:
            # Use allow_redirects=True to follow redirects automatically
            # We'll track the history to build the redirect chain
            async with session.get(
                url,
                allow_redirects=True,
                ssl=False  # Don't verify SSL to avoid certificate issues blocking checks
            ) as response:
                # Build redirect chain from history (Requirements: 5.3)
                if response.history:
                    redirect_chain = [str(resp.url) for resp in response.history]
                    redirect_chain.append(str(response.url))
                
                return response.status, redirect_chain, response.headers
    
    def _determine_status(self, status_code: int) -> str:
        """
        Determine check status based on HTTP status code.
        
        Status levels:
        - GREEN (OK): 200 status code
        - YELLOW (WARNING): 3xx redirect status codes
        - RED (ERROR): 4xx client errors or 5xx server errors
        
        Args:
            status_code: HTTP status code from response
            
        Returns:
            Status string (OK, WARNING, or ERROR)
            
        Requirements: 5.4, 5.5, 5.6
        """
        if status_code == 200:
            # Success (Requirements: 5.4)
            return CheckResult.OK
        elif 300 <= status_code < 400:
            # Redirect (Requirements: 5.5)
            return CheckResult.WARNING
        elif 400 <= status_code < 600:
            # Client or server error (Requirements: 5.6)
            return CheckResult.ERROR
        else:
            # Other status codes (1xx, etc.)
            return CheckResult.WARNING
