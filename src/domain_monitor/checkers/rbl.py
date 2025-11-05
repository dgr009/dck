"""
RBL (Real-time Blackhole List) checker for domain monitoring.

Checks if domain IPs and mail server IPs are listed in spam blacklists.
"""

import asyncio
import logging
from typing import List, Set, Tuple
import dns.resolver
import dns.exception

from .base_checker import BaseChecker, CheckResult


logger = logging.getLogger(__name__)


class RBLChecker(BaseChecker):
    """
    Checker for RBL (Real-time Blackhole List) status.
    
    Queries major RBL services to check if domain IPs or mail server IPs
    are listed in spam blacklists.
    """
    
    # Major RBL servers to check
    RBL_SERVERS = [
        'zen.spamhaus.org',
        'b.barracudacentral.org',
        'bl.spamcop.net',
    ]
    
    def __init__(self, timeout: int = 10):
        """
        Initialize the RBL checker.
        
        Args:
            timeout: Maximum time in seconds for check completion
        """
        super().__init__(timeout)
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
    
    async def check(self, domain: str, **kwargs) -> CheckResult:
        """
        Check if domain or mail server IPs are listed in RBLs.
        
        Args:
            domain: The domain name to check
            
        Returns:
            CheckResult with RBL listing status
        """
        import time
        check_start_time = time.time()
        logger.debug(f"Starting RBL check for domain: {domain}")
        
        try:
            # Collect all IPs (domain A records + MX server IPs)
            logger.debug(f"Collecting IP addresses for {domain}")
            ip_start = time.time()
            ips = await self._get_domain_ips(domain)
            ip_collection_time = time.time() - ip_start
            logger.debug(f"Collected {len(ips)} IP(s) for {domain} in {ip_collection_time:.3f}s: {list(ips)}")
            
            if not ips:
                logger.warning(f"No IP addresses found to check for {domain}")
                return self._create_result(
                    domain=domain,
                    status=CheckResult.WARNING,
                    message="No IP addresses found to check",
                    details={
                        "ips_checked": [],
                        "timing": {
                            "ip_collection_time": ip_collection_time,
                            "total_check_time": time.time() - check_start_time
                        }
                    }
                )
            
            # Check all IPs against all RBL servers in parallel
            logger.debug(f"Checking {len(ips)} IP(s) against {len(self.RBL_SERVERS)} RBL server(s) for {domain}")
            rbl_start = time.time()
            listed_results = await self._check_all_ips(ips)
            rbl_check_time = time.time() - rbl_start
            logger.debug(f"RBL checks completed for {domain} in {rbl_check_time:.3f}s: {len(listed_results)} listing(s) found")
            
            total_time = time.time() - check_start_time
            timing_details = {
                "ip_collection_time": ip_collection_time,
                "rbl_check_time": rbl_check_time,
                "total_check_time": total_time
            }
            
            if listed_results:
                # Build detailed message about listings
                listing_details = []
                for ip, rbl_server in listed_results:
                    listing_details.append(f"{ip} listed in {rbl_server}")
                    logger.warning(f"RBL listing found for {domain}: {ip} in {rbl_server}")
                
                message = f"LISTED: {len(listed_results)} listing(s) found"
                
                return self._create_result(
                    domain=domain,
                    status=CheckResult.CRITICAL,
                    message=message,
                    details={
                        "ips_checked": list(ips),
                        "listings": [
                            {"ip": ip, "rbl_server": rbl}
                            for ip, rbl in listed_results
                        ],
                        "listing_details": listing_details,
                        "timing": timing_details
                    }
                )
            else:
                logger.debug(f"No RBL listings found for {domain} (checked {len(ips)} IP(s) against {len(self.RBL_SERVERS)} RBL server(s))")
                return self._create_result(
                    domain=domain,
                    status=CheckResult.OK,
                    message=f"Not listed in any RBL ({len(ips)} IP(s) checked)",
                    details={
                        "ips_checked": list(ips),
                        "listings": [],
                        "timing": timing_details
                    }
                )
                
        except Exception as e:
            logger.error(f"RBL check failed for {domain}: {str(e)}", exc_info=True)
            return self._create_result(
                domain=domain,
                status=CheckResult.ERROR,
                message=f"RBL check failed: {str(e)}",
                details={"error": str(e)}
            )
    
    async def _get_domain_ips(self, domain: str) -> Set[str]:
        """
        Get all IP addresses associated with the domain.
        
        Collects both A records for the domain and IPs of MX servers.
        
        Args:
            domain: The domain name to query
            
        Returns:
            Set of IP addresses (IPv4)
        """
        ips = set()
        
        # Get A records for the domain
        try:
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None,
                lambda: self.resolver.resolve(domain, 'A')
            )
            for rdata in answers:
                ips.add(str(rdata))
            logger.debug(f"Found {len(ips)} A record(s) for {domain}")
        except dns.exception.DNSException as e:
            logger.debug(f"No A records found for {domain}: {str(e)}")
        
        # Get MX records and resolve their IPs
        try:
            loop = asyncio.get_event_loop()
            mx_answers = await loop.run_in_executor(
                None,
                lambda: self.resolver.resolve(domain, 'MX')
            )
            
            # Resolve each MX hostname to IP
            for mx_rdata in mx_answers:
                mx_hostname = str(mx_rdata.exchange).rstrip('.')
                try:
                    mx_a_answers = await loop.run_in_executor(
                        None,
                        lambda h=mx_hostname: self.resolver.resolve(h, 'A')
                    )
                    for a_rdata in mx_a_answers:
                        ips.add(str(a_rdata))
                    logger.debug(f"Resolved MX {mx_hostname} to IP(s)")
                except dns.exception.DNSException as e:
                    logger.debug(f"Could not resolve MX {mx_hostname}: {str(e)}")
            
        except dns.exception.DNSException as e:
            logger.debug(f"No MX records found for {domain}: {str(e)}")
        
        return ips
    
    async def _check_all_ips(self, ips: Set[str]) -> List[Tuple[str, str]]:
        """
        Check all IPs against all RBL servers in parallel.
        
        Args:
            ips: Set of IP addresses to check
            
        Returns:
            List of tuples (ip, rbl_server) for IPs that are listed
        """
        tasks = []
        for ip in ips:
            for rbl_server in self.RBL_SERVERS:
                tasks.append(self._check_ip_in_rbl(ip, rbl_server))
        
        # Execute all checks in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect listings (filter out None and exceptions)
        listings = []
        for result in results:
            if isinstance(result, tuple) and result is not None:
                listings.append(result)
        
        return listings
    
    async def _check_ip_in_rbl(self, ip: str, rbl_server: str) -> Tuple[str, str] | None:
        """
        Check if a specific IP is listed in a specific RBL server.
        
        Args:
            ip: The IP address to check
            rbl_server: The RBL server hostname
            
        Returns:
            Tuple of (ip, rbl_server) if listed, None otherwise
        """
        try:
            # Reverse the IP and append RBL server
            reversed_ip = self._reverse_ip(ip)
            query_hostname = f"{reversed_ip}.{rbl_server}"
            
            # Query the RBL server
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: self.resolver.resolve(query_hostname, 'A')
            )
            
            # If we get a response, the IP is listed
            logger.info(f"IP {ip} is LISTED in {rbl_server}")
            return (ip, rbl_server)
            
        except dns.resolver.NXDOMAIN:
            # NXDOMAIN means not listed (this is good)
            logger.debug(f"IP {ip} is not listed in {rbl_server}")
            return None
        except dns.exception.DNSException as e:
            # Other DNS errors (timeout, etc.)
            logger.debug(f"RBL query failed for {ip} in {rbl_server}: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error checking {ip} in {rbl_server}: {str(e)}")
            return None
    
    def _reverse_ip(self, ip: str) -> str:
        """
        Reverse IP address format for RBL queries.
        
        RBL queries require IP addresses in reverse order.
        Example: 1.2.3.4 becomes 4.3.2.1
        
        Args:
            ip: IP address in standard format (e.g., "1.2.3.4")
            
        Returns:
            Reversed IP address (e.g., "4.3.2.1")
        """
        octets = ip.split('.')
        return '.'.join(reversed(octets))
