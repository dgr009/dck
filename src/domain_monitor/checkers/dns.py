"""
DNS checker for domain monitoring.

Queries DNS records, checks propagation across public DNS servers,
and compares local DNS cache with public DNS results.
"""

import asyncio
import logging
import time
from typing import Dict, Any, List, Optional, Set

import dns.resolver
import dns.exception

from .base_checker import BaseChecker, CheckResult

logger = logging.getLogger(__name__)


class DNSChecker(BaseChecker):
    """
    Checker for DNS records and propagation status.
    
    Queries various DNS record types (A, AAAA, MX, NS, TXT),
    checks DNS propagation across multiple public DNS servers,
    and compares local DNS cache with public DNS results.
    """
    
    # Public DNS servers for propagation checks (Requirements: 7.2)
    PUBLIC_DNS_SERVERS = [
        '8.8.8.8',      # Google
        '1.1.1.1',      # Cloudflare
        '9.9.9.9',      # Quad9
    ]
    
    async def check(self, domain: str, **kwargs) -> CheckResult:
        """
        Execute DNS check for the specified domain.
        
        Queries all DNS record types, checks propagation across public DNS servers,
        and compares local DNS cache with public DNS results.
        
        Args:
            domain: The domain name to check
            **kwargs: Additional parameters (unused)
            
        Returns:
            CheckResult with DNS information and status
            
        Requirements: 7.2
        """
        check_start_time = time.time()
        logger.debug(f"Starting DNS check for domain: {domain}")
        
        try:
            details = {}
            warnings = []
            timing_details = {}
            
            # Query all DNS record types (Requirements: 6.1-6.6)
            logger.debug(f"Querying DNS records for {domain}")
            
            record_start = time.time()
            a_records = await self._query_record(domain, 'A')
            timing_details['a_query_time'] = time.time() - record_start
            logger.debug(f"A records for {domain}: {a_records} (took {timing_details['a_query_time']:.3f}s)")
            
            record_start = time.time()
            aaaa_records = await self._query_record(domain, 'AAAA')
            timing_details['aaaa_query_time'] = time.time() - record_start
            logger.debug(f"AAAA records for {domain}: {aaaa_records} (took {timing_details['aaaa_query_time']:.3f}s)")
            
            record_start = time.time()
            mx_records = await self._query_record(domain, 'MX')
            timing_details['mx_query_time'] = time.time() - record_start
            logger.debug(f"MX records for {domain}: {mx_records} (took {timing_details['mx_query_time']:.3f}s)")
            
            record_start = time.time()
            ns_records = await self._query_record(domain, 'NS')
            timing_details['ns_query_time'] = time.time() - record_start
            logger.debug(f"NS records for {domain}: {ns_records} (took {timing_details['ns_query_time']:.3f}s)")
            
            record_start = time.time()
            txt_records = await self._query_record(domain, 'TXT')
            timing_details['txt_query_time'] = time.time() - record_start
            logger.debug(f"TXT records for {domain}: {txt_records} (took {timing_details['txt_query_time']:.3f}s)")
            
            details['a_records'] = a_records
            details['aaaa_records'] = aaaa_records
            details['mx_records'] = mx_records
            details['ns_records'] = ns_records
            details['txt_records'] = txt_records
            
            # Check DNS propagation (Requirements: 7.1, 7.3, 7.4, 7.5)
            logger.debug(f"Checking DNS propagation for {domain} across {len(self.PUBLIC_DNS_SERVERS)} servers")
            prop_start = time.time()
            propagation_result = await self._check_propagation(domain)
            timing_details['propagation_check_time'] = time.time() - prop_start
            details['propagation'] = propagation_result
            
            logger.debug(f"Propagation check for {domain}: consistent={propagation_result['consistent']} (took {timing_details['propagation_check_time']:.3f}s)")
            if not propagation_result['consistent']:
                logger.debug(f"Propagation details for {domain}: {propagation_result}")
                warnings.append(f"Propagation Mismatch: {propagation_result['message']}")
            
            # Check local vs public DNS cache mismatch (Requirements: 8.1, 8.2, 8.3, 8.4)
            logger.debug(f"Checking DNS cache consistency for {domain}")
            cache_start = time.time()
            cache_result = await self._check_cache_mismatch(domain)
            timing_details['cache_check_time'] = time.time() - cache_start
            details['cache_status'] = cache_result
            
            logger.debug(f"Cache check for {domain}: mismatch={cache_result['mismatch']} (took {timing_details['cache_check_time']:.3f}s)")
            if cache_result['mismatch']:
                logger.debug(f"Cache mismatch details for {domain}: local={cache_result.get('local_results', [])}, public={cache_result.get('public_results', [])}")
                warnings.append(f"Cache Mismatch: {cache_result['message']}")
            
            # Add timing details in debug mode
            total_time = time.time() - check_start_time
            timing_details['total_check_time'] = total_time
            details['timing'] = timing_details
            logger.debug(f"DNS check completed for {domain} in {total_time:.3f}s")
            
            # Determine overall status
            if warnings:
                status = CheckResult.WARNING
                message = "; ".join(warnings)
            else:
                status = CheckResult.OK
                message = "All DNS records resolved successfully"
            
            return self._create_result(
                domain=domain,
                status=status,
                message=message,
                details=details
            )
            
        except Exception as e:
            logger.error(f"DNS check failed for {domain}: {str(e)}", exc_info=True)
            return self._create_result(
                domain=domain,
                status=CheckResult.ERROR,
                message=f"DNS check failed: {str(e)}",
                details={"error_type": type(e).__name__}
            )

    async def _query_record(
        self,
        domain: str,
        record_type: str,
        nameserver: Optional[str] = None
    ) -> List[str]:
        """
        Query DNS records for the specified domain and record type.
        
        Uses dnspython to query DNS records. Can optionally specify a nameserver
        for the query, otherwise uses the system default resolver.
        
        Args:
            domain: The domain name to query
            record_type: Type of DNS record (A, AAAA, MX, NS, TXT)
            nameserver: Optional specific nameserver to query (IP address)
            
        Returns:
            List of record values as strings
            
        Raises:
            dns.exception.DNSException: If DNS query fails
            
        Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6
        """
        try:
            # Run DNS query in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                self._query_record_sync,
                domain,
                record_type,
                nameserver
            )
            return result
            
        except dns.resolver.NXDOMAIN:
            # Domain does not exist
            return []
        except dns.resolver.NoAnswer:
            # No records of this type
            return []
        except dns.resolver.NoNameservers:
            # All nameservers failed
            return []
        except dns.exception.Timeout:
            # Query timed out
            return []
        except Exception:
            # Other DNS errors
            return []
    
    def _query_record_sync(
        self,
        domain: str,
        record_type: str,
        nameserver: Optional[str] = None
    ) -> List[str]:
        """
        Synchronous helper to query DNS records (runs in thread pool).
        
        Args:
            domain: The domain name to query
            record_type: Type of DNS record (A, AAAA, MX, NS, TXT)
            nameserver: Optional specific nameserver to query
            
        Returns:
            List of record values as strings
        """
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        
        # Configure specific nameserver if provided
        if nameserver:
            resolver.nameservers = [nameserver]
        
        try:
            answers = resolver.resolve(domain, record_type)
            
            # Format results based on record type
            if record_type == 'MX':
                # MX records include priority
                return [f"{answer.preference} {answer.exchange.to_text()}" for answer in answers]
            elif record_type == 'TXT':
                # TXT records may have multiple strings
                return [' '.join(str(s, 'utf-8') if isinstance(s, bytes) else str(s) for s in answer.strings) for answer in answers]
            elif record_type in ['NS', 'CNAME']:
                # NS and CNAME records return domain names
                return [answer.to_text().rstrip('.') for answer in answers]
            else:
                # A, AAAA records return IP addresses
                return [answer.to_text() for answer in answers]
                
        except Exception:
            raise

    async def _check_propagation(self, domain: str) -> Dict[str, Any]:
        """
        Check DNS propagation across multiple public DNS servers.
        
        Queries A records from multiple public DNS servers in parallel and
        compares the results to detect propagation issues.
        
        Args:
            domain: The domain name to check
            
        Returns:
            Dictionary with propagation status:
                - consistent: Boolean indicating if all servers agree
                - message: Description of the propagation status
                - results: Dict mapping server IPs to their A record results
                
        Requirements: 7.1, 7.3, 7.4, 7.5
        """
        # Query all public DNS servers in parallel
        tasks = [
            self._query_record(domain, 'A', nameserver=server)
            for server in self.PUBLIC_DNS_SERVERS
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Build results dictionary
        server_results = {}
        for server, result in zip(self.PUBLIC_DNS_SERVERS, results):
            if isinstance(result, Exception):
                server_results[server] = []
            else:
                server_results[server] = sorted(result)  # Sort for comparison
        
        # Check if all servers return the same results
        all_results = [tuple(r) for r in server_results.values() if r]
        
        if not all_results:
            # No servers returned results
            return {
                'consistent': True,
                'message': 'No A records found on any public DNS server',
                'results': server_results
            }
        
        # Convert to sets for comparison
        result_sets = [set(r) for r in all_results]
        
        # Check if all non-empty results are identical
        if len(set(map(frozenset, result_sets))) == 1:
            # All servers agree
            return {
                'consistent': True,
                'message': 'DNS propagated consistently across all public servers',
                'results': server_results
            }
        else:
            # Servers disagree - propagation mismatch
            different_servers = []
            for server, result in server_results.items():
                if result and set(result) != result_sets[0]:
                    different_servers.append(server)
            
            return {
                'consistent': False,
                'message': f'Different results from servers: {", ".join(different_servers)}',
                'results': server_results
            }

    async def _check_cache_mismatch(self, domain: str) -> Dict[str, Any]:
        """
        Compare local DNS cache with public DNS results.
        
        Queries A records using both the system default resolver and
        Google Public DNS (8.8.8.8) to detect local DNS cache issues.
        
        Args:
            domain: The domain name to check
            
        Returns:
            Dictionary with cache comparison status:
                - mismatch: Boolean indicating if local and public DNS differ
                - message: Description of the cache status
                - local_results: A records from system resolver
                - public_results: A records from Google DNS (8.8.8.8)
                
        Requirements: 8.1, 8.2, 8.3, 8.4
        """
        # Query using system default resolver (Requirements: 8.1)
        local_results = await self._query_record(domain, 'A', nameserver=None)
        
        # Query using Google Public DNS (Requirements: 8.2)
        public_results = await self._query_record(domain, 'A', nameserver='8.8.8.8')
        
        # Sort for comparison
        local_set = set(sorted(local_results))
        public_set = set(sorted(public_results))
        
        # Compare results (Requirements: 8.3)
        if local_set == public_set:
            return {
                'mismatch': False,
                'message': 'Local and public DNS results match',
                'local_results': local_results,
                'public_results': public_results
            }
        else:
            # Results differ - cache mismatch (Requirements: 8.4)
            return {
                'mismatch': True,
                'message': f'Local DNS ({", ".join(local_results) or "none"}) differs from public DNS ({", ".join(public_results) or "none"})',
                'local_results': local_results,
                'public_results': public_results
            }
