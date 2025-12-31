"""
DNS Propagation Checker for verifying DNS record propagation across multiple public DNS servers.

This module provides functionality to check DNS propagation status by querying
multiple public DNS servers in parallel and comparing results against expected values.
"""

import asyncio
import logging
import time
from datetime import datetime
from typing import List, Optional, Tuple

import dns.resolver
import dns.exception

from ..models import DNSServerInfo, DNSQueryResult, PropagationResult

logger = logging.getLogger(__name__)


class DNSPropagationChecker:
    """DNS propagation checker for verifying DNS record propagation across multiple public DNS servers."""
    
    # Public DNS servers with their names and locations (Requirements: 1.1, 1.2)
    PUBLIC_DNS_SERVERS = [
        ('8.8.8.8', 'Google Primary', 'Global'),
        ('8.8.4.4', 'Google Secondary', 'Global'),
        ('1.1.1.1', 'Cloudflare Primary', 'Global'),
        ('1.0.0.1', 'Cloudflare Secondary', 'Global'),
        ('9.9.9.9', 'Quad9', 'Global'),
        ('208.67.222.222', 'OpenDNS Primary', 'Global'),
        ('208.67.220.220', 'OpenDNS Secondary', 'Global'),
        ('64.6.64.6', 'Verisign', 'Global'),
        ('64.6.65.6', 'Verisign Secondary', 'Global'),
        ('77.88.8.8', 'Yandex', 'Russia'),
        ('8.26.56.26', 'Comodo Secure DNS', 'Global'),
        ('156.154.70.1', 'Neustar UltraDNS', 'Global'),
    ]
    
    # Supported DNS record types (Requirements: 3.1-3.6)
    SUPPORTED_RECORD_TYPES = {'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT'}
    
    def __init__(self, custom_servers: Optional[List[Tuple[str, str, str]]] = None):
        """Initialize DNS propagation checker.
        
        Args:
            custom_servers: Optional list of custom DNS servers as (ip, name, location) tuples
                          (Requirements: 1.3)
        """
        self.dns_servers = []
        
        # Add default public DNS servers
        for ip, name, location in self.PUBLIC_DNS_SERVERS:
            self.dns_servers.append(DNSServerInfo(ip=ip, name=name, location=location))
        
        # Add custom servers if provided (Requirements: 1.3)
        if custom_servers:
            for ip, name, location in custom_servers:
                self.dns_servers.append(DNSServerInfo(ip=ip, name=name, location=location))
        
        logger.debug(f"Initialized DNSPropagationChecker with {len(self.dns_servers)} DNS servers")
    
    async def check_propagation(
        self,
        domain: str,
        record_type: str,
        expected_value: Optional[str] = None
    ) -> PropagationResult:
        """Check DNS propagation across all configured DNS servers.
        
        Queries all DNS servers in parallel and compares results against expected value.
        
        Args:
            domain: Domain name to check
            record_type: DNS record type (A, AAAA, CNAME, MX, NS, TXT)
            expected_value: Optional expected value to compare against (Requirements: 4.1)
            
        Returns:
            PropagationResult containing status for each DNS server
            
        Raises:
            ValueError: If record_type is not supported
            
        Requirements: 2.1, 2.2, 2.5, 3.1-3.6, 4.1-4.5
        """
        # Validate record type (Requirements: 9.3)
        record_type = record_type.upper()
        if record_type not in self.SUPPORTED_RECORD_TYPES:
            raise ValueError(
                f"Invalid record type '{record_type}'. "
                f"Supported types: {', '.join(sorted(self.SUPPORTED_RECORD_TYPES))}"
            )
        
        logger.info(f"Checking DNS propagation for {domain} ({record_type} record)")
        if expected_value:
            logger.info(f"Expected value: {expected_value}")
        
        start_time = time.time()
        
        # Query all DNS servers in parallel (Requirements: 2.1)
        tasks = [
            self._query_dns_server(domain, record_type, server)
            for server in self.dns_servers
        ]
        
        query_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Convert exceptions to error results
        final_results = []
        for i, result in enumerate(query_results):
            if isinstance(result, Exception):
                server = self.dns_servers[i]
                logger.error(f"Query failed for server {server.name}: {result}")
                final_results.append(DNSQueryResult(
                    server=server,
                    status='unreachable',
                    values=[],
                    response_time=0.0,
                    error=str(result)
                ))
            else:
                final_results.append(result)
        
        # Compare with expected value if provided (Requirements: 4.1, 4.2, 4.3)
        if expected_value:
            for result in final_results:
                if result.status not in ('unreachable', 'timeout'):
                    # Check if expected value matches any of the actual values
                    if self._values_match(expected_value, result.values, record_type):
                        result.status = 'matched'
                    else:
                        result.status = 'mismatched'
        
        total_time = time.time() - start_time
        logger.info(f"DNS propagation check completed in {total_time:.2f}s")
        
        return PropagationResult(
            domain=domain,
            record_type=record_type,
            expected_value=expected_value,
            query_results=final_results,
            timestamp=datetime.now()
        )
    
    async def _query_dns_server(
        self,
        domain: str,
        record_type: str,
        server: DNSServerInfo
    ) -> DNSQueryResult:
        """Query a single DNS server for the specified record.
        
        Args:
            domain: Domain name to query
            record_type: DNS record type
            server: DNS server information
            
        Returns:
            DNSQueryResult with query status and values
            
        Requirements: 1.4, 2.3, 2.5
        """
        start_time = time.time()
        
        try:
            # Run DNS query in thread pool to avoid blocking (Requirements: 2.4)
            loop = asyncio.get_event_loop()
            
            # Set timeout for individual query (Requirements: 2.5)
            values = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    self._query_record_sync,
                    domain,
                    record_type,
                    server.ip
                ),
                timeout=5.0  # 5 second timeout per query
            )
            
            response_time = time.time() - start_time
            
            # If no expected value, status is just 'success' or similar
            # Status will be updated later if expected value is provided
            status = 'success' if values else 'no_records'
            
            return DNSQueryResult(
                server=server,
                status=status,
                values=values,
                response_time=response_time,
                error=None
            )
            
        except asyncio.TimeoutError:
            # Query timed out (Requirements: 1.4, 2.3, 2.5)
            response_time = time.time() - start_time
            logger.warning(f"DNS query timeout for {domain} on {server.name} ({server.ip})")
            return DNSQueryResult(
                server=server,
                status='timeout',
                values=[],
                response_time=response_time,
                error='Query timeout (>5s)'
            )
            
        except Exception as e:
            # Server unreachable or other error (Requirements: 1.4, 2.3)
            response_time = time.time() - start_time
            logger.warning(f"DNS query failed for {domain} on {server.name} ({server.ip}): {e}")
            return DNSQueryResult(
                server=server,
                status='unreachable',
                values=[],
                response_time=response_time,
                error=str(e)
            )
    
    def _query_record_sync(
        self,
        domain: str,
        record_type: str,
        nameserver: str
    ) -> List[str]:
        """Synchronous helper to query DNS records (runs in thread pool).
        
        This method reuses the logic from DNSChecker for consistency.
        
        Args:
            domain: The domain name to query
            record_type: Type of DNS record (A, AAAA, CNAME, MX, NS, TXT)
            nameserver: Specific nameserver to query (IP address)
            
        Returns:
            List of record values as strings
            
        Raises:
            dns.exception.DNSException: If DNS query fails
            
        Requirements: 3.1-3.6, 10.1
        """
        resolver = dns.resolver.Resolver()
        # Use shorter timeout for faster responses
        resolver.timeout = 2.0
        resolver.lifetime = 4.0
        
        # Configure specific nameserver
        resolver.nameservers = [nameserver]
        
        try:
            answers = resolver.resolve(domain, record_type)
            
            # Format results based on record type (Requirements: 3.1-3.6)
            if record_type == 'MX':
                # MX records include priority (Requirements: 3.4, 4.5)
                return [f"{answer.preference} {answer.exchange.to_text().rstrip('.')}" for answer in answers]
            elif record_type == 'TXT':
                # TXT records may have multiple strings (Requirements: 3.6, 4.5)
                return [' '.join(str(s, 'utf-8') if isinstance(s, bytes) else str(s) for s in answer.strings) for answer in answers]
            elif record_type in ['NS', 'CNAME']:
                # NS and CNAME records return domain names (Requirements: 3.3, 3.5, 4.5)
                return [answer.to_text().rstrip('.') for answer in answers]
            else:
                # A, AAAA records return IP addresses (Requirements: 3.1, 3.2)
                return [answer.to_text() for answer in answers]
                
        except dns.resolver.NXDOMAIN:
            # Domain does not exist (Requirements: 9.1)
            logger.debug(f"Domain {domain} does not exist (NXDOMAIN)")
            return []
        except dns.resolver.NoAnswer:
            # No records of this type
            logger.debug(f"No {record_type} records found for {domain}")
            return []
        except dns.resolver.NoNameservers:
            # All nameservers failed
            logger.debug(f"All nameservers failed for {domain}")
            raise
        except dns.exception.Timeout:
            # Query timed out
            logger.debug(f"DNS query timeout for {domain}")
            raise
        except Exception as e:
            # Other DNS errors (Requirements: 9.2, 9.4)
            logger.debug(f"DNS query error for {domain}: {e}")
            raise
    
    def _values_match(
        self,
        expected: str,
        actual_values: List[str],
        record_type: str
    ) -> bool:
        """Check if expected value matches any of the actual values.
        
        Handles multiple values for record types that can return multiple results.
        
        Args:
            expected: Expected value
            actual_values: List of actual values from DNS query
            record_type: DNS record type
            
        Returns:
            True if expected value matches any actual value
            
        Requirements: 4.1, 4.2, 4.3, 4.5
        """
        if not actual_values:
            return False
        
        # Normalize expected value
        expected_normalized = expected.strip().lower()
        
        # For record types that can have multiple values, check if expected matches any
        for value in actual_values:
            value_normalized = value.strip().lower()
            
            # For MX records, compare without priority if expected doesn't include it
            if record_type == 'MX' and ' ' in value_normalized:
                # Extract just the domain part for comparison
                mx_domain = value_normalized.split(' ', 1)[1]
                if expected_normalized == mx_domain or expected_normalized == value_normalized:
                    return True
            elif expected_normalized == value_normalized:
                return True
        
        return False
