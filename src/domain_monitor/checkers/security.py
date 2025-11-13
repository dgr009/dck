"""
Security checker for domain monitoring.

Checks security-related DNS records (SPF, DMARC, DKIM, DNSSEC)
and HTTP security headers.
"""

import asyncio
import logging
import re
import time
from typing import Dict, Any, List

import dns.resolver
import aiohttp

from .base_checker import BaseChecker, CheckResult

logger = logging.getLogger(__name__)


class SecurityChecker(BaseChecker):
    """
    Checker for security records and HTTP security headers.
    
    Validates SPF, DMARC, DKIM, and DNSSEC records, and checks
    for presence of important HTTP security headers.
    """
    
    async def check(self, domain: str, **kwargs) -> CheckResult:
        """
        Execute security check for the specified domain.
        
        Checks SPF, DMARC, DKIM (if selectors provided), DNSSEC,
        and HTTP security headers.
        
        Args:
            domain: The domain name to check
            **kwargs: Additional parameters:
                - dkim_selectors: List of DKIM selectors to check
            
        Returns:
            CheckResult with security status and details
            
        Requirements: 2.5
        """
        check_start_time = time.time()
        logger.debug(f"Starting security check for domain: {domain}")
        
        try:
            details = {}
            warnings = []
            timing_details = {}
            
            # Get DKIM selectors from kwargs
            dkim_selectors = kwargs.get('dkim_selectors', [])
            logger.debug(f"DKIM selectors for {domain}: {dkim_selectors}")
            
            # Check SPF record
            logger.debug(f"Checking SPF record for {domain}")
            spf_start = time.time()
            spf_result = await self._check_spf(domain)
            timing_details['spf_check_time'] = time.time() - spf_start
            details['spf'] = spf_result
            logger.debug(f"SPF check for {domain}: status={spf_result['status']}, record={spf_result.get('record', 'None')} (took {timing_details['spf_check_time']:.3f}s)")
            if spf_result['status'] != 'OK':
                warnings.append(spf_result['message'])
            
            # Check DMARC record
            logger.debug(f"Checking DMARC record for {domain}")
            dmarc_start = time.time()
            dmarc_result = await self._check_dmarc(domain)
            timing_details['dmarc_check_time'] = time.time() - dmarc_start
            details['dmarc'] = dmarc_result
            logger.debug(f"DMARC check for {domain}: status={dmarc_result['status']}, policy={dmarc_result.get('policy', 'None')} (took {timing_details['dmarc_check_time']:.3f}s)")
            if dmarc_result['status'] != 'OK':
                warnings.append(dmarc_result['message'])
            
            # Check DKIM records if selectors provided
            if dkim_selectors:
                logger.debug(f"Checking DKIM records for {domain} with {len(dkim_selectors)} selector(s)")
                dkim_start = time.time()
                dkim_result = await self._check_dkim(domain, dkim_selectors)
                timing_details['dkim_check_time'] = time.time() - dkim_start
                details['dkim'] = dkim_result
                logger.debug(f"DKIM check for {domain}: status={dkim_result['status']} (took {timing_details['dkim_check_time']:.3f}s)")
                if dkim_result['status'] != 'OK':
                    warnings.append(dkim_result['message'])
            else:
                logger.debug(f"Skipping DKIM check for {domain} - no selectors provided")
                details['dkim'] = {'status': 'SKIPPED', 'message': 'No DKIM selectors specified'}
            
            # Check DNSSEC
            logger.debug(f"Checking DNSSEC for {domain}")
            dnssec_start = time.time()
            dnssec_result = await self._check_dnssec(domain)
            timing_details['dnssec_check_time'] = time.time() - dnssec_start
            details['dnssec'] = dnssec_result
            logger.debug(f"DNSSEC check for {domain}: status={dnssec_result['status']} (took {timing_details['dnssec_check_time']:.3f}s)")
            if dnssec_result['status'] != 'OK':
                warnings.append(dnssec_result['message'])
            
            # Check HTTP security headers
            logger.debug(f"Checking HTTP security headers for {domain}")
            headers_start = time.time()
            headers_result = await self._check_security_headers(domain)
            timing_details['headers_check_time'] = time.time() - headers_start
            details['security_headers'] = headers_result
            logger.debug(f"Security headers check for {domain}: status={headers_result['status']}, missing={headers_result.get('missing_headers', [])} (took {timing_details['headers_check_time']:.3f}s)")
            if headers_result['status'] != 'OK':
                warnings.append(headers_result['message'])
            
            # Add timing details
            total_time = time.time() - check_start_time
            timing_details['total_check_time'] = total_time
            details['timing'] = timing_details
            logger.debug(f"Security check completed for {domain} in {total_time:.3f}s")
            
            # Determine overall status based on critical security items only
            # Critical: SPF, DMARC (email security)
            # Non-critical: DNSSEC, Security Headers (nice to have)
            critical_warnings = []
            
            if spf_result['status'] != 'OK':
                critical_warnings.append(spf_result['message'])
            if dmarc_result['status'] != 'OK':
                critical_warnings.append(dmarc_result['message'])
            
            if critical_warnings:
                status = CheckResult.WARNING
                message = "; ".join(warnings)  # Show all warnings in message
            else:
                status = CheckResult.OK
                if warnings:
                    # Has non-critical warnings but critical checks passed
                    message = "Critical security checks passed"
                else:
                    message = "All security checks passed"
            
            return self._create_result(
                domain=domain,
                status=status,
                message=message,
                details=details
            )
            
        except Exception as e:
            logger.error(f"Security check failed for {domain}: {str(e)}", exc_info=True)
            return self._create_result(
                domain=domain,
                status=CheckResult.ERROR,
                message=f"Security check failed: {str(e)}",
                details={"error_type": type(e).__name__}
            )

    async def _check_spf(self, domain: str) -> Dict[str, Any]:
        """
        Check SPF record existence and validity.
        
        Queries TXT records for SPF record, verifies it starts with "v=spf1",
        and validates syntax for common issues like "+all".
        
        Args:
            domain: The domain name to check
            
        Returns:
            Dictionary with SPF check results:
                - status: OK, WARNING, or ERROR
                - message: Description of the SPF status
                - record: The SPF record if found
                - validation: Validation results if record found
                
        Requirements: 9.1, 9.2, 9.3, 9.4, 9.5
        """
        try:
            # Query TXT records (Requirements: 9.1)
            loop = asyncio.get_event_loop()
            txt_records = await loop.run_in_executor(
                None,
                self._query_txt_records_sync,
                domain
            )
            
            # Find SPF record (starts with "v=spf1") (Requirements: 9.2)
            spf_record = None
            for record in txt_records:
                if record.startswith('v=spf1'):
                    spf_record = record
                    break
            
            if not spf_record:
                # SPF record not found (Requirements: 9.3)
                return {
                    'status': 'WARNING',
                    'message': 'Missing SPF',
                    'record': None,
                    'validation': None
                }
            
            # Validate SPF syntax (Requirements: 9.4, 9.5)
            validation = self._validate_spf_syntax(spf_record)
            
            if not validation['valid']:
                return {
                    'status': 'WARNING',
                    'message': validation['message'],
                    'record': spf_record,
                    'validation': validation
                }
            
            return {
                'status': 'OK',
                'message': 'SPF record valid',
                'record': spf_record,
                'validation': validation
            }
            
        except Exception as e:
            return {
                'status': 'ERROR',
                'message': f'SPF check failed: {str(e)}',
                'record': None,
                'validation': None
            }
    
    def _query_txt_records_sync(self, domain: str) -> List[str]:
        """
        Synchronous helper to query TXT records (runs in thread pool).
        
        Args:
            domain: The domain name to query
            
        Returns:
            List of TXT record values as strings
        """
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        
        try:
            answers = resolver.resolve(domain, 'TXT')
            # TXT records may have multiple strings
            return [
                ' '.join(str(s, 'utf-8') if isinstance(s, bytes) else str(s) for s in answer.strings)
                for answer in answers
            ]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return []
        except Exception:
            return []
    
    def _validate_spf_syntax(self, spf_record: str) -> Dict[str, Any]:
        """
        Validate SPF record syntax and check for insecure patterns.
        
        Checks for common SPF issues:
        - "+all" mechanism (allows all senders - insecure)
        - Invalid syntax
        
        Args:
            spf_record: The SPF record to validate
            
        Returns:
            Dictionary with validation results:
                - valid: Boolean indicating if SPF is valid and secure
                - message: Description of validation result
                - issues: List of specific issues found
                
        Requirements: 9.4, 9.5
        """
        issues = []
        
        # Check for "+all" mechanism (Requirements: 9.4)
        if '+all' in spf_record:
            issues.append('Contains "+all" mechanism (allows all senders - insecure)')
        
        # Check for basic syntax validity (Requirements: 9.5)
        if not spf_record.startswith('v=spf1'):
            issues.append('Does not start with "v=spf1"')
        
        # Check for common syntax errors
        # SPF should have mechanisms like ip4, ip6, include, a, mx, etc.
        mechanisms = ['ip4:', 'ip6:', 'include:', 'a', 'mx', 'ptr', 'exists:', 'all']
        has_mechanism = any(mech in spf_record for mech in mechanisms)
        
        if not has_mechanism:
            issues.append('No valid SPF mechanisms found')
        
        if issues:
            if '+all' in spf_record:
                message = 'Insecure SPF'
            else:
                message = 'Invalid SPF'
            
            return {
                'valid': False,
                'message': message,
                'issues': issues
            }
        
        return {
            'valid': True,
            'message': 'SPF record is valid',
            'issues': []
        }

    async def _check_dmarc(self, domain: str) -> Dict[str, Any]:
        """
        Check DMARC record existence and extract policy.
        
        Queries TXT records at _dmarc subdomain, verifies it contains "v=DMARC1",
        and extracts the policy (p=) tag.
        
        Args:
            domain: The domain name to check
            
        Returns:
            Dictionary with DMARC check results:
                - status: OK or WARNING
                - message: Description of the DMARC status
                - record: The DMARC record if found
                - policy: The DMARC policy (p= tag value) if found
                
        Requirements: 10.1, 10.2, 10.3, 10.4
        """
        try:
            # Query TXT records at _dmarc subdomain (Requirements: 10.1)
            dmarc_domain = f'_dmarc.{domain}'
            loop = asyncio.get_event_loop()
            txt_records = await loop.run_in_executor(
                None,
                self._query_txt_records_sync,
                dmarc_domain
            )
            
            # Find DMARC record (contains "v=DMARC1") (Requirements: 10.2)
            dmarc_record = None
            for record in txt_records:
                if 'v=DMARC1' in record:
                    dmarc_record = record
                    break
            
            if not dmarc_record:
                # DMARC record not found (Requirements: 10.4)
                return {
                    'status': 'WARNING',
                    'message': 'Missing DMARC',
                    'record': None,
                    'policy': None
                }
            
            # Extract policy (p=) tag (Requirements: 10.3)
            policy = None
            policy_match = re.search(r'p=(\w+)', dmarc_record)
            if policy_match:
                policy = policy_match.group(1)
            
            return {
                'status': 'OK',
                'message': f'DMARC record found with policy: {policy}' if policy else 'DMARC record found',
                'record': dmarc_record,
                'policy': policy
            }
            
        except Exception as e:
            return {
                'status': 'ERROR',
                'message': f'DMARC check failed: {str(e)}',
                'record': None,
                'policy': None
            }

    async def _check_dkim(self, domain: str, selectors: List[str]) -> Dict[str, Any]:
        """
        Check DKIM record existence for specified selectors.
        
        Queries TXT or CNAME records at selector._domainkey subdomain for each
        specified selector, and verifies TXT records contain "v=DKIM1".
        
        Args:
            domain: The domain name to check
            selectors: List of DKIM selectors to check
            
        Returns:
            Dictionary with DKIM check results:
                - status: OK or WARNING
                - message: Description of the DKIM status
                - selectors: Dict mapping selector names to their check results
                
        Requirements: 11.1, 11.2, 11.3
        """
        try:
            selector_results = {}
            missing_selectors = []
            
            # Check each selector (Requirements: 11.1)
            for selector in selectors:
                dkim_domain = f'{selector}._domainkey.{domain}'
                
                # Query TXT records
                loop = asyncio.get_event_loop()
                txt_records = await loop.run_in_executor(
                    None,
                    self._query_txt_records_sync,
                    dkim_domain
                )
                
                # Also try CNAME records
                cname_records = await loop.run_in_executor(
                    None,
                    self._query_cname_records_sync,
                    dkim_domain
                )
                
                # Check if DKIM record found
                dkim_found = False
                dkim_record = None
                
                # Check TXT records for "v=DKIM1" (Requirements: 11.3)
                for record in txt_records:
                    if 'v=DKIM1' in record:
                        dkim_found = True
                        dkim_record = record
                        break
                
                # If not found in TXT, check if CNAME exists (points to another DKIM record)
                if not dkim_found and cname_records:
                    dkim_found = True
                    dkim_record = f'CNAME: {cname_records[0]}'
                
                if dkim_found:
                    selector_results[selector] = {
                        'found': True,
                        'record': dkim_record
                    }
                else:
                    # DKIM record not found for this selector (Requirements: 11.2)
                    selector_results[selector] = {
                        'found': False,
                        'record': None
                    }
                    missing_selectors.append(selector)
            
            # Determine overall status
            if missing_selectors:
                return {
                    'status': 'WARNING',
                    'message': f'Missing DKIM for selectors: {", ".join(missing_selectors)}',
                    'selectors': selector_results
                }
            
            return {
                'status': 'OK',
                'message': f'DKIM records found for all {len(selectors)} selectors',
                'selectors': selector_results
            }
            
        except Exception as e:
            return {
                'status': 'ERROR',
                'message': f'DKIM check failed: {str(e)}',
                'selectors': {}
            }
    
    def _query_cname_records_sync(self, domain: str) -> List[str]:
        """
        Synchronous helper to query CNAME records (runs in thread pool).
        
        Args:
            domain: The domain name to query
            
        Returns:
            List of CNAME record values as strings
        """
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        
        try:
            answers = resolver.resolve(domain, 'CNAME')
            return [answer.to_text().rstrip('.') for answer in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return []
        except Exception:
            return []

    async def _check_dnssec(self, domain: str) -> Dict[str, Any]:
        """
        Check DNSSEC activation status.
        
        Queries DS or DNSKEY records to determine if DNSSEC is enabled.
        
        Args:
            domain: The domain name to check
            
        Returns:
            Dictionary with DNSSEC check results:
                - status: OK or WARNING
                - message: Description of the DNSSEC status
                - ds_records: List of DS records if found
                - dnskey_records: List of DNSKEY records if found
                
        Requirements: 12.1, 12.2, 12.3
        """
        try:
            # Query DS records (Requirements: 12.1)
            loop = asyncio.get_event_loop()
            ds_records = await loop.run_in_executor(
                None,
                self._query_dnssec_records_sync,
                domain,
                'DS'
            )
            
            # Query DNSKEY records (Requirements: 12.1)
            dnskey_records = await loop.run_in_executor(
                None,
                self._query_dnssec_records_sync,
                domain,
                'DNSKEY'
            )
            
            # Check if either DS or DNSKEY records exist (Requirements: 12.3)
            if ds_records or dnskey_records:
                return {
                    'status': 'OK',
                    'message': 'DNSSEC enabled',
                    'ds_records': ds_records,
                    'dnskey_records': dnskey_records
                }
            else:
                # Neither DS nor DNSKEY found (Requirements: 12.2)
                return {
                    'status': 'WARNING',
                    'message': 'DNSSEC Not Enabled',
                    'ds_records': [],
                    'dnskey_records': []
                }
            
        except Exception as e:
            return {
                'status': 'ERROR',
                'message': f'DNSSEC check failed: {str(e)}',
                'ds_records': [],
                'dnskey_records': []
            }
    
    def _query_dnssec_records_sync(self, domain: str, record_type: str) -> List[str]:
        """
        Synchronous helper to query DNSSEC records (runs in thread pool).
        
        Args:
            domain: The domain name to query
            record_type: Type of DNSSEC record (DS or DNSKEY)
            
        Returns:
            List of DNSSEC record values as strings
        """
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        
        try:
            answers = resolver.resolve(domain, record_type)
            return [answer.to_text() for answer in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return []
        except Exception:
            return []

    async def _check_security_headers(self, domain: str) -> Dict[str, Any]:
        """
        Check HTTP security headers presence.
        
        Sends HTTPS request to the domain and checks for important security headers:
        - Strict-Transport-Security
        - Content-Security-Policy
        - X-Frame-Options
        - X-Content-Type-Options
        
        Args:
            domain: The domain name to check
            
        Returns:
            Dictionary with security headers check results:
                - status: OK or WARNING
                - message: Description of the security headers status
                - headers: Dict of header names to their values (or None if missing)
                - missing_headers: List of missing security headers
                
        Requirements: 14.1, 14.2, 14.3, 14.4, 14.5, 14.6
        """
        try:
            # Required security headers (Requirements: 14.2, 14.3, 14.4, 14.5)
            required_headers = [
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-Frame-Options',
                'X-Content-Type-Options'
            ]
            
            # Send HTTPS request and capture headers (Requirements: 14.1)
            url = f'https://{domain}'
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            
            # Create SSL context that doesn't verify certificates
            import ssl
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            connector = aiohttp.TCPConnector(ssl=ssl_context)
            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                async with session.get(url, allow_redirects=True) as response:
                    headers = response.headers
                    
                    # Check for each required header
                    header_results = {}
                    missing_headers = []
                    
                    for header in required_headers:
                        if header in headers:
                            header_results[header] = headers[header]
                        else:
                            header_results[header] = None
                            missing_headers.append(header)
                    
                    # Determine status (Requirements: 14.6)
                    if missing_headers:
                        return {
                            'status': 'WARNING',
                            'message': f'Missing Headers: {", ".join(missing_headers)}',
                            'headers': header_results,
                            'missing_headers': missing_headers
                        }
                    
                    return {
                        'status': 'OK',
                        'message': 'All security headers present',
                        'headers': header_results,
                        'missing_headers': []
                    }
            
        except aiohttp.ClientError as e:
            return {
                'status': 'ERROR',
                'message': f'Failed to check security headers: {str(e)}',
                'headers': {},
                'missing_headers': []
            }
        except Exception as e:
            return {
                'status': 'ERROR',
                'message': f'Security headers check failed: {str(e)}',
                'headers': {},
                'missing_headers': []
            }
