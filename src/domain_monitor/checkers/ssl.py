"""
SSL certificate checker for domain monitoring.

Verifies SSL certificate validity, expiration dates, and certificate details.
"""

import asyncio
import logging
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any

from cryptography import x509 as crypto_x509
from cryptography.x509.oid import ExtensionOID
from OpenSSL import crypto

from .base_checker import BaseChecker, CheckResult

logger = logging.getLogger(__name__)


class SSLChecker(BaseChecker):
    """
    Checker for SSL certificate validation and expiration monitoring.
    
    Connects to the domain on port 443, retrieves the SSL certificate,
    and validates its expiration date and details.
    """
    
    async def check(self, domain: str, **kwargs: Any) -> CheckResult:
        """
        Check SSL certificate for the specified domain.
        
        Establishes an SSL connection to port 443, retrieves the certificate,
        parses its details, and determines the status based on expiration date.
        
        Args:
            domain: The domain name to check
            **kwargs: Additional parameters (unused)
            
        Returns:
            CheckResult with SSL certificate status and details
            
        Requirements: 4.1
        """
        check_start_time = time.time()
        logger.debug(f"Starting SSL check for domain: {domain}")
        
        try:
            # Get the certificate
            logger.debug(f"Establishing SSL connection to {domain}:443")
            cert_start = time.time()
            cert_dict = await self._get_certificate(domain)
            cert_retrieval_time = time.time() - cert_start
            logger.debug(f"SSL certificate retrieved for {domain} in {cert_retrieval_time:.3f}s")
            
            # Parse certificate details
            logger.debug(f"Parsing SSL certificate for {domain}")
            parse_start = time.time()
            cert_info = self._parse_certificate(cert_dict)
            parse_time = time.time() - parse_start
            logger.debug(f"Certificate parsed in {parse_time:.3f}s")
            
            # Log certificate details
            logger.debug(f"Certificate details for {domain}:")
            logger.debug(f"  Issuer: {cert_info.get('issuer', 'Unknown')}")
            logger.debug(f"  Subject: {cert_info.get('subject', 'Unknown')}")
            logger.debug(f"  SANs: {cert_info.get('sans', [])}")
            logger.debug(f"  Expiration: {cert_info.get('expiration_date', 'Unknown')}")
            
            # Calculate days until expiry
            expiration_date_str = cert_info['expiration_date']
            # Parse the ISO format string back to datetime
            if isinstance(expiration_date_str, str):
                expiration_date = datetime.fromisoformat(expiration_date_str)
            else:
                expiration_date = expiration_date_str
            
            now = datetime.now(timezone.utc)
            days_until_expiry = (expiration_date - now).days
            
            logger.debug(f"SSL certificate for {domain} expires in {days_until_expiry} days")
            
            # Determine status based on expiration
            status = self._determine_status(days_until_expiry)
            
            # Create appropriate message
            if days_until_expiry < 0:
                message = f"SSL certificate expired {abs(days_until_expiry)} days ago"
            elif days_until_expiry < 7:
                message = f"SSL certificate expires in {days_until_expiry} days (CRITICAL)"
            elif days_until_expiry < 14:
                message = f"SSL certificate expires in {days_until_expiry} days"
            else:
                message = f"SSL certificate valid for {days_until_expiry} days"
            
            # Add days_until_expiry and timing to details
            cert_info['days_until_expiry'] = days_until_expiry
            cert_info['timing'] = {
                'certificate_retrieval_time': cert_retrieval_time,
                'parse_time': parse_time,
                'total_check_time': time.time() - check_start_time
            }
            
            logger.debug(f"SSL check completed for {domain} in {cert_info['timing']['total_check_time']:.3f}s")
            
            return self._create_result(
                domain=domain,
                status=status,
                message=message,
                details=cert_info
            )
            
        except socket.gaierror as e:
            logger.error(f"Failed to resolve domain {domain}: {e!s}")
            return self._create_result(
                domain=domain,
                status=CheckResult.ERROR,
                message="Failed to resolve domain name"
            )
        except TimeoutError:
            logger.warning(f"SSL connection to {domain} timed out after {self.timeout}s")
            return self._create_result(
                domain=domain,
                status=CheckResult.ERROR,
                message=f"Connection timed out after {self.timeout}s"
            )
        except ssl.SSLError as e:
            logger.exception(f"SSL error for {domain}: {e!s}")
            return self._create_result(
                domain=domain,
                status=CheckResult.ERROR,
                message=f"SSL error: {e!s}"
            )
        except Exception as e:
            logger.exception(f"SSL check failed for {domain}: {e!s}")
            return self._create_result(
                domain=domain,
                status=CheckResult.ERROR,
                message=f"SSL check failed: {e!s}"
            )
    
    async def _get_certificate(self, domain: str, port: int = 443) -> dict[str, Any]:
        """
        Establish SSL connection and retrieve certificate.
        
        Creates an SSL socket connection to the specified domain and port,
        retrieves the peer certificate, and returns it as a dictionary.
        
        Args:
            domain: The domain name to connect to
            port: The port to connect to (default: 443)
            
        Returns:
            Dictionary containing certificate information
            
        Raises:
            socket.gaierror: If domain cannot be resolved
            socket.timeout: If connection times out
            ssl.SSLError: If SSL handshake fails
            
        Requirements: 4.1
        """
        # Run the blocking socket operation in a thread pool
        loop = asyncio.get_event_loop()
        cert_dict = await loop.run_in_executor(
            None,
            self._get_certificate_sync,
            domain,
            port
        )
        return cert_dict
    
    def _get_certificate_sync(self, domain: str, port: int) -> dict[str, Any]:
        """
        Synchronous helper to get certificate (runs in thread pool).
        
        Args:
            domain: The domain name to connect to
            port: The port to connect to
            
        Returns:
            Dictionary containing certificate information
        """
        # Create context that doesn't verify certificates but still gets cert info
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((domain, port), timeout=self.timeout) as sock:
            # First get the certificate in binary form (always works)
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
        
        # Now parse the certificate using cryptography x509 to get details
        if cert_der:
            cert_crypto = crypto_x509.load_der_x509_certificate(cert_der)
            
            # Build cert_dict from cryptography x509 object
            subject_components = [
                (attr.oid._name or attr.oid.dotted_string, str(attr.value))
                for attr in cert_crypto.subject
            ]
            issuer_components = [
                (attr.oid._name or attr.oid.dotted_string, str(attr.value))
                for attr in cert_crypto.issuer
            ]
            
            not_before_str = cert_crypto.not_valid_before_utc.strftime('%b %d %H:%M:%S %Y GMT')
            not_after_str = cert_crypto.not_valid_after_utc.strftime('%b %d %H:%M:%S %Y GMT')
            
            cert_dict = {
                '_der': cert_der,
                'subject': tuple(subject_components),
                'issuer': tuple(issuer_components),
                'version': cert_crypto.version.value,
                'serialNumber': str(cert_crypto.serial_number),
                'notBefore': not_before_str,
                'notAfter': not_after_str,
            }
            
            # Extract SANs if available
            sans = []
            try:
                san_ext = cert_crypto.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                if isinstance(san_ext.value, crypto_x509.SubjectAlternativeName):
                    for dns_name in san_ext.value.get_values_for_type(crypto_x509.DNSName):
                        sans.append(('DNS', dns_name))
            except Exception:
                pass
            
            if sans:
                cert_dict['subjectAltName'] = tuple(sans)
            
            return cert_dict
        
        return {}
    
    def _parse_certificate(self, cert_dict: dict[str, Any]) -> dict[str, Any]:
        """
        Parse certificate details from certificate dictionary.
        
        Extracts issuer, subject, SANs (Subject Alternative Names), and
        expiration date from the certificate.
        
        Args:
            cert_dict: Certificate dictionary from SSL socket
            
        Returns:
            Dictionary with parsed certificate information:
                - issuer: Certificate issuer organization
                - subject: Certificate subject (domain)
                - sans: List of Subject Alternative Names
                - expiration_date: Certificate expiration as datetime
                
        Requirements: 4.2, 4.3, 4.4
        """
        cert_info = {}
        
        # Extract issuer (Requirements: 4.2)
        # issuer is a tuple of tuples: ((('organizationName', 'Let\'s Encrypt'),),)
        issuer_tuple = cert_dict.get('issuer', ())
        issuer_dict = {}
        for rdn in issuer_tuple:
            for name_tuple in rdn:
                if len(name_tuple) == 2:
                    issuer_dict[name_tuple[0]] = name_tuple[1]
        cert_info['issuer'] = issuer_dict.get('organizationName', issuer_dict.get('commonName', issuer_dict.get('O', 'Unknown')))
        
        # Extract subject (Requirements: 4.3)
        # subject is also a tuple of tuples: ((('commonName', 'example.com'),),)
        subject_tuple = cert_dict.get('subject', ())
        subject_dict = {}
        for rdn in subject_tuple:
            for name_tuple in rdn:
                if len(name_tuple) == 2:
                    subject_dict[name_tuple[0]] = name_tuple[1]
        cert_info['subject'] = subject_dict.get('commonName', subject_dict.get('CN', 'Unknown'))
        
        # Extract SANs (Subject Alternative Names) (Requirements: 4.3)
        sans = []
        if 'subjectAltName' in cert_dict:
            sans = [name[1] for name in cert_dict['subjectAltName'] if name[0] == 'DNS']
        cert_info['sans'] = sans
        
        # Extract expiration date (Requirements: 4.4)
        # notAfter format: 'Nov  5 10:30:00 2025 GMT'
        not_after = cert_dict.get('notAfter', '')
        try:
            # Parse the date string
            expiration_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
            # Make it timezone-aware (UTC)
            expiration_date = expiration_date.replace(tzinfo=timezone.utc)
        except (ValueError, AttributeError):
            # Fallback: try using OpenSSL if available
            if '_der' in cert_dict:
                try:
                    x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_dict['_der'])
                    not_after_bytes = x509.get_notAfter()
                    if not_after_bytes:
                        # Format: b'20251105103000Z'
                        not_after_str = not_after_bytes.decode('ascii')
                        expiration_date = datetime.strptime(not_after_str, '%Y%m%d%H%M%SZ')
                        expiration_date = expiration_date.replace(tzinfo=timezone.utc)
                    else:
                        expiration_date = datetime.now(timezone.utc)
                except Exception:
                    # Last resort: use current time (will show as expired)
                    expiration_date = datetime.now(timezone.utc)
            else:
                expiration_date = datetime.now(timezone.utc)
        
        cert_info['expiration_date'] = expiration_date.isoformat()
        
        return cert_info
    
    def _determine_status(self, days_until_expiry: int) -> str:
        """
        Determine status based on days until certificate expiration.
        
        Status levels:
        - RED (CRITICAL): Certificate expired or expires within 7 days
        - YELLOW (WARNING): Certificate expires within 14 days
        - GREEN (OK): Certificate valid for 14 or more days
        
        Args:
            days_until_expiry: Number of days until certificate expires
            
        Returns:
            Status string (OK, WARNING, or CRITICAL)
            
        Requirements: 4.5, 4.6, 4.7
        """
        if days_until_expiry < 0:
            # Certificate has expired (Requirements: 4.7)
            return CheckResult.CRITICAL
        elif days_until_expiry < 7:
            # Expires within 7 days (Requirements: 4.6)
            return CheckResult.CRITICAL
        elif days_until_expiry < 14:
            # Expires within 14 days (Requirements: 4.5)
            return CheckResult.WARNING
        else:
            # Valid for 14+ days
            return CheckResult.OK
