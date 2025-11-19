"""
WHOIS checker for domain registration information.

Queries WHOIS data to extract registrar, status, and expiration information,
and determines the urgency level based on days until expiration.
"""

import asyncio
import logging
import time
from datetime import datetime
from typing import Optional

import whois

from .base_checker import BaseChecker, CheckResult

logger = logging.getLogger(__name__)


class WhoisChecker(BaseChecker):
    """
    Checker for WHOIS domain registration information.
    
    Queries WHOIS data to retrieve:
    - Domain registrar
    - Domain status
    - Expiration date
    
    Determines status based on days until expiration:
    - RED (CRITICAL): < 30 days
    - YELLOW (WARNING): < 60 days
    - GREEN (OK): >= 60 days
    """
    
    async def check(self, domain: str, **kwargs) -> CheckResult:
        """
        Execute WHOIS check for the specified domain.
        
        Args:
            domain: The domain name to check
            **kwargs: Additional parameters (unused)
            
        Returns:
            CheckResult with WHOIS information and expiration status
        """
        check_start_time = time.time()
        logger.debug(f"Starting WHOIS check for domain: {domain}")
        
        try:
            # Run WHOIS query in thread pool to avoid blocking
            logger.debug(f"Querying WHOIS data for {domain}")
            query_start = time.time()
            loop = asyncio.get_event_loop()
            whois_data = await loop.run_in_executor(None, whois.whois, domain)
            query_time = time.time() - query_start
            logger.debug(f"WHOIS query completed for {domain} in {query_time:.3f}s")
            
            # Extract key information
            logger.debug(f"Extracting WHOIS information for {domain}")
            registrar = self._extract_registrar(whois_data)
            status = self._extract_status(whois_data)
            expiration_date = self._extract_expiration_date(whois_data)
            country = self._extract_country(whois_data)
            
            logger.debug(f"WHOIS data for {domain}:")
            logger.debug(f"  Registrar: {registrar}")
            logger.debug(f"  Country: {country}")
            logger.debug(f"  Status: {status}")
            logger.debug(f"  Expiration Date: {expiration_date}")
            
            if not expiration_date:
                logger.warning(f"Unable to extract expiration date from WHOIS data for {domain}")
                return self._create_result(
                    domain=domain,
                    status=CheckResult.ERROR,
                    message="Unable to extract expiration date from WHOIS data",
                    details={
                        "registrar": registrar,
                        "country": country,
                        "status": status,
                        "query_time": query_time,
                        "total_check_time": time.time() - check_start_time
                    }
                )
            
            # Calculate days until expiry
            days_until_expiry = self._calculate_days_until_expiry(expiration_date)
            logger.debug(f"Domain {domain} expires in {days_until_expiry} days")
            
            # Determine status based on days until expiry
            check_status = self._determine_status(days_until_expiry)
            
            # Create appropriate message
            if days_until_expiry < 0:
                message = f"Domain expired {abs(days_until_expiry)} days ago"
            else:
                message = f"Domain expires in {days_until_expiry} days"
            
            total_time = time.time() - check_start_time
            logger.debug(f"WHOIS check completed for {domain} in {total_time:.3f}s")
            
            return self._create_result(
                domain=domain,
                status=check_status,
                message=message,
                details={
                    "registrar": registrar,
                    "country": country,
                    "status": status,
                    "expiration_date": expiration_date.isoformat() if expiration_date else None,
                    "days_until_expiry": days_until_expiry,
                    "timing": {
                        "query_time": query_time,
                        "total_check_time": total_time
                    }
                }
            )
            
        except (AttributeError, KeyError) as e:
            # Handle WHOIS parsing errors
            logger.error(f"WHOIS query failed for {domain}: {str(e)}", exc_info=True)
            return self._create_result(
                domain=domain,
                status=CheckResult.ERROR,
                message=f"WHOIS query failed: {str(e)}",
                details={"error_type": "whois_error"}
            )
        except Exception as e:
            logger.error(f"WHOIS check failed for {domain}: {str(e)}", exc_info=True)
            return self._create_result(
                domain=domain,
                status=CheckResult.ERROR,
                message=f"WHOIS check failed: {str(e)}",
                details={"error_type": type(e).__name__}
            )
    
    def _extract_registrar(self, whois_data) -> Optional[str]:
        """
        Extract registrar information from WHOIS data.
        
        Args:
            whois_data: WHOIS query result object
            
        Returns:
            Registrar name or None if not available
        """
        if hasattr(whois_data, 'registrar'):
            registrar = whois_data.registrar
            if isinstance(registrar, list):
                return registrar[0] if registrar else None
            return registrar
        return None
    
    def _extract_status(self, whois_data) -> Optional[str]:
        """
        Extract domain status from WHOIS data.
        
        Args:
            whois_data: WHOIS query result object
            
        Returns:
            Domain status or None if not available
        """
        if hasattr(whois_data, 'status'):
            status = whois_data.status
            if isinstance(status, list):
                return ', '.join(status) if status else None
            return status
        return None
    
    def _extract_country(self, whois_data) -> Optional[str]:
        """
        Extract country information from WHOIS data.
        
        Args:
            whois_data: WHOIS query result object
            
        Returns:
            Country code or name, or None if not available
        """
        if hasattr(whois_data, 'country'):
            country = whois_data.country
            if isinstance(country, list):
                return country[0] if country else None
            return country
        return None
    
    def _extract_expiration_date(self, whois_data) -> Optional[datetime]:
        """
        Extract expiration date from WHOIS data.
        
        Args:
            whois_data: WHOIS query result object
            
        Returns:
            Expiration date as datetime object or None if not available
        """
        if hasattr(whois_data, 'expiration_date'):
            expiration = whois_data.expiration_date
            if isinstance(expiration, list):
                # Some domains return multiple dates, use the first one
                expiration = expiration[0] if expiration else None
            
            if isinstance(expiration, datetime):
                return expiration
        
        return None
    
    def _calculate_days_until_expiry(self, expiry_date: datetime) -> int:
        """
        Calculate the number of days until domain expiration.
        
        Args:
            expiry_date: The domain expiration date
            
        Returns:
            Number of days until expiration (negative if already expired)
        """
        now = datetime.now()
        
        # Make expiry_date timezone-naive if it has timezone info
        if expiry_date.tzinfo is not None:
            expiry_date = expiry_date.replace(tzinfo=None)
        
        delta = expiry_date - now
        return delta.days
    
    def _determine_status(self, days_until_expiry: int) -> str:
        """
        Determine check status based on days until expiration.
        
        Status levels:
        - CRITICAL (RED): < 30 days or already expired
        - WARNING (YELLOW): < 60 days
        - OK (GREEN): >= 60 days
        
        Args:
            days_until_expiry: Number of days until expiration
            
        Returns:
            Status string (OK, WARNING, or CRITICAL)
        """
        if days_until_expiry < 30:
            return CheckResult.CRITICAL
        elif days_until_expiry < 60:
            return CheckResult.WARNING
        else:
            return CheckResult.OK
