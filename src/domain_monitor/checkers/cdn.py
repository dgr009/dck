"""CDN and Edge Protection Checker."""

import asyncio
import logging
import re
import socket
import time
from typing import Any, Dict, List, Optional, Tuple

import aiohttp
import dns.resolver

from .base_checker import BaseChecker, CheckResult

logger = logging.getLogger(__name__)


class CDNChecker(BaseChecker):
    """
    Checker for CDN and Edge DDoS Protection status.
    
    Detects CDN providers (Tencent EdgeOne, Cloudflare, CloudFront, Akamai, Fastly)
    via CNAME DNS records, IP resolution, and HTTP response headers.
    """
    
    CDN_SIGNATURES = [
        ('Tencent EdgeOne', [r'edgeone', r'eo-', r'tencentedge', r'qcloudcdn', r'eo-cdn']),
        ('Cloudflare', [r'cloudflare', r'cf-ray', r'cf-cache-status']),
        ('AWS CloudFront', [r'cloudfront', r'x-amz-cf-id', r'x-amz-cf-pop']),
        ('Akamai', [r'akamai', r'x-akamai']),
        ('Fastly', [r'fastly', r'x-fastly']),
        ('Baidu Yunjiasu', [r'yunjiasu', r'baidu']),
    ]
    
    async def check(self, domain: str, **kwargs: Any) -> CheckResult:
        """Execute CDN check for domain."""
        start_time = time.time()
        logger.debug(f"Starting CDN check for domain: {domain}")
        
        try:
            detected_providers = set()
            cname_records = []
            headers_found = {}
            
            # 1. Query CNAME records
            loop = asyncio.get_event_loop()
            cname_records = await loop.run_in_executor(
                None,
                self._query_cname_sync,
                domain
            )
            
            for cname in cname_records:
                cname_lower = cname.lower()
                for provider_name, patterns in self.CDN_SIGNATURES:
                    if any(re.search(pat, cname_lower) for pat in patterns):
                        detected_providers.add(provider_name)
            
            # 2. Check HTTP headers for CDN signatures
            headers_found = await self._check_http_headers(domain)
            for provider_name, patterns in self.CDN_SIGNATURES:
                for header_name, header_val in headers_found.items():
                    combined = f"{header_name}: {header_val}".lower()
                    if any(re.search(pat, combined) for pat in patterns):
                        detected_providers.add(provider_name)
            
            check_time = time.time() - start_time
            
            if detected_providers:
                providers_str = ", ".join(sorted(detected_providers))
                message = f"CDN / Edge Protection Active ({providers_str})"
                details = {
                    'cdn_active': True,
                    'providers': list(detected_providers),
                    'cname_records': cname_records,
                    'cdn_headers': headers_found,
                    'total_check_time': check_time
                }
                return self._create_result(domain=domain, status=CheckResult.OK, message=message, details=details)
            else:
                message = "No known CDN / Edge Protection detected (Direct Origin or Unlisted CDN)"
                details = {
                    'cdn_active': False,
                    'providers': [],
                    'cname_records': cname_records,
                    'total_check_time': check_time
                }
                return self._create_result(domain=domain, status=CheckResult.OK, message=message, details=details)
                
        except Exception as e:
            logger.error(f"CDN check failed for {domain}: {e}", exc_info=True)
            return self._create_result(
                domain=domain,
                status=CheckResult.ERROR,
                message=f"CDN check failed: {str(e)}",
                details={'error': str(e)}
            )
            
    def _query_cname_sync(self, domain: str) -> List[str]:
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        try:
            answers = resolver.resolve(domain, 'CNAME')
            return [str(r.target).rstrip('.') for r in answers]
        except Exception:
            return []

    async def _check_http_headers(self, domain: str) -> Dict[str, str]:
        url = f"https://{domain}"
        cdn_headers = {}
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                async with session.head(url, allow_redirects=True) as resp:
                    for k, v in resp.headers.items():
                        k_lower = k.lower()
                        if any(sig in k_lower or sig in v.lower() for sig in ['server', 'via', 'eo-', 'cf-', 'x-amz', 'akamai', 'fastly', 'cdn']):
                            cdn_headers[k] = v
        except Exception:
            pass
        return cdn_headers
