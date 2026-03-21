"""
Aura Omni v3 — Hyper-Speed Reactor (Async Core Requester)
=========================================================
This module replaces the synchronous httpx calls with lightning-fast
asynchronous requests using `httpx.AsyncClient`. 
It includes connection pooling, rate limiting (semaphores), and automatic retries
to ensure stability when hitting a target with 100+ requests per second.
"""

import asyncio
import httpx
import logging
from typing import List, Dict, Any, Optional

from aura.core.phantom_router import PhantomRouter
from aura.core.privacy import PrivacyFilter
from aura.core.signers import SignerManager

class AsyncRequester:
    def __init__(self, concurrency_limit: int = 50, timeout: int = 15, proxy_file: Optional[str] = None):
        """
        Initializes the async requester with a connection pool and rate limiter.
        """
        self.concurrency_limit = concurrency_limit
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(self.concurrency_limit)
        self.phantom = PhantomRouter(proxy_file)
        self.proxy_file = proxy_file
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        self._client = httpx.AsyncClient(timeout=self.timeout, verify=False)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            await self._client.aclose()
            self._client = None

    async def ghost_fetch(self, method: str, url: str, **kwargs) -> Optional[Any]:
        """
        Aura v25.0: The Ghost Protocol.
        Uses curl_cffi to mimic a real Chrome browser TLS fingerprint.
        Bypasses JA3/TLS-based Cloudflare blocks.
        """
        try:
            from curl_cffi import requests as ghost_requests
            
            # Mask logging
            masked_url = PrivacyFilter.redact(url)
            logging.debug(f"[GHOST] Requesting {masked_url}")
            
            # Auto-sign if needed
            signer = SignerManager.get_signer(url)
            if signer:
                kwargs["headers"] = signer.sign(method, url, kwargs.get("headers", {}), kwargs.get("json") or kwargs.get("data"))

            response = ghost_requests.request(
                method, 
                url, 
                impersonate="chrome110", 
                timeout=self.timeout,
                verify=False,
                **kwargs
            )
            return response
        except Exception as e:
            logging.error(f"[GHOST] Error: {e}")
            return None

    async def fetch(self, method: str, url: str, **kwargs) -> Optional[httpx.Response]:
        """
        Core fetching method with Semaphore concurrency and Auto-Signer integration.
        """
        if not self._client:
            raise RuntimeError("AsyncRequester must be used as an async context manager.")
            
        # Apply target-specific signing if registered
        signer = SignerManager.get_signer(url)
        if signer:
            kwargs["headers"] = signer.sign(method, url, kwargs.get("headers", {}), kwargs.get("json") or kwargs.get("data"))

        retries = kwargs.pop("retries", 3)
        client_to_use = self._client
        
        async with self.semaphore:
            for attempt in range(retries):
                try:
                    # 1. Phantom Evasion Headers (Random UA + Chrome/Firefox spoofing)
                    headers = kwargs.get("headers", {})
                    evasion_headers = self.phantom.get_evasion_headers()
                    # Merge but don't overwrite if explicitly provided by the module
                    for k, v in evasion_headers.items():
                        if k not in headers:
                            headers[k] = v
                    kwargs["headers"] = headers

                    # 2. Fire the request
                    response = await client_to_use.request(method, url, **kwargs)

                    # 3. Auto-WAF Bypass
                    # If we hit a WAF block (403, 429) AND we have a proxy string active:
                    if response.status_code in (403, 429) and self.phantom.is_active:
                        if attempt < retries - 1:
                            new_proxy = self.phantom.get_proxy()
                            client_to_use = self._create_client(new_proxy)
                            # Remove the old user agent so it gets fresh generated on retry
                            if "User-Agent" in headers: del headers["User-Agent"]
                            kwargs["headers"] = headers
                            # Small jitter sleep
                            await asyncio.sleep(0.5)
                            continue # Try again with new identity
                    
                    return response

                except (httpx.RequestError, httpx.TimeoutException) as e:
                    if attempt == retries - 1:
                        return None
                    
                    # On connection failure, rotate proxy if active
                    if self.phantom.is_active:
                        new_proxy = self.phantom.get_proxy()
                        client_to_use = self._create_client(new_proxy)

                    await asyncio.sleep(0.5)
        return None

    async def fetch_all(self, requests: List[Dict[str, Any]]) -> List[Optional[httpx.Response]]:
        """
        Executes a batch of requests concurrently.
        
        Args:
            requests: List of dicts, each containing:
                - method: 'GET', 'POST', etc.
                - url: Target URL
                - **kwargs: headers, cookies, data, json, etc.
        """
        tasks = []
        for req in requests:
            # v38.0: Create a copy to avoid mutating the original request dict
            r_copy = req.copy()
            method = r_copy.pop("method", "GET")
            url = r_copy.pop("url")
            tasks.append(self.fetch(method, url, **r_copy))
            
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r if isinstance(r, httpx.Response) else None for r in results]

# Helper function to easily run a batch without managing the context manager manually
async def run_async_batch(requests: List[Dict[str, Any]], concurrency: int = 50, proxy_file: Optional[str] = None) -> List[Optional[httpx.Response]]:
    """
    Given a list of request dictionaries, executes them all concurrently with optional proxy evasion.
    """
    async with AsyncRequester(concurrency_limit=concurrency, proxy_file=proxy_file) as requester:
        results = await requester.fetch_all(requests)
        clean_results = [r if isinstance(r, httpx.Response) else None for r in results]
        return clean_results
