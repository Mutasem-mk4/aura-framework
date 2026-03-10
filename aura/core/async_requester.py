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

class AsyncRequester:
    def __init__(self, concurrency_limit: int = 50, timeout: int = 15, proxy_file: Optional[str] = None):
        """
        Initializes the async requester with a connection pool and rate limiter.
        
        Args:
            concurrency_limit (int): Maximum number of concurrent requests.
            timeout (int): Global timeout per request.
        """
        self.concurrency_limit = concurrency_limit
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(self.concurrency_limit)
        self.phantom = PhantomRouter(proxy_file)
        self.proxy_file = proxy_file
        
        # We reuse the same client across the session if no proxy rotation is needed
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        # We start with a base client. If we use a single proxy list, we'll
        # instantiate them dynamically if we hit a 403 or if proxy rotation is on.
        self._client = self._create_client(self.phantom.get_proxy())
        return self

    def _create_client(self, proxy_str: Optional[str] = None) -> httpx.AsyncClient:
        """Creates a new httpx client, optionally with a proxy."""
        limits = httpx.Limits(max_connections=self.concurrency_limit, max_keepalive_connections=self.concurrency_limit)
        if proxy_str:
            return httpx.AsyncClient(verify=False, timeout=self.timeout, limits=limits, proxies={"all://": proxy_str})
        return httpx.AsyncClient(verify=False, timeout=self.timeout, limits=limits)

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            await self._client.aclose()

    async def fetch(self, method: str, url: str, **kwargs) -> Optional[httpx.Response]:
        """
        Core fetching method with Semaphore concurrency, custom evasion headers,
        and Auto-WAF Bypass on 403/429.
        """
        if not self._client:
            raise RuntimeError("AsyncRequester must be used as an async context manager.")
            
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
            method = req.pop("method", "GET")
            url = req.pop("url")
            tasks.append(self.fetch(method, url, **req))
            
        return await asyncio.gather(*tasks, return_exceptions=True)

# Helper function to easily run a batch without managing the context manager manually
async def run_async_batch(requests: List[Dict[str, Any]], concurrency: int = 50, proxy_file: Optional[str] = None) -> List[Optional[httpx.Response]]:
    """
    Given a list of request dictionaries, executes them all concurrently with optional proxy evasion.
    """
    async with AsyncRequester(concurrency_limit=concurrency, proxy_file=proxy_file) as requester:
        results = await requester.fetch_all(requests)
        clean_results = [r if isinstance(r, httpx.Response) else None for r in results]
        return clean_results
