"""
Aura v28.0 — Race Condition Hunter ⚡
======================================
Detects race condition vulnerabilities by sending parallel HTTP requests
with sub-millisecond precision timing. Targets single-use logic:
- Coupon/promo code redemption
- Payment processing checkpoints
- Account creation with referral bonuses
- Loyalty point transactions
- Email verification links
"""
import asyncio
import httpx
import re
import time
from typing import List, Dict, Any, Optional, Tuple
from rich.console import Console
from aura.core import state
from aura.core.nexus_bridge import NexusBridge

from aura.ui.formatter import console

# Endpoints likely to have single-use state
RACE_CANDIDATE_PATTERNS = [
    r'/coupon', r'/promo', r'/redeem', r'/apply',
    r'/checkout', r'/pay', r'/purchase', r'/buy',
    r'/transfer', r'/withdraw', r'/send',
    r'/verify', r'/confirm', r'/activate',
    r'/vote', r'/like', r'/refer', r'/invite',
    r'/reset', r'/use', r'/claim', r'/register',
]

RACE_CONCURRENCY = 25   # simultaneous requests in a single burst


class RaceConditionHunter:
    """
    v50.0 OMEGA: Race Condition Hunter.
    Uses Nexus (Go) for microsecond-precise parallel bursting.
    """

    def __init__(self, session=None):
        self.session = session
        self._candidates = []
        try:
            self.nexus = NexusBridge()
        except:
            self.nexus = None

    # ── Candidate Detection ──────────────────────────────────────────────────
    def _is_candidate(self, url: str) -> bool:
        """Checks if a URL is likely to have single-use state."""
        url_low = url.lower()
        return any(re.search(p, url_low) for p in RACE_CANDIDATE_PATTERNS)

    def _filter_candidates(self, urls: list) -> list:
        return [u for u in urls if self._is_candidate(u)]

    # ── Single Race Burst ────────────────────────────────────────────────────
    async def _race_burst(self, url: str, method: str = "GET",
                          data: dict = None, headers: dict = None) -> list:
        """
        Fires RACE_CONCURRENCY requests simultaneously.
        Uses Nexus (Go) for maximum precision, or httpx fallback.
        """
        if self.nexus and method.upper() == "POST":
            console.print("[yellow][⚡] Nexus Core Active: Initiating synchronized high-precision burst...[/yellow]")
            # Go results are [Result{URL, StatusCode, Server}, ...]
            go_results = self.nexus.race_burst(url, data or {}, RACE_CONCURRENCY)
            return [(r["status"], 0, f"Nexus-Burst: {r['server']}") for r in go_results]

        # FALLBACK: Native Python Async + HTTP/2
        shared_headers = {
            "User-Agent": "Mozilla/5.0 (compatible; AuraRaceEngine/28.0)",
            **(headers or {})
        }

        async def _single_req(client):
            t0 = time.monotonic()
            try:
                if method.upper() == "POST":
                    r = await client.post(url, data=data or {}, headers=shared_headers, timeout=10)
                else:
                    r = await client.get(url, headers=shared_headers, timeout=10)
                elapsed = time.monotonic() - t0
                return (r.status_code, elapsed, r.text[:200])
            except Exception as e:
                return (0, time.monotonic() - t0, str(e)[:100])

        limits = httpx.Limits(max_connections=RACE_CONCURRENCY, max_keepalive_connections=RACE_CONCURRENCY)
        async with httpx.AsyncClient(limits=limits, verify=False, follow_redirects=True, http2=True) as client:
            tasks = [_single_req(client) for _ in range(RACE_CONCURRENCY)]
            results = await asyncio.gather(*tasks)

        return list(results)

    # ── Race Analysis ────────────────────────────────────────────────────────
    def _analyze_results(self, results: list) -> dict:
        """
        Determines if a race condition was triggered.
        Signs of success:
        1. Multiple 200 OK responses where only 1 was expected
        2. Different response bodies for same request (state divergence)
        3. Success count > 1 on "single-use" endpoint
        """
        status_codes = [r[0] for r in results]
        bodies = [r[2] for r in results]

        success_count = status_codes.count(200)
        unique_bodies = len(set(bodies))

        # Success indicators
        success_indicators = []

        if success_count > 1:
            success_indicators.append(
                f"Multiple successes: {success_count}/{len(results)} requests returned 200 OK."
            )

        if unique_bodies > 1 and success_count > 0:
            success_indicators.append(
                f"State divergence detected: {unique_bodies} unique responses for identical requests."
            )

        # Check for success keywords in bodies
        success_keywords = ["success", "applied", "redeemed", "confirmed", "accepted", "credited", "discount"]
        success_body_hits = sum(1 for b in bodies if any(k in b.lower() for k in success_keywords))
        if success_body_hits > 1:
            success_indicators.append(
                f"Success keywords appeared {success_body_hits} times in parallel responses."
            )

        return {
            "confirmed": len(success_indicators) > 0,
            "success_count": success_count,
            "total_requests": len(results),
            "indicators": success_indicators,
            "status_distribution": {str(s): status_codes.count(s) for s in set(status_codes)},
        }

    # ── Main Scan ────────────────────────────────────────────────────────────
    async def scan_urls(self, urls: list) -> list:
        """
        Scans a list of URLs for race conditions.
        Returns confirmed findings.
        """
        candidates = self._filter_candidates(urls)
        if not candidates:
            console.print("[dim][Race] No race condition candidates detected in URL set.[/dim]")
            return []

        console.print(f"[bold cyan][⚡ Race] {len(candidates)} endpoint(s) identified as race candidates.[/bold cyan]")
        findings = []

        for url in candidates:
            console.print(f"[cyan][⚡ Race] Bursting {RACE_CONCURRENCY} simultaneous requests → {url}[/cyan]")
            results = await self._race_burst(url)
            analysis = self._analyze_results(results)

            sev = "CRITICAL" if analysis["confirmed"] else "INFO"
            status_str = str(analysis["status_distribution"])
            indicators_str = "\n".join(f"  - {i}" for i in analysis["indicators"])

            if analysis["confirmed"]:
                evidence = (
                    f"Race Condition CONFIRMED on {url}\n"
                    f"Result: {analysis['success_count']}/{analysis['total_requests']} requests succeeded simultaneously.\n"
                    f"Status Distribution: {status_str}\n"
                    f"Evidence:\n{indicators_str}"
                )
                console.print(f"[bold red][⚡ RACE CONFIRMED] {evidence}[/bold red]")
                findings.append({
                    "type": "Race Condition",
                    "finding_type": "Race Condition",
                    "severity": "CRITICAL",
                    "owasp": "A04:2021 – Insecure Design",
                    "mitre": "T1499.003",
                    "content": evidence,
                    "url": url,
                    "confirmed": True,
                    "poc_evidence": evidence,
                })
            else:
                console.print(
                    f"[dim][Race] No race detected on {url} "
                    f"(Status: {status_str})[/dim]"
                )

        return findings

    async def scan_target(self, target_url: str) -> list:
        """Quick single-target scan using common race-prone paths."""
        from urllib.parse import urlparse
        base = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
        probe_paths = [
            "/api/coupon/apply", "/api/promo/redeem", "/checkout/apply-coupon",
            "/api/payment/confirm", "/api/referral/claim", "/api/vote",
            "/api/transfer", "/account/verify", "/api/invite/use",
        ]
        probe_urls = [f"{base}{p}" for p in probe_paths]
        return await self.scan_urls(probe_urls)
