"""
Aura v29.0 — Web Cache Poisoning Engine 🕸️
===========================================
Detects Web Cache Poisoning vulnerabilities by injecting into
"unkeyed" HTTP headers — headers that affect the response but
are NOT included in the cache key.

If a reflected unkeyed header is cacheable, the poisoned response
gets served to ALL subsequent visitors requesting the same URL.

Attack vectors:
  - X-Forwarded-Host → reflected in redirect or HTML links
  - X-Forwarded-Scheme → forces HTTP downgrade
  - X-Host, X-Original-URL, X-Rewrite-URL → reflected in path
  - Vary header bypass: X-Cache-Buster (unique per request)
"""
import asyncio
import hashlib
import re
import time
import httpx
from rich.console import Console

console = Console()

# Unkeyed headers to test with a canary value
UNKEYED_HEADERS = [
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-HTTP-Host-Override",
    "Forwarded",
    "X-Forwarded-For",
    "X-Forwarded-Scheme",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Custom-IP-Authorization",
    "X-Originating-IP",
    "True-Client-IP",
    "CF-Connecting-IP",
]

# Indicators that a response is cacheable
CACHE_INDICATORS = [
    "cache-control",
    "x-cache",
    "cf-cache-status",
    "age",
    "x-varnish",
    "x-drupal-cache",
    "surrogate-control",
]


class CachePoisoningEngine:
    """
    v29.0: Web Cache Poisoning Engine.
    Detects unkeyed header reflection in cacheable responses.
    """

    CANARY = "aura-cache-poison-29"

    def __init__(self, session=None):
        self.session = session

    def _is_cacheable(self, response: httpx.Response) -> tuple[bool, str]:
        """Check if a response is cacheable and return evidence."""
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        evidence = []

        # Strong cache indicators
        x_cache = headers_lower.get("x-cache", "")
        if "hit" in x_cache.lower() or "miss" in x_cache.lower():
            evidence.append(f"X-Cache: {x_cache}")

        cf_cache = headers_lower.get("cf-cache-status", "")
        if cf_cache:
            evidence.append(f"CF-Cache-Status: {cf_cache}")

        age = headers_lower.get("age", "")
        if age and age.isdigit() and int(age) > 0:
            evidence.append(f"Age: {age}s (cached content)")

        cc = headers_lower.get("cache-control", "")
        if "public" in cc or "max-age" in cc:
            evidence.append(f"Cache-Control: {cc}")

        if "x-varnish" in headers_lower:
            evidence.append("Varnish cache detected")

        return bool(evidence), ", ".join(evidence) if evidence else "No cache detected"

    async def _test_header(self, client: httpx.AsyncClient, url: str,
                           header_name: str) -> dict | None:
        """Tests a single unkeyed header for reflection and cacheability."""
        canary = f"{self.CANARY}-{header_name.lower().replace('-', '')}"

        # 1. Send request with poisoned header
        try:
            r = await client.get(
                url,
                headers={
                    header_name: canary,
                    "Cache-Buster": f"aura{int(time.time())}",  # unique per test
                },
                timeout=12,
                follow_redirects=True
            )
        except Exception as e:
            return None

        # 2. Check if canary is reflected in the response body or headers
        reflected_in_body = canary in r.text
        reflected_in_headers = any(canary in str(v) for v in r.headers.values())
        is_cached, cache_evidence = self._is_cacheable(r)

        if not (reflected_in_body or reflected_in_headers):
            return None

        reflection_location = (
            "response body" if reflected_in_body else "response headers"
        )

        # 3. Confirm with a second request WITHOUT the header to verify poisoning
        await asyncio.sleep(0.5)
        try:
            r2 = await client.get(url, timeout=10, follow_redirects=True)
            poisoning_confirmed = canary in r2.text or canary in str(r2.headers)
        except Exception:
            poisoning_confirmed = False

        severity = "CRITICAL" if poisoning_confirmed and is_cached else "HIGH"

        evidence = (
            f"Web Cache Poisoning via `{header_name}`\n"
            f"URL: {url}\n"
            f"Injected Value: `{canary}`\n"
            f"Reflection: Found in {reflection_location}\n"
            f"Cache Status: {cache_evidence}\n"
        )
        if poisoning_confirmed:
            evidence += f"\n⚠️  CRITICAL: Poisoning CONFIRMED — second request (no header) still received poisoned value!\n"
            evidence += f"Impact: All visitors to {url} may receive the poisoned response.\n"
        else:
            evidence += f"\nNote: Reflection detected but cache poisoning not yet confirmed (may require specific cache conditions).\n"

        evidence += (
            f"\nRemediation: Use a Vary header to include {header_name} in the cache key, "
            f"or strip unkeyed headers at the CDN/reverse proxy level."
        )

        return {
            "type": "Web Cache Poisoning",
            "finding_type": "Web Cache Poisoning",
            "severity": severity,
            "owasp": "A05:2021 – Security Misconfiguration",
            "mitre": "T1557 – Adversary-in-the-Middle",
            "content": evidence,
            "url": url,
            "confirmed": poisoning_confirmed,
            "poc_evidence": evidence,
        }

    async def scan_target(self, target_url: str) -> list:
        """Tests the target for Web Cache Poisoning across all unkeyed headers."""
        console.print(f"[bold cyan][🕸️ Cache Poison] Testing {len(UNKEYED_HEADERS)} unkeyed headers on {target_url}...[/bold cyan]")
        findings = []
        seen = set()

        async with httpx.AsyncClient(verify=False, follow_redirects=False) as client:
            sem = asyncio.Semaphore(5)

            async def _test(header):
                async with sem:
                    return await self._test_header(client, target_url, header)

            results = await asyncio.gather(*[_test(h) for h in UNKEYED_HEADERS])

        for r in results:
            if r is None:
                continue
            sig = f"{r['url']}_{r['type']}"
            if sig in seen:
                continue
            seen.add(sig)
            severity_label = "[bold red]CRITICAL[/bold red]" if r["severity"] == "CRITICAL" else "[yellow]HIGH[/yellow]"
            console.print(f"[bold red][🕸️ CACHE POISON] {severity_label} — {r['content'][:120]}[/bold red]")
            findings.append(r)

        if not findings:
            console.print(f"[dim][Cache Poison] No poisonable headers detected on {target_url}[/dim]")
        return findings

    async def scan_urls(self, urls: list) -> list:
        all_findings = []
        for url in urls[:10]:  # limit to avoid rate limits
            try:
                results = await self.scan_target(url)
                all_findings.extend(results)
            except Exception as e:
                console.print(f"[dim red][Cache Poison] Skipped {url}: {e}[/dim red]")
        return all_findings
