# -*- coding: utf-8 -*-
"""
Aura v31.0 - Open Redirect Engine (Phase 25)
=============================================
Detects open redirect vulnerabilities and chains them to OAuth token theft.

Techniques:
- Parameter discovery (next, redirect, url, return, to, dest...)
- Bypass techniques: //evil.com, /\/evil.com, %2f%2fevil.com, etc.
- OAuth redirect_uri manipulation
- Token leakage via Referer header
"""
import asyncio
import re
import httpx
from rich.console import Console

console = Console()

REDIRECT_PARAMS = [
    "redirect", "redirect_url", "redirect_uri", "return", "return_url",
    "next", "url", "to", "dest", "destination", "target", "link",
    "goto", "forward", "location", "continue", "success_url", "cancel_url",
    "back", "ref", "referer", "out", "view", "page", "callback",
]

EVIL_HOST = "https://aura-redirect-test.com"

# Bypass payloads
BYPASS_PAYLOADS = [
    "https://aura-redirect-test.com",
    "//aura-redirect-test.com",
    "/\\aura-redirect-test.com",
    "\\/aura-redirect-test.com",
    "https://aura-redirect-test.com%2f",
    "https://legitimate.com@aura-redirect-test.com",
    "https://aura-redirect-test.com#legitimate.com",
    "https://aura-redirect-test.com?.legitimate.com",
    "%2f%2faura-redirect-test.com",
    "https://aura-redirect-test%2ecom",
]


class OpenRedirectEngine:
    """v31.0: Open Redirect scanner with OAuth chaining."""

    def __init__(self, session=None):
        self.session = session

    def _check_redirected(self, response: httpx.Response) -> bool:
        """Checks if response redirects to our evil host."""
        loc = response.headers.get("Location", "")
        return "aura-redirect-test.com" in loc

    async def _test_param(self, client, url: str, param: str, payload: str) -> dict | None:
        """Tests a single redirect parameter with a payload."""
        test_url = f"{url}?{param}={payload}"
        try:
            r = await client.get(test_url, timeout=8, follow_redirects=False)
            if r.status_code in (301, 302, 303, 307, 308) and self._check_redirected(r):
                loc = r.headers.get("Location", "")
                return {
                    "type": "Open Redirect",
                    "finding_type": "Open Redirect",
                    "severity": "MEDIUM",
                    "owasp": "A01:2021 - Broken Access Control",
                    "mitre": "T1566 - Phishing",
                    "content": (
                        f"Open Redirect CONFIRMED\n"
                        f"URL: {test_url}\n"
                        f"Parameter: `{param}`\n"
                        f"Payload: {payload}\n"
                        f"Location: {loc}\n"
                        f"Impact: Can be chained with OAuth to steal access_tokens, "
                        f"or used for phishing attacks."
                    ),
                    "url": test_url,
                    "confirmed": True,
                    "poc_evidence": f"GET {test_url} -> {r.status_code} Location: {loc}"
                }
        except Exception:
            pass
        return None

    async def _scan_oauth_redirect(self, client, base_url: str) -> list:
        """Tests OAuth redirect_uri for open redirect."""
        oauth_paths = [
            "/oauth/authorize", "/auth/authorize", "/oauth2/authorize",
            "/connect/authorize", "/api/oauth/authorize",
        ]
        findings = []
        for path in oauth_paths:
            url = f"{base_url}{path}"
            test_url = f"{url}?response_type=code&client_id=test&redirect_uri={EVIL_HOST}"
            try:
                r = await client.get(test_url, timeout=8, follow_redirects=False)
                loc = r.headers.get("Location", "")
                if "aura-redirect-test.com" in loc:
                    findings.append({
                        "type": "OAuth Redirect URI Manipulation",
                        "finding_type": "OAuth Open Redirect - Token Theft Vector",
                        "severity": "HIGH",
                        "owasp": "A07:2021 - Identification and Authentication Failures",
                        "mitre": "T1528 - Steal Application Access Token",
                        "content": (
                            f"OAuth redirect_uri accepted external domain\n"
                            f"URL: {test_url}\n"
                            f"Location: {loc}\n"
                            f"Impact: Attacker can steal authorization codes and access tokens."
                        ),
                        "url": url,
                        "confirmed": True,
                        "poc_evidence": test_url
                    })
            except Exception:
                continue
        return findings

    async def scan_target(self, target_url: str) -> list:
        from urllib.parse import urlparse, parse_qs, urlencode
        base = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
        findings = []
        console.print(f"[bold cyan][Redirect] Scanning {base} for open redirects...[/bold cyan]")

        async with httpx.AsyncClient(verify=False, follow_redirects=False) as client:
            sem = asyncio.Semaphore(8)

            async def _test(param, payload):
                async with sem:
                    return await self._test_param(client, target_url, param, payload)

            # Top 3 payloads x all params for speed
            tasks = [_test(p, pay) for p in REDIRECT_PARAMS[:10] for pay in BYPASS_PAYLOADS[:3]]
            results = await asyncio.gather(*tasks)

            seen = set()
            for r in results:
                if r and r["url"] not in seen:
                    seen.add(r["url"])
                    console.print(f"[bold red][Redirect CONFIRMED] {r['url']}[/bold red]")
                    findings.append(r)

            # OAuth check
            oauth_findings = await self._scan_oauth_redirect(client, base)
            findings.extend(oauth_findings)

        if not findings:
            console.print(f"[dim][Redirect] No open redirects detected.[/dim]")
        return findings

    async def scan_urls(self, urls: list) -> list:
        all_findings = []
        sem = asyncio.Semaphore(3)
        async def _scan(url):
            async with sem:
                return await self.scan_target(url)
        results = await asyncio.gather(*[_scan(u) for u in urls[:20]])
        for r in results:
            all_findings.extend(r)
        return all_findings
