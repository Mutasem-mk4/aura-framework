# -*- coding: utf-8 -*-
"""
Aura v31.0 - Host Header Injection Engine (Phase 24)
======================================================
Detects Host Header Injection vulnerabilities:
- Password Reset Poisoning -> attacker-controlled reset links
- X-Forwarded-Host injection -> redirect manipulation
- Absolute URL generation attacks
"""
import asyncio
import httpx
import re
from rich.console import Console

console = Console()

POISON_HOST = "aura-poison-test.com"

RESET_PATHS = [
    "/forgot-password", "/reset-password", "/auth/forgot",
    "/api/forgot-password", "/account/reset", "/password/reset",
    "/api/password/reset", "/user/forgot-password",
]

INJECT_HEADERS = [
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-HTTP-Host-Override",
    "Forwarded",
]


class HostHeaderEngine:
    """v31.0: Host Header Injection scanner."""

    def __init__(self, session=None):
        self.session = session

    async def _probe_reset_poison(self, client, url: str, host: str) -> dict | None:
        """Sends a password reset request with a poisoned Host header."""
        for inject_header in INJECT_HEADERS:
            try:
                r = await client.post(
                    url,
                    json={"email": "test@example.com"},
                    headers={inject_header: POISON_HOST},
                    timeout=10
                )
                body = r.text
                # Check if our canary appears in response (bad sign — token link contains it)
                if POISON_HOST in body:
                    return {
                        "type": "Host Header Injection - Reset Poisoning",
                        "finding_type": "Host Header Injection (Password Reset Poisoning)",
                        "severity": "HIGH",
                        "owasp": "A05:2021 - Security Misconfiguration",
                        "mitre": "T1556 - Modify Authentication Process",
                        "content": (
                            f"Password reset link poisoned via `{inject_header}` header\n"
                            f"URL: {url}\n"
                            f"Injected Host: {POISON_HOST}\n"
                            f"Canary found in response: YES\n"
                            f"Impact: Reset email will contain link pointing to attacker domain -> Account Takeover."
                        ),
                        "url": url,
                        "confirmed": True,
                        "poc_evidence": f"POST {url} with {inject_header}: {POISON_HOST}"
                    }
                # Check if response reflects host in Location or Link headers
                loc = r.headers.get("Location", "") + r.headers.get("Link", "")
                if POISON_HOST in loc:
                    return {
                        "type": "Host Header Injection - Redirect Poisoning",
                        "finding_type": "Host Header Injection",
                        "severity": "HIGH",
                        "owasp": "A05:2021 - Security Misconfiguration",
                        "mitre": "T1566",
                        "content": (
                            f"Host header reflected in redirect via `{inject_header}`\n"
                            f"URL: {url} | Location: {loc[:200]}"
                        ),
                        "url": url,
                        "confirmed": True,
                        "poc_evidence": f"Header: {inject_header}: {POISON_HOST} -> Location: {loc[:100]}"
                    }
            except Exception:
                continue
        return None

    async def _probe_generic(self, client, url: str) -> dict | None:
        """Tests if Host header is reflected in general responses."""
        try:
            r = await client.get(
                url,
                headers={"Host": POISON_HOST},
                timeout=8
            )
            if POISON_HOST in r.text:
                return {
                    "type": "Host Header Reflected in Response",
                    "finding_type": "Host Header Injection",
                    "severity": "MEDIUM",
                    "owasp": "A05:2021 - Security Misconfiguration",
                    "mitre": "T1566",
                    "content": (
                        f"Host header value reflected in response body\n"
                        f"URL: {url}\n"
                        f"Injected: Host: {POISON_HOST}\n"
                        f"Impact: May enable cache poisoning or phishing via crafted emails."
                    ),
                    "url": url,
                    "confirmed": True,
                    "poc_evidence": f"GET {url} Host: {POISON_HOST} -> body contains {POISON_HOST}"
                }
        except Exception:
            pass
        return None

    async def scan_target(self, target_url: str) -> list:
        from urllib.parse import urlparse
        base = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
        findings = []
        console.print(f"[bold cyan][Email Host Header] Testing {base} for host injection...[/bold cyan]")

        async with httpx.AsyncClient(verify=False, follow_redirects=False) as client:
            # Test reset endpoints
            sem = asyncio.Semaphore(5)
            async def _test_reset(path):
                async with sem:
                    url = f"{base}{path}"
                    return await self._probe_reset_poison(client, url, POISON_HOST)

            results = await asyncio.gather(*[_test_reset(p) for p in RESET_PATHS])
            for r in results:
                if r:
                    console.print(f"[bold red][Host Inject] {r['type']} on {r['url']}[/bold red]")
                    findings.append(r)

            # Generic reflection test on main URL
            gen = await self._probe_generic(client, target_url)
            if gen:
                console.print(f"[bold yellow][Host Inject] {gen['type']}[/bold yellow]")
                findings.append(gen)

        if not findings:
            console.print(f"[dim][Host Header] No injection detected.[/dim]")
        return findings

    async def scan_urls(self, urls: list) -> list:
        all_findings = []
        seen = set()
        for url in urls:
            from urllib.parse import urlparse
            base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            if base in seen:
                continue
            seen.add(base)
            try:
                results = await self.scan_target(url)
                all_findings.extend(results)
            except Exception as e:
                console.print(f"[dim red][Host Header] Skipped {url}: {e}[/dim red]")
        return all_findings
