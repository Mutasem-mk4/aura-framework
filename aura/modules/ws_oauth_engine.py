# -*- coding: utf-8 -*-
"""
Aura v31.0 - WebSocket + OAuth Attacker (Phase 28)
===================================================
WebSocket Security:
- Origin validation bypass
- Message injection (XSS/SQLi in WS messages)
- Auth token in WS handshake

OAuth Deep Attacks:
- State parameter bypass (CSRF)
- Authorization code reuse
- Token in Referer header leakage
- Implicit flow token exposure
"""
import asyncio
import re
import httpx
from rich.console import Console

console = Console()

WS_PATHS = ["/ws", "/websocket", "/socket", "/api/ws", "/chat", "/live", "/stream"]
OAUTH_PATHS = [
    "/oauth/authorize", "/auth/authorize", "/oauth2/authorize",
    "/connect/authorize", "/api/oauth/authorize", "/sso/authorize",
]


class WSAndOAuthEngine:
    """v31.0: WebSocket + OAuth Deep Attack Engine."""

    def __init__(self, session=None):
        self.session = session

    # ── WebSocket Tests ────────────────────────────────────────────────────
    async def _test_ws_origin(self, base_url: str) -> dict | None:
        """Tests if WebSocket allows connections from arbitrary origins."""
        try:
            import websockets
            for path in WS_PATHS:
                ws_url = base_url.replace("http", "ws") + path
                try:
                    async with websockets.connect(
                        ws_url,
                        extra_headers={"Origin": "https://evil.aura-attacker.com"},
                        open_timeout=5, close_timeout=3
                    ) as ws:
                        return {
                            "type": "WebSocket Origin Validation Missing",
                            "finding_type": "WebSocket Cross-Origin Vulnerability",
                            "severity": "HIGH",
                            "owasp": "A07:2021 - Identification and Authentication Failures",
                            "mitre": "T1602",
                            "content": (
                                f"WebSocket accepts connection from arbitrary origin\n"
                                f"URL: {ws_url}\n"
                                f"Origin: https://evil.aura-attacker.com\n"
                                f"Impact: Cross-site WebSocket hijacking (CSWSH) possible."
                            ),
                            "url": ws_url,
                            "confirmed": True,
                            "poc_evidence": f"WS connected with Origin: evil.aura-attacker.com"
                        }
                except Exception:
                    continue
        except ImportError:
            pass
        return None

    # ── OAuth Tests ────────────────────────────────────────────────────────
    async def _test_state_bypass(self, client, base_url: str) -> dict | None:
        """Tests if OAuth state parameter is validated."""
        for path in OAUTH_PATHS:
            url = f"{base_url}{path}?response_type=code&client_id=test&state=AURA_CSRF_TEST_31&redirect_uri={base_url}/callback"
            try:
                r = await client.get(url, timeout=8, follow_redirects=False)
                loc = r.headers.get("Location", "")
                # If state was accepted without validation, it will be echoed back
                if "AURA_CSRF_TEST_31" in loc:
                    return {
                        "type": "OAuth State Parameter CSRF",
                        "finding_type": "OAuth CSRF (Missing State Validation)",
                        "severity": "HIGH",
                        "owasp": "A07:2021 - Identification and Authentication Failures",
                        "mitre": "T1528",
                        "content": (
                            f"OAuth state parameter accepted without CSRF validation\n"
                            f"URL: {url}\n"
                            f"Impact: CSRF attack can force account linking or token issuance."
                        ),
                        "url": url,
                        "confirmed": True,
                        "poc_evidence": f"GET {url} - state echoed back in redirect"
                    }
            except Exception:
                continue
        return None

    async def _test_code_reuse(self, client, base_url: str) -> dict | None:
        """Checks if auth code endpoint accepts duplicate codes."""
        token_paths = ["/oauth/token", "/auth/token", "/api/oauth/token", "/token"]
        for path in token_paths:
            url = f"{base_url}{path}"
            # Send same code twice
            payload = {
                "grant_type": "authorization_code",
                "code": "AURA_TEST_CODE_31",
                "client_id": "test",
                "redirect_uri": f"{base_url}/callback"
            }
            try:
                r1 = await client.post(url, data=payload, timeout=8)
                r2 = await client.post(url, data=payload, timeout=8)
                # If second request doesn't return "code already used" error
                if r2.status_code == 200 and "error" not in r2.text.lower():
                    return {
                        "type": "OAuth Authorization Code Reuse",
                        "finding_type": "OAuth Code Reuse",
                        "severity": "HIGH",
                        "owasp": "A07:2021 - Identification and Authentication Failures",
                        "mitre": "T1528",
                        "content": (
                            f"OAuth token endpoint may accept reused auth codes\n"
                            f"URL: {url}\n"
                            f"Impact: Stolen authorization codes can be reused for token generation."
                        ),
                        "url": url,
                        "confirmed": False,
                        "poc_evidence": "Double submission returned 200 OK without error"
                    }
            except Exception:
                continue
        return None

    async def _test_token_leakage(self, client, base_url: str) -> dict | None:
        """Checks implicit flow for token in URL fragment."""
        for path in OAUTH_PATHS:
            url = f"{base_url}{path}?response_type=token&client_id=test&redirect_uri={base_url}/callback"
            try:
                r = await client.get(url, timeout=8, follow_redirects=False)
                loc = r.headers.get("Location", "")
                if "access_token=" in loc and "#" in loc:
                    return {
                        "type": "OAuth Implicit Flow Token in URL",
                        "finding_type": "OAuth Token Exposure in URL Fragment",
                        "severity": "HIGH",
                        "owasp": "A07:2021 - Identification and Authentication Failures",
                        "mitre": "T1528",
                        "content": (
                            f"OAuth implicit flow exposes access_token in URL fragment\n"
                            f"URL: {url}\n"
                            f"Location: {loc[:200]}\n"
                            f"Impact: Token visible in browser history and server logs."
                        ),
                        "url": url,
                        "confirmed": True,
                        "poc_evidence": f"Location: {loc[:100]}"
                    }
            except Exception:
                continue
        return None

    async def scan_target(self, target_url: str) -> list:
        from urllib.parse import urlparse
        base = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
        findings = []
        console.print(f"[bold cyan][WS+OAuth] Scanning {base}...[/bold cyan]")

        async with httpx.AsyncClient(verify=False, follow_redirects=False) as client:
            results = await asyncio.gather(
                self._test_ws_origin(base),
                self._test_state_bypass(client, base),
                self._test_code_reuse(client, base),
                self._test_token_leakage(client, base),
                return_exceptions=True
            )
            for r in results:
                if r and not isinstance(r, Exception):
                    console.print(f"[bold red][WS+OAuth] {r['type']}![/bold red]")
                    findings.append(r)

        if not findings:
            console.print(f"[dim][WS+OAuth] No issues detected.[/dim]")
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
                console.print(f"[dim red][WS+OAuth] Skipped {url}: {e}[/dim red]")
        return all_findings
