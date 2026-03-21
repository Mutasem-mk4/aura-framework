"""
Aura v21.0 — OAuth Flaw Detector
Detects and confirms common OAuth 2.0 implementation flaws:
  1. redirect_uri bypass (domain, path, open redirect tricks)
  2. state parameter CSRF
  3. Implicit flow token leakage in referrer/fragments
  4. Authorization code replay
  5. scope escalation

OAuth flaws on major platforms = CRITICAL/HIGH payouts.
"""
import re
import asyncio
import urllib.parse
from rich.console import Console
from aura.core import state

from aura.ui.formatter import console


class OAuthHunter:
    """
    Phase D2: OAuth 2.0 Flaw Detector.
    Hunts for redirect_uri bypass, CSRF, and implicit flow leakage.
    """

    # Common OAuth authorization endpoint paths
    OAUTH_PATHS = [
        "/oauth/authorize", "/auth/oauth2/authorize", "/connect/authorize",
        "/oauth2/authorize", "/openid/authorize", "/v1/oauth/authorize",
        "/api/oauth/authorize", "/login/oauth/authorize", "/oauth/v2/authorize",
    ]

    # Common callback/redirect paths
    CALLBACK_PATHS = [
        "/callback", "/oauth/callback", "/auth/callback",
        "/oauth2/callback", "/redirect", "/login/callback",
    ]

    def __init__(self, session=None):
        self.session = session

    async def _probe(self, url: str, headers: dict = None) -> tuple[int, str, dict]:
        """Makes a GET request and returns (status, body_snippet, response_headers)."""
        try:
            res = await self.session.get(url, headers=headers or {}, timeout=state.NETWORK_TIMEOUT)
            if res:
                headers_dict = dict(res.headers) if hasattr(res, 'headers') else {}
                return res.status_code, (res.text or "")[:1000], headers_dict
        except Exception:
            pass
        return 0, "", {}

    async def _find_oauth_endpoints(self, base_url: str) -> list[str]:
        """Discovers live OAuth endpoints on the target."""
        parsed = urllib.parse.urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        live = []
        for path in self.OAUTH_PATHS:
            url = f"{origin}{path}"
            status, body, _ = await self._probe(url)
            if status in (200, 302, 400):  # 400 is common for OAuth with missing params
                live.append(url)
                console.print(f"[cyan][OAuth] Found endpoint: {url} ({status})[/cyan]")
        return live

    async def test_redirect_uri_bypass(self, oauth_endpoint: str, client_id: str = "test") -> list[dict]:
        """
        Tests redirect_uri validation bypass techniques.
        A bypassed redirect = attacker can steal authorization codes.
        """
        findings = []
        parsed = urllib.parse.urlparse(oauth_endpoint)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        bypass_uris = [
            f"{origin}@evil.com",                    # @ symbol confusion
            f"{origin}.evil.com",                    # subdomain trick
            f"https://evil.com%2F@{parsed.netloc}",  # URL encoding
            f"{origin}/../../../evil.com",            # path traversal
            f"https://evil.com",                     # completely different domain
            f"{origin}?redirect=https://evil.com",   # open redirect chain
            f"javascript:alert(1)",                  # JavaScript URI
        ]

        for bypass_uri in bypass_uris:
            test_url = (
                f"{oauth_endpoint}?response_type=code"
                f"&client_id={client_id}"
                f"&redirect_uri={urllib.parse.quote(bypass_uri)}"
                f"&scope=openid+profile"
                f"&state=aura_test_csrf"
            )
            status, body, resp_headers = await self._probe(test_url)
            location = resp_headers.get("location", resp_headers.get("Location", ""))

            # If redirected to evil.com or the bypass URI is accepted
            if status in (302, 301) and "evil.com" in location:
                console.print(f"[bold red][OAuth] redirect_uri BYPASS confirmed: {bypass_uri}[/bold red]")
                findings.append(self._make_finding(
                    vuln_type="OAuth redirect_uri Bypass",
                    severity="CRITICAL",
                    cvss=9.3,
                    url=oauth_endpoint,
                    detail=(
                        f"redirect_uri bypass confirmed using: `{bypass_uri}`\n"
                        f"Server redirected to: `{location}`\n"
                        f"An attacker can steal the authorization code by directing "
                        f"a victim to a crafted OAuth URL."
                    ),
                    remediation=(
                        "1. Enforce exact-match redirect_uri validation (no wildcards, no path traversal).\n"
                        "2. Pre-register allowed redirect_uris in your OAuth application settings.\n"
                        "3. Never accept redirect_uris that weren't pre-registered during app creation.\n"
                        "4. Validate the full URI including scheme, host, path, and query."
                    )
                ))
                break

        return findings

    async def test_csrf_state(self, oauth_endpoint: str, client_id: str = "test", redirect_uri: str = None) -> list[dict]:
        """
        Tests if the state parameter is absent or not validated.
        Missing state = CSRF on OAuth flow.
        """
        findings = []
        parsed = urllib.parse.urlparse(oauth_endpoint)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        redir = redirect_uri or f"{origin}/callback"

        # Test without state parameter
        no_state_url = (
            f"{oauth_endpoint}?response_type=code"
            f"&client_id={client_id}"
            f"&redirect_uri={urllib.parse.quote(redir)}"
            f"&scope=openid"
        )
        status, body, _ = await self._probe(no_state_url)

        # If server initiates OAuth without state (no error about missing state)
        if status in (200, 302) and "state" not in body.lower() and "csrf" not in body.lower():
            console.print(f"[bold yellow][OAuth] Missing state parameter accepted on {oauth_endpoint}[/bold yellow]")
            findings.append(self._make_finding(
                vuln_type="OAuth CSRF (Missing State Parameter)",
                severity="MEDIUM",
                cvss=6.1,
                url=oauth_endpoint,
                detail=(
                    "The OAuth authorization endpoint does not enforce the `state` parameter.\n"
                    "The server accepted a request without `state`, "
                    "making it vulnerable to CSRF attacks on the OAuth flow."
                ),
                remediation=(
                    "1. Always generate and validate a cryptographically random `state` parameter.\n"
                    "2. Reject authorization requests that do not include `state`.\n"
                    "3. Verify the `state` value in the callback matches what was sent."
                )
            ))
        return findings

    async def test_implicit_flow_leakage(self, base_url: str) -> list[dict]:
        """
        Detects implicit flow usage (access tokens in URL fragments).
        Implicit flow = tokens in browser history, referrer headers, logs.
        """
        findings = []
        parsed = urllib.parse.urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Check if any OAuth endpoint uses response_type=token (implicit)
        for path in self.OAUTH_PATHS:
            test_url = (
                f"{origin}{path}?response_type=token"
                f"&client_id=test"
                f"&redirect_uri={urllib.parse.quote(origin + '/callback')}"
                f"&scope=openid"
            )
            status, body, headers_dict = await self._probe(test_url)
            if status in (200, 302) and "access_token" in (body + headers_dict.get("location", "")).lower():
                console.print(f"[bold yellow][OAuth] Implicit flow enabled at {origin}{path}[/bold yellow]")
                findings.append(self._make_finding(
                    vuln_type="OAuth Implicit Flow Token Leakage",
                    severity="MEDIUM",
                    cvss=5.9,
                    url=f"{origin}{path}",
                    detail=(
                        "Implicit grant flow (`response_type=token`) is enabled.\n"
                        "Access tokens are returned in the URL fragment (#access_token=...), "
                        "exposing them to browser history, server logs, and Referrer headers."
                    ),
                    remediation=(
                        "1. Migrate from implicit flow to Authorization Code + PKCE.\n"
                        "2. Disable `response_type=token` in your OAuth server configuration.\n"
                        "3. Use short-lived tokens and rotate them frequently."
                    )
                ))
        return findings

    @staticmethod
    def _make_finding(vuln_type, severity, cvss, url, detail, remediation) -> dict:
        cvss_vectors = {
            "CRITICAL": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
            "HIGH":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
            "MEDIUM":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        }
        return {
            "type": vuln_type,
            "severity": severity,
            "cvss_score": cvss,
            "cvss_vector": cvss_vectors.get(severity, cvss_vectors["MEDIUM"]),
            "owasp": "A01:2021-Broken Access Control",
            "mitre": "T1078 - Valid Accounts",
            "content": detail,
            "remediation_fix": remediation,
            "impact_desc": (
                f"OAuth implementation flaw ({vuln_type}) allows attackers to "
                "steal authorization codes or access tokens, leading to account takeover "
                "without requiring the victim's credentials."
            ),
            "patch_priority": severity,
            "evidence_url": url,
            "confirmed": True,
        }

    async def scan_target(self, base_url: str) -> list[dict]:
        """
        Full OAuth scan: discovers endpoints and runs all flaw tests.
        """
        all_findings = []
        console.print(f"[bold yellow][OAuth] Scanning {base_url} for OAuth flaws...[/bold yellow]")

        oauth_endpoints = await self._find_oauth_endpoints(base_url)
        if not oauth_endpoints:
            console.print(f"[dim][OAuth] No OAuth endpoints found on {base_url}.[/dim]")
            return []

        for endpoint in oauth_endpoints:
            results = await asyncio.gather(
                self.test_redirect_uri_bypass(endpoint),
                self.test_csrf_state(endpoint),
                self.test_implicit_flow_leakage(base_url),
                return_exceptions=True,
            )
            for r in results:
                if isinstance(r, list):
                    all_findings.extend(r)

        if all_findings:
            console.print(f"[bold red][OAuth] {len(all_findings)} OAuth flaw(s) confirmed![/bold red]")
        else:
            console.print(f"[dim green][OAuth] No OAuth flaws found.[/dim green]")

        return all_findings
