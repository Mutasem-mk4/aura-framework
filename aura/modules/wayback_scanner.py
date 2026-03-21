"""
Aura v20.0 — Wayback Machine JS Scanner (Phase 4)
Fetches all historical JavaScript files for a target domain from
the Wayback Machine CDX API, then runs SecretHunter on each.

Companies patch secrets in live code, but archives keep them forever.
This module finds secrets that were exposed in the past and may be
STILL VALID (companies often forget to rotate after removing from code).
"""
import asyncio
import json
import re
from rich.console import Console
from aura.core import state

from aura.ui.formatter import console

# Max historical JS files to scan per target (prevent excessive runtime)
MAX_WAYBACK_FILES = 50


class WaybackScanner:
    """
    Phase 4: Historical JavaScript Secret Hunter.
    Integrates with the Wayback Machine CDX API to find past secret exposures.
    """

    CDX_API = "https://web.archive.org/cdx/search/cdx"
    WAYBACK_PREFIX = "https://web.archive.org/web/"

    def __init__(self, session=None):
        self.session = session

    async def _fetch_cdx(self, domain: str) -> list[str]:
        """
        Queries CDX API for all historical JS/config files for the domain.
        Returns a list of (timestamp, original_url) pairs for Wayback fetching.
        """
        js_urls = []
        try:
            params = (
                f"url={domain}/*.js"
                f"&output=json"
                f"&fl=timestamp,original"
                f"&collapse=urlkey"
                f"&filter=statuscode:200"
                f"&limit={MAX_WAYBACK_FILES}"
            )
            url = f"{self.CDX_API}?{params}"
            console.print(f"[cyan][Wayback] Querying CDX for {domain} JS history...[/cyan]")

            import httpx
            async with httpx.AsyncClient(timeout=20) as client:
                r = await client.get(url)
                if r.status_code == 200 and r.text.strip():
                    rows = json.loads(r.text)
                    # First row is header ["timestamp", "original"]
                    for row in rows[1:]:
                        timestamp, original = row[0], row[1]
                        wayback_url = f"{self.WAYBACK_PREFIX}{timestamp}/{original}"
                        js_urls.append((original, wayback_url))
                    console.print(f"[cyan][Wayback] Found {len(js_urls)} historical JS files for {domain}.[/cyan]")
        except Exception as e:
            console.print(f"[dim red][Wayback] CDX query failed: {e}[/dim red]")

        return js_urls

    async def _fetch_archived_content(self, wayback_url: str) -> str | None:
        """Fetches the archived version of a JS file from Wayback Machine."""
        try:
            import httpx
            async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
                r = await client.get(wayback_url)
                if r.status_code == 200:
                    return r.text
        except Exception:
            pass
        return None

    async def scan_target(self, domain: str, live_urls: list[str] = None) -> list[dict]:
        """
        Main entry: scans all historical JS files for the domain.
        Skips files whose URLs are in the live_urls list (already scanned by main engine).
        Returns a list of findings (same format as SecretHunter).
        """
        # Import here to avoid circular dependency
        from aura.modules.secret_hunter import SecretHunter

        all_findings = []
        live_url_set = set(live_urls or [])

        historical_files = await self._fetch_cdx(domain)
        if not historical_files:
            console.print("[dim][Wayback] No historical JS files found.[/dim]")
            return []

        # Filter out files that are currently live (already scanned)
        new_files = [(orig, wb) for orig, wb in historical_files if orig not in live_url_set]
        console.print(
            f"[cyan][Wayback] Scanning {len(new_files)} archived files "
            f"({len(historical_files) - len(new_files)} skipped as still-live)...[/cyan]"
        )

        hunter = SecretHunter(session=self.session)

        for original_url, wayback_url in new_files:
            content = await self._fetch_archived_content(wayback_url)
            if not content:
                continue
            findings = await hunter._scan_content(content, original_url, is_html=False)
            if findings:
                # Tag findings as historical
                for f in findings:
                    f["type"] = f"[HISTORICAL] {f['type']}"
                    f["content"] = (
                        f"[HISTORICAL EXPOSURE - May Still Be Valid]\n"
                        f"Found in archived Wayback Machine snapshot: {wayback_url}\n"
                        f"Original URL: {original_url}\n\n"
                        f"{f['content']}"
                    )
                all_findings.extend(findings)
                console.print(f"[bold red]  [Wayback] {len(findings)} secret(s) in archived {original_url}[/bold red]")

        if all_findings:
            console.print(
                f"[bold red][Wayback] DONE: {len(all_findings)} historical secret(s) found! "
                f"These may STILL BE VALID if never rotated.[/bold red]"
            )
        else:
            console.print("[dim green][Wayback] No historical secrets found.[/dim green]")

        return all_findings
