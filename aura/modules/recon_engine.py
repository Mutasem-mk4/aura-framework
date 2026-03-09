"""
Aura v2 — Recon & JS Secret Scraper Engine
============================================
Unlocks hidden attack surfaces by performing:
  1. Passive Subdomain Discovery (crt.sh + OSINT APIs)
  2. Recursive JS Secret Scrapping (API keys, endpoints, credentials)
  3. Cloud Bucket Discovery (S3, Azure, GCP)
  4. Lightweight Port Scanning

Usage:
    aura www.target.com --recon
"""

import asyncio
import json
import os
import re
import socket
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Optional, Set

import httpx
import urllib3
urllib3.disable_warnings()

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

console = Console()

# ─── JS Secret Regex Patterns ───────────────────────────────────────────────
# Curated list of high-value secrets
SECRET_PATTERNS = {
    "AWS Access Key":     r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "Google API Key":     r"AIza[0-9A-Za-z\\-_]{35}",
    "Firebase API Key":   r"AIza[0-9A-Za-z\\-_]{35}",
    "Stripe API Key":      r"(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24}",
    "Slack Token":        r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "Generic API Key":    r"(?:api_key|apikey|secret|token|password|auth|creds)[\"']?\s?[:=]\s?[\"']?([0-9a-zA-Z\\-_]{16,64})[\"']?",
    "Mailgun API Key":    r"key-[0-9a-zA-Z]{32}",
    "GitHub Token":       r"gh[oprs]_[a-zA-Z0-9]{36,40}",
    "Internal Endpoint":  r"(?:https?://)?(?:[a-zA-Z0-9-]+\.)*(?:staging|dev|test|internal|qa|api-test|beta|admin)\.[a-zA-Z0-9-]+\.[a-z]{2,}",
    "S3 Bucket URL":       r"([a-z0-9.-]+\.s3\.amazonaws\.com|[a-z0-9.-]+\.s3-[a-z0-9-]+\.amazonaws\.com)",
    "Azure Blob":         r"([a-z0-9.-]+\.blob\.core\.windows\.net)",
    "Google Storage":     r"([a-z0-9.-]+\.storage\.googleapis\.com)",
}

# ─── Ports to Scan ───────────────────────────────────────────────────────────
COMMON_PORTS = [80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9000, 9090, 21, 22, 25, 53, 111, 445, 3306, 5432, 6379, 27017]


class ReconEngine:
    """
    Automated reconnaissance and secret scraping engine.
    """

    def __init__(
        self,
        target: str,
        output_dir: str = "./reports",
        timeout: int = 15,
    ):
        if not target.startswith("http"):
            target = "https://" + target
        self.target = target.rstrip("/")
        self.target_url_parsed = urllib.parse.urlparse(self.target)
        self.target_domain = self.target_url_parsed.netloc
        self.base_domain = self.target_domain.replace("www.", "")
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        
        self.subdomains: Set[str] = {self.target_domain}
        self.js_files: Set[str] = set()
        self.secrets: list[dict] = []
        self.open_ports: list[int] = []
        self.cloud_buckets: Set[str] = set()

    # ─────────────────────────────────────────────────────────────────────────
    # MODULE 1: Subdomain Discovery
    # ─────────────────────────────────────────────────────────────────────────

    async def _fetch_crt_sh(self):
        """Passive subdomain discovery via crt.sh (Certificate Transparency logs)."""
        console.print(f"  [cyan]🔍 Fetching crt.sh logs for {self.base_domain}...[/cyan]")
        url = f"https://crt.sh/?q=%25.{self.base_domain}&output=json"
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data:
                        # crt.sh returns newline-separated domains in 'common_name' and 'name_value'
                        for key in ['common_name', 'name_value']:
                            val = item.get(key, "")
                            for sub in val.split("\n"):
                                sub = sub.strip().lower()
                                if sub and "*" not in sub:
                                    self.subdomains.add(sub)
        except Exception as e:
            console.print(f"  [dim]crt.sh lookup failed: {e}[/dim]")

    # ─────────────────────────────────────────────────────────────────────────
    # MODULE 2: JS Secret Scraper
    # ─────────────────────────────────────────────────────────────────────────

    async def _fetch_js_files(self):
        """Finds and fetches all .js files from the homepage."""
        console.print(f"  [cyan]🕷️ Finding JavaScript files on {self.target}...[/cyan]")
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, verify=False) as client:
                resp = await client.get(self.target)
                if resp.status_code != 200:
                    return

                # Simple regex-based script tag extraction
                # (Alternative: use BeautifulSoup but we want fewer dependencies)
                found = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', resp.text)
                for src in found:
                    full_url = urllib.parse.urljoin(self.target, src)
                    if self.base_domain in full_url:
                        self.js_files.add(full_url)
        except Exception as e:
            console.print(f"  [dim]JS discovery failed: {e}[/dim]")

    async def _scan_js_file(self, url: str):
        """Downloads a JS file and scans for secrets."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, verify=False) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    return

                content = resp.text
                for name, pattern in SECRET_PATTERNS.items():
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        # match might be a tuple if group is used
                        match_val = match[0] if isinstance(match, tuple) else match
                        
                        # Avoid duplicates
                        if not any(s['value'] == match_val for s in self.secrets):
                            self.secrets.append({
                                "type": name,
                                "value": match_val,
                                "source": url,
                                "severity": "HIGH" if "Key" in name or "Secret" in name else "MEDIUM"
                            })
                            # If it's a domain, add to subdomains
                            if name in ["Internal Endpoint", "S3 Bucket URL", "Azure Blob", "Google Storage"]:
                                self.cloud_buckets.add(match_val)
                                if self.base_domain in match_val:
                                    self.subdomains.add(match_val)
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    # MODULE 3: Cloud Bucket Discovery (Brute Probe)
    # ─────────────────────────────────────────────────────────────────────────

    async def _probe_buckets(self):
        """Probes for common bucket names based on the target domain."""
        console.print(f"  [cyan]🪣 Probing common cloud bucket names...[/cyan]")
        prefixes = [self.base_domain.replace(".", "-"), self.base_domain.split(".")[0]]
        suffixes = ["assets", "images", "dev", "prod", "backup", "data", "files", "internal"]
        
        candidates = []
        for p in prefixes:
            for s in suffixes:
                candidates.append(f"{p}-{s}.s3.amazonaws.com")
                candidates.append(f"{p}-{s}.blob.core.windows.net")
                candidates.append(f"{p}-{s}.storage.googleapis.com")

        async with httpx.AsyncClient(timeout=5, verify=False) as client:
            for url in candidates:
                try:
                    # no-cors/head request
                    full_url = "https://" + url
                    resp = await client.head(full_url)
                    # 200 or 403 (exists but private) are interesting. 404 means doesn't exist.
                    if resp.status_code in [200, 403]:
                        self.cloud_buckets.add(url)
                except Exception:
                    pass

    # ─────────────────────────────────────────────────────────────────────────
    # MODULE 4: Port Scanner
    # ─────────────────────────────────────────────────────────────────────────

    async def _check_port(self, port: int):
        """Asynchronously checks if a TCP port is open."""
        loop = asyncio.get_event_loop()
        try:
            # socket.create_connection is blocking, use loop.run_in_executor
            await loop.run_in_executor(None, lambda: socket.create_connection((self.target_domain, port), timeout=2))
            self.open_ports.append(port)
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    # CORE ENGINE EXECUTION
    # ─────────────────────────────────────────────────────────────────────────

    async def run(self):
        """Runs the full recon process."""
        console.print(Panel(
            f"[bold white]🕵️ AURA v2 — Recon Engine[/bold white]\n"
            f"Target: [cyan]{self.target}[/cyan]",
            style="bright_blue",
        ))

        tasks = [
            self._fetch_crt_sh(),
            self._fetch_js_files(),
            self._probe_buckets(),
        ]
        
        # Run initial discovery
        await asyncio.gather(*tasks)

        # Scan JS files for secrets
        if self.js_files:
            console.print(f"  [cyan]💉 Scanning {len(self.js_files)} JS files for secrets...[/cyan]")
            js_tasks = [self._scan_js_file(js) for js in self.js_files]
            await asyncio.gather(*js_tasks)

        # Port scanning
        console.print(f"  [cyan]📡 Scanning standard ports...[/cyan]")
        port_tasks = [self._check_port(p) for p in COMMON_PORTS]
        await asyncio.gather(*port_tasks)

        return self._finalize()

    def _finalize(self):
        """Prints findings and saves to JSON."""
        # 1. Subdomains Table
        if self.subdomains:
            table = Table(title="Discoverd Subdomains", title_style="bold green", box=box.ROUNDED)
            table.add_column("Domain", style="cyan")
            for sub in sorted(list(self.subdomains))[:15]: # Show top 15
                table.add_row(sub)
            if len(self.subdomains) > 15:
                table.add_row(f"... and {len(self.subdomains)-15} more")
            console.print(table)

        # 2. Open Ports
        if self.open_ports:
            console.print(f"  [bold yellow]📡 Open Ports:[/bold yellow] [green]{', '.join(map(str, sorted(self.open_ports)))}[/green]")

        # 3. Secrets Table
        if self.secrets:
            table = Table(title="🔥 Exposed Secrets & Endpoints", title_style="bold red", box=box.HEAVY_EDGE)
            table.add_column("Type", style="red")
            table.add_column("Value", style="yellow")
            table.add_column("Source", style="dim")
            for s in self.secrets:
                table.add_row(s['type'], f"{s['value'][:40]}...", s['source'].split("/")[-1])
            console.print(table)

        # 4. Cloud Buckets
        if self.cloud_buckets:
            console.print(f"\n  [bold cyan]🪣  Discovered Cloud Assets:[/bold cyan]")
            for b in self.cloud_buckets:
                console.print(f"    - {b}")

        # Save to file
        report = {
            "target": self.target,
            "timestamp": datetime.utcnow().isoformat(),
            "subdomains": list(self.subdomains),
            "js_files": list(self.js_files),
            "secrets": self.secrets,
            "open_ports": sorted(self.open_ports),
            "cloud_buckets": list(self.cloud_buckets)
        }
        
        target_slug = self.target_domain.replace(".", "_")
        out_path = self.output_dir / f"recon_{target_slug}.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        
        console.print(f"\n  [bold green]💾 Full Recon Report saved:[/bold green] [cyan]{out_path}[/cyan]")
        return report


def run_recon(target: str):
    """Entry point for CLI."""
    engine = ReconEngine(target)
    return asyncio.run(engine.run())


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "www.iciparisxl.nl"
    run_recon(target)
