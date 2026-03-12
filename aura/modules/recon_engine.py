"""
Aura v3 Omni — Recon & JS Secret Scraper Engine (Hyper-Speed Async)
===================================================================
Unlocks hidden attack surfaces by performing:
  1. Passive Subdomain Discovery (crt.sh + OSINT APIs)
  2. Recursive JS Secret Scrapping (API keys, endpoints, credentials)
  3. Cloud Bucket Discovery (Batched probing of S3, Azure, GCP)
  4. Lightweight Port Scanning
  5. Subdomain Takeover Detector

Now powered by AsyncRequester for lightning fast recon.
"""

import asyncio
import json
import os
import re
import socket
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Optional, Set, List

from aura.core.async_requester import AsyncRequester

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

console = Console()

# ─── JS Secret Regex Patterns ───────────────────────────────────────────────
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

# ─── JS Secret Blacklist (Noise Reduction) ──────────────────────────────────
SECRET_BLACKLIST = [
    "amplitude", "google-analytics", "ga_", "utm_", "device_id", 
    "session_id", "client_id", "fbp", "_fbc", "hotjar", "hubspot", 
    "mixpanel", "segment", "traceparent", "persona", "fingerprint"
]

# ─── Ports to Scan ───────────────────────────────────────────────────────────
COMMON_PORTS = [80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9000, 9090, 21, 22, 25, 53, 111, 445, 3306, 5432, 6379, 27017]

# ─── Subdomain Takeover Fingerprints ─────────────────────────────────────────
TAKEOVER_FINGERPRINTS = {
    ".herokudns.com":      ("Heroku",        "No such app"),
    ".herokuapp.com":      ("Heroku",        "No such app"),
    ".github.io":          ("GitHub Pages",  "There isn't a GitHub Pages site here"),
    ".netlify.app":        ("Netlify",       "Not Found"),
    ".netlify.com":        ("Netlify",       "Not Found"),
    ".vercel.app":         ("Vercel",        "The deployment you are trying"),
    ".fastly.net":         ("Fastly",        "Fastly error: unknown domain"),
    ".cloudfront.net":     ("CloudFront",    "ERROR: The request could not be satisfied"),
    ".s3.amazonaws.com":   ("AWS S3",        "NoSuchBucket"),
    ".s3-website":         ("AWS S3",        "NoSuchBucket"),
    ".azurewebsites.net":  ("Azure",         "404 Web Site not found"),
    ".cloudapp.net":       ("Azure",         "404 Web Site not found"),
    ".blob.core.windows.net": ("Azure Blob", "BlobNotFound"),
    ".storage.googleapis.com": ("GCS",       "NoSuchBucket"),
    ".myshopify.com":      ("Shopify",       "Sorry, this shop is currently unavailable"),
    ".squarespace.com":    ("Squarespace",   "No Such Account"),
    ".cargocollective.com":("Cargo",         "404 Not Found"),
    ".zendesk.com":        ("Zendesk",       "Help Center Closed"),
    ".tumblr.com":         ("Tumblr",        "There's nothing here"),
    ".wpengine.com":       ("WP Engine",     "The site you were looking for couldn't be found"),
    ".pantheonsite.io":    ("Pantheon",      "The gods are wise"),
    ".surge.sh":           ("Surge",         "project not found"),
    ".readme.io":          ("Readme",        "Project doesnt exist"),
    ".ghost.io":           ("Ghost",         "The thing you were looking"),
    ".launchrock.com":     ("Launchrock",    "It looks like you may have"),
    ".hs-sites.com":       ("HubSpot",       "does not exist"),
    ".unbouncepages.com":  ("Unbounce",      "The requested URL was not found"),
    ".intercom.help":      ("Intercom",      "This page is reserved"),
    ".bitbucket.io":       ("Bitbucket",     "Repository not found"),
    ".myjetbrains.com":    ("JetBrains",     "is not a registered InCloud YouTrack"),
    ".fly.dev":            ("Fly.io",        "404 Not Found"),
    ".onrender.com":       ("Render",        "not found"),
}

class ReconEngine:
    """
    Automated hyper-speed reconnaissance and secret scraping engine.
    """

    def __init__(self, target: str, output_dir: str = "./reports", timeout: int = 15, proxy_file: Optional[str] = None):
        if not target.startswith("http"):
            target = "https://" + target
        self.target = target.rstrip("/")
        self.target_url_parsed = urllib.parse.urlparse(self.target)
        self.target_domain = self.target_url_parsed.netloc
        self.base_domain = self.target_domain.replace("www.", "")
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.proxy_file = proxy_file
        
        self.subdomains: Set[str] = {self.target_domain}
        self.js_files: Set[str] = set()
        self.secrets: list[dict] = []
        self.open_ports: list[int] = []
        self.cloud_buckets: Set[str] = set()
        self.takeover_findings: list[dict] = []

    async def _fetch_crt_sh(self, requester: AsyncRequester):
        console.print(f"  [cyan]🔍 Fetching crt.sh logs for {self.base_domain}...[/cyan]")
        url = f"https://crt.sh/?q=%25.{self.base_domain}&output=json"
        try:
            resp = await requester.fetch("GET", url, timeout=30)
            if resp and resp.status_code == 200:
                data = resp.json()
                for item in data:
                    for key in ['common_name', 'name_value']:
                        val = item.get(key, "")
                        for sub in val.split("\n"):
                            sub = sub.strip().lower()
                            if sub and "*" not in sub:
                                self.subdomains.add(sub)
        except Exception as e:
            console.print(f"  [dim]crt.sh lookup failed: {e}[/dim]")

    async def _fetch_js_files(self, requester: AsyncRequester):
        console.print(f"  [cyan]🕷️ Finding JavaScript files on {self.target}...[/cyan]")
        try:
            resp = await requester.fetch("GET", self.target, follow_redirects=True)
            if resp and resp.status_code == 200:
                found = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', resp.text)
                for src in found:
                    full_url = urllib.parse.urljoin(self.target, src)
                    if self.base_domain in full_url:
                        self.js_files.add(full_url)
        except Exception as e:
            console.print(f"  [dim]JS discovery failed: {e}[/dim]")

    async def _scan_all_js_files(self, requester: AsyncRequester):
        if not self.js_files:
            return
        console.print(f"  [cyan]💉 Scanning {len(self.js_files)} JS files concurrently for secrets...[/cyan]")
        
        requests = [{"method": "GET", "url": url, "follow_redirects": True} for url in self.js_files]
        results = await requester.fetch_all(requests)
        
        for req, resp in zip(requests, results):
            if not resp or resp.status_code != 200: continue
            
            content = resp.text
            url = req["url"]
            for name, pattern in SECRET_PATTERNS.items():
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    match_val = match[0] if isinstance(match, tuple) else match
                    if not any(s['value'] == match_val for s in self.secrets):
                        # --- Anti-FP Check: Blacklist Filter ---
                        if any(b in match_val.lower() or b in name.lower() for b in SECRET_BLACKLIST):
                            continue

                        severity = "INFO" # Default to INFO for reconnaissance
                        if any(k in name for k in ["Access Key", "Secret", "Token", "GitHub", "Stripe"]):
                            severity = "MEDIUM" # Escalate ONLY for real credentials

                        self.secrets.append({
                            "type": name,
                            "value": match_val,
                            "source": url,
                            "severity": severity
                        })
                        if name in ["Internal Endpoint", "S3 Bucket URL", "Azure Blob", "Google Storage"]:
                            self.cloud_buckets.add(match_val)
                            if self.base_domain in match_val:
                                self.subdomains.add(match_val)

    async def _probe_buckets(self, requester: AsyncRequester):
        console.print(f"  [cyan]🪣 Probing common cloud bucket names...[/cyan]")
        prefixes = [self.base_domain.replace(".", "-"), self.base_domain.split(".")[0]]
        suffixes = ["assets", "images", "dev", "prod", "backup", "data", "files", "internal"]
        
        candidates = []
        for p in prefixes:
            for s in suffixes:
                candidates.extend([
                    f"{p}-{s}.s3.amazonaws.com",
                    f"{p}-{s}.blob.core.windows.net",
                    f"{p}-{s}.storage.googleapis.com"
                ])

        requests = [{"method": "HEAD", "url": "https://" + url} for url in candidates]
        results = await requester.fetch_all(requests)

        for req, resp in zip(requests, results):
            if resp and resp.status_code in [200, 403]:
                url_without_schema = req["url"].replace("https://", "")
                self.cloud_buckets.add(url_without_schema)

    def _resolve_cname(self, domain: str) -> Optional[str]:
        try:
            canonical = socket.getfqdn(domain)
            if canonical and canonical != domain:
                return canonical.rstrip(".")
            return None
        except Exception:
            return None

    async def _check_all_takeovers(self, requester: AsyncRequester):
        if len(self.subdomains) <= 1:
            return
            
        console.print(f"  [cyan]🔓 Checking {len(self.subdomains)} subdomains for takeover concurrently...[/cyan]")
        
        # Determine which subdomains have vulnerable CNAMEs BEFORE making HTTP requests
        takeover_candidates = []
        for sub in self.subdomains:
            if sub in (self.target_domain, self.base_domain): continue
            
            cname = self._resolve_cname(sub)
            if not cname: continue
            
            for cname_suffix, (service, body_fingerprint) in TAKEOVER_FINGERPRINTS.items():
                if cname.endswith(cname_suffix) or cname_suffix.lstrip(".") in cname:
                    takeover_candidates.append({
                        "subdomain": sub,
                        "cname": cname,
                        "service": service,
                        "fingerprint": body_fingerprint
                    })
                    break

        if not takeover_candidates:
            console.print(f"     [green]✅ No subdomain takeover detected among {len(self.subdomains)} processed.[/green]")
            return

        # Prepare HTTP requests to verify the takeover
        requests = []
        for candidate in takeover_candidates:
            sub = candidate["subdomain"]
            requests.append({"method": "GET", "url": f"http://{sub}", "follow_redirects": True, "meta": candidate})
            requests.append({"method": "GET", "url": f"https://{sub}", "follow_redirects": True, "meta": candidate})

        results = await requester.fetch_all(requests)

        for req, resp in zip(requests, results):
            if not resp: continue
            candidate = req["meta"]
            if candidate["fingerprint"].lower() in resp.text.lower():
                finding = {
                    "type": "Subdomain Takeover",
                    "severity": "HIGH",
                    "cvss_score": 8.1,
                    "subdomain": candidate["subdomain"],
                    "cname": candidate["cname"],
                    "service": candidate["service"],
                    "fingerprint": candidate["fingerprint"],
                    "url": req["url"],
                    "timestamp": datetime.utcnow().isoformat(),
                }
                if not any(f["subdomain"] == finding["subdomain"] for f in self.takeover_findings):
                    self.takeover_findings.append(finding)
                    console.print(f"     [bold red]🚨 TAKEOVER! {candidate['subdomain']} → {candidate['cname']} ({candidate['service']})[/bold red]")

    async def _check_all_ports(self):
        console.print(f"  [cyan]📡 Scanning standard ports...[/cyan]")
        loop = asyncio.get_event_loop()
        
        def check_port(port):
            try:
                socket.create_connection((self.target_domain, port), timeout=2)
                self.open_ports.append(port)
            except Exception:
                pass

        tasks = [loop.run_in_executor(None, lambda p=p: check_port(p)) for p in COMMON_PORTS]
        await asyncio.gather(*tasks)

    # ─────────────────────────────────────────────────────────────────────────
    # CORE ENGINE EXECUTION
    # ─────────────────────────────────────────────────────────────────────────

    async def run_async(self):
        console.print(Panel(
            f"[bold white]⚡ AURA v3 OMNI — Recon Engine (Async)[/bold white]\n"
            f"Target: [cyan]{self.target}[/cyan]",
            style="bright_blue",
        ))

        # Use 100 concurrent connections
        async with AsyncRequester(concurrency_limit=100, timeout=10, proxy_file=self.proxy_file) as requester:
            # Phase 1: Initial Discovery
            await asyncio.gather(
                self._fetch_crt_sh(requester),
                self._fetch_js_files(requester),
                self._probe_buckets(requester)
            )

            # Phase 2: Deep Scanning (Depends on Phase 1)
            await asyncio.gather(
                self._scan_all_js_files(requester),
                self._check_all_ports(),
                self._check_all_takeovers(requester)
            )

            # Phase 3: Nuclei Vanguard on all discovered subdomains
            await self._run_nuclei_vanguard()

        return self._finalize()

    async def _run_nuclei_vanguard(self):
        """Phase 5.0: Vanguard Template Scanning using Nuclei over all live targets"""
        if not self.subdomains:
            return
            
        console.print(Panel(f"[bold cyan]🔍 Recon Engine: Initiating Nuclei Vanguard against {len(self.subdomains)} targets[/bold cyan]", box=box.ROUNDED))
        
        # Write subdomains to a temp file for Nuclei
        targets_file = self.output_dir / "nuclei_targets.txt"
        targets_file.write_text("\n".join(self.subdomains), encoding="utf-8")
        output_file = self.output_dir / "nuclei_output.json"

        try:
            with Progress(
                SpinnerColumn("dots12"),
                TextColumn("[cyan]Running Nuclei Templates (CVEs, Misconfigs) on discovered subdomains...[/cyan]"),
                console=console
            ) as progress:
                task = progress.add_task("nuclei", total=None)
                
                # Execute Nuclei silently, outputting JSON to a file
                process = await asyncio.create_subprocess_exec(
                    "nuclei", "-l", str(targets_file), "-json-export", str(output_file), "-silent", "-severity", "low,medium,high,critical",
                    "-c", "50", "-bs", "25", # Concurrency limits to prevent crashing
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                await process.communicate()
            
            # Parse Findings
            if output_file.exists():
                findings_count = 0
                from aura.core.storage import AuraStorage
                db = AuraStorage()
                
                with open(output_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        try:
                            finding = json.loads(line)
                            severity = finding.get("info", {}).get("severity", "info").upper()
                            name = finding.get("info", {}).get("name", "Unknown Vuln")
                            url = finding.get("matched-at", self.target)
                            
                            # Only log actionable items to DB
                            if severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                                details = json.dumps(finding, indent=2)
                                db.add_finding(self.target, details, f"Nuclei: {name}", severity)
                                console.print(f"[bold red]► {severity}:[/bold red] [white]{name}[/white] at [yellow]{url}[/yellow]")
                                findings_count += 1
                        except json.JSONDecodeError:
                            continue
                
                if findings_count == 0:
                    console.print("[dim green]✅ Nuclei Vanguard: No immediate low-hanging fruit found.[/dim green]")
                else:
                    console.print(f"[bold orange3]⚠️ Nuclei Vanguard recorded {findings_count} template findings.[/bold orange3]")
            else:
                 console.print("[dim green]✅ Nuclei Vanguard: No findings file generated (Target Secure).[/dim green]")

        except FileNotFoundError:
            console.print("[yellow]⚠️ Nuclei binary not found. Skipping template vanguard.[/yellow]")
        except Exception as e:
            console.print(f"[red]❌ Nuclei Execution Error: {e}[/red]")
        finally:
            if targets_file.exists(): targets_file.unlink()
            if output_file.exists(): output_file.unlink()

    def run(self):
        """Wrapper to call async from sync code."""
        return asyncio.run(self.run_async())


    def _finalize(self):
        """Prints findings and saves to JSON."""
        # 1. Subdomains Table
        if self.subdomains:
            table = Table(title="Discoverd Subdomains", title_style="bold green", box=box.ROUNDED)
            table.add_column("Domain", style="cyan")
            for sub in sorted(list(self.subdomains))[:15]:
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

        report = {
            "target": self.target,
            "timestamp": datetime.utcnow().isoformat(),
            "subdomains": list(self.subdomains),
            "js_files": list(self.js_files),
            "secrets": self.secrets,
            "open_ports": sorted(self.open_ports),
            "cloud_buckets": list(self.cloud_buckets),
            "takeover_findings": self.takeover_findings,
        }

        if self.takeover_findings:
            from rich.table import Table as RichTable
            tk_table = RichTable(
                title="🚨 Subdomain Takeover Vulnerabilities",
                title_style="bold red", box=box.HEAVY_EDGE
            )
            tk_table.add_column("Subdomain",  style="cyan")
            tk_table.add_column("CNAME",      style="yellow")
            tk_table.add_column("Service",    style="red")
            tk_table.add_column("Severity",   style="bold red")
            for tk in self.takeover_findings:
                tk_table.add_row(tk["subdomain"], tk["cname"][:45], tk["service"], tk["severity"])
            console.print(tk_table)
            console.print(f"\n  [bold red]💡 Submit these as HIGH severity on Intigriti/HackerOne![/bold red]")

        target_slug = self.target_domain.replace(".", "_")
        out_path = self.output_dir / f"recon_omni_{target_slug}.json"
        
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        
        console.print(f"\n  [bold green]💾 Full Omni Recon Report saved:[/bold green] [cyan]{out_path}[/cyan]")
        return report

def run_recon(target: str, discovery_map_path: Optional[str] = None, proxy_file: Optional[str] = None) -> list[dict]:
    """Entry point for CLI."""
    engine = ReconEngine(target, proxy_file=proxy_file)
    return engine.run()

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "www.iciparisxl.nl"
    run_recon(target)
