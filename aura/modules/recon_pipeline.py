"""
Aura v5.0: Hybrid Reconnaissance Pipeline
Subfinder → HTTPX → Nmap pipeline with Python-native fallback.

If external tools (subfinder, httpx, nmap) are installed on PATH, they are used for
maximum speed and accuracy. If not, Aura falls back to its internal DNS/HTTP/TCP engines.
This ensures the MISSING KEY problem is fully solved — no external API needed.
"""
import asyncio
import os
import socket
import subprocess
import shutil
import re
import json
from urllib.parse import urlparse
from aura.core import state
from rich.console import Console
from aura.core.engine_interface import IEngine
from aura.core.models import Finding
from aura.core.native_prober import NativeProber
from aura.core.aura_subfinder import NativeSubfinder
from aura.core.aura_port_scanner import NativePortScanner
from aura.modules.cloud_recon import AuraCloudRecon
from aura.modules.infra_reaper import InfraReaper
from aura.modules.sentinel_ssrf import SentinelSSRF
from aura.modules.desync_prober import DesyncProber

from aura.ui.formatter import console


class ReconPipeline(IEngine):
    """
    v5.0 Multi-layered Recon Pipeline:
      Stage 1: Subfinder (or DNS brute-force fallback) → alive subdomains
      Stage 2: HTTPX (or aiohttp fallback) → HTTP probe, title, status, tech
      Stage 3: Nmap (or TCP scanner fallback) → open ports, service banners
    """
    
    ENGINE_ID = "recon_pipeline"

    SUBDOMAINS_WORDLIST = [
        "www", "api", "dev", "staging", "admin", "mail", "blog", "app",
        "test", "shop", "cdn", "static", "assets", "auth", "login",
        "portal", "dashboard", "vpn", "remote", "ftp", "smtp", "pop",
        "m", "mobile", "web", "secure", "beta", "old", "new", "v2",
        "jenkins", "gitlab", "bitbucket", "jira", "confluence", "wiki",
    ]
    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                    3306, 5432, 6379, 8080, 8443, 8888, 27017]

    def __init__(self, session=None, persistence=None, telemetry=None, brain=None, **kwargs):
        self.session = session
        self.persistence = persistence
        self.telemetry = telemetry
        self.brain = brain
        import os
        
        def find_tool(name):
            path = shutil.which(name)
            if path: return path
            go_path = os.path.expanduser(f"~/go/bin/{name}.exe")
            if os.path.exists(go_path): return go_path
            return None

        self.subfinder_path = find_tool("subfinder")
        self.httpx_path = find_tool("httpx")
        self.nmap_path = find_tool("nmap")
        self.katana_path = find_tool("katana")
        
        self.native_prober = NativeProber()
        self.native_subfinder = NativeSubfinder()
        self.native_port_scanner = NativePortScanner()
        
        self.cloud_recon = AuraCloudRecon(storage=self.persistence)
        self.infra_reaper = InfraReaper()
        self.sentinel_ssrf = SentinelSSRF()
        self.desync_prober = DesyncProber(storage=self.persistence)
        self._status = "initialized"
        
        self._has_subfinder = True # We now have native subfinder via NativeSubfinder
        self._has_httpx = True # We now have native httpx via NativeProber
        self._has_nmap = True # We now have native nmap via NativePortScanner
        self._has_katana = self.katana_path is not None

    # ─── Stage 1: Subdomain Discovery ────────────────────────────────────────

    async def stage1_subfinder(self, domain: str) -> list[str]:
        """v51.0: Discovers live subdomains using NATIVE Subfinder (OSINT + DNS Resolver)."""
        try:
            found = await self.native_subfinder.discover(domain)
            console.print(f"[bold green][+] Stage 1 Complete: {len(found)} LIVE subdomains discovered natively.[/bold green]")
            return found
        except Exception as e:
            console.print(f"[red][!] Native Subfinder failed: {e}. Falling back to basic list.[/red]")
            return [domain]

    # ─── Stage 2: HTTP Probing ────────────────────────────────────────────────

    async def stage2_httpx(self, hosts: list[str], stealth_mode: bool = False) -> list[dict]:
        """v51.0: Probes hosts using AURA NATIVE Prober (Morphic Headers + AI Feedback)."""
        console.print(f"[cyan][🌐 Recon] Stage 2: Native Prober → analyzing {len(hosts)} hosts...[/cyan]")
        
        try:
            results = await self.native_prober.batch_probe(hosts, stealth=stealth_mode)
            
            # Map native results to recon pipeline format
            formatted_results = []
            for r in results:
                if r.get("error") or r.get("status_code") == 0:
                    continue
                formatted_results.append({
                    "host": urlparse(r.get("url", "")).netloc if r.get("url") else "unknown",
                    "url": r.get("url", ""),
                    "status": r.get("status_code", 0),
                    "title": r.get("title", ""),
                    "tech": r.get("tech", []),
                    "waf": r.get("waf"),
                    "ai_advice": r.get("ai_advice")
                })
            
            console.print(f"[green][+] Native Prober: {len(formatted_results)} live HTTP services discovered.[/green]")
            return formatted_results
        except Exception as e:
            console.print(f"[yellow][!] Native Prober failed: {e}. Falling back to basic Python probe.[/yellow]")
            return await self.stage2_fallback(hosts)

        return await self.stage2_fallback(hosts)

    async def stage2_fallback(self, hosts: list[str]) -> list[dict]:
        """Fallback: Python HTTP probe"""
        console.print(f"[cyan][🌐 Recon] Stage 2 (HTTP Fallback): Probing {len(hosts)} hosts...[/cyan]")
        results = []

        async def probe(host):
            for scheme in ["https", "http"]:
                url = f"{scheme}://{host}"
                try:
                    import aiohttp
                    async with aiohttp.ClientSession() as s:
                        async with s.get(url, timeout=aiohttp.ClientTimeout(total=5),
                                         allow_redirects=True, ssl=False) as r:
                            body = await r.text()
                            title_match = re.search(r"<title>([^<]{1,120})</title>", body, re.I)
                            title = title_match.group(1).strip() if title_match else ""
                            tech = []
                            if "wordpress" in body.lower(): tech.append("WordPress")
                            if "laravel" in body.lower(): tech.append("Laravel")
                            if "django" in body.lower(): tech.append("Django")
                            if "x-powered-by" in str(r.headers).lower():
                                tech.append(r.headers.get("x-powered-by", ""))
                            results.append({
                                "host": host, "url": url,
                                "status": r.status, "title": title, "tech": tech
                            })
                            console.print(f"[green]  [+] {url} → {r.status} | {title[:40]}[/green]")
                            return
                except: pass

        await asyncio.gather(*[probe(h) for h in hosts])
        return results

    # ─── Stage 3: Port Scanning & Banner Grabbing ─────────────────────────────

    async def stage3_nmap(self, ip: str, ports: list[int] = None, stealth_mode: bool = False, passive_ports: list[int] = None) -> list[dict]:
        """v51.0 (PRO): Scans for open ports using AURA NATIVE Port Scanner."""
        ports = ports or self.native_port_scanner.COMMON_PORTS
        
        if passive_ports:
            # Use passive intel to focus the scan or skip if in deep stealth
            if stealth_mode:
                console.print(f"[bold yellow][!] Stealth Mode Active: Skipping active scan. Relying on passive OSINT ports.[/bold yellow]")
                return [{"port": p, "state": "open", "service": "unknown", "banner": "passive-intel"} for p in passive_ports]
            else:
                ports = list(set(ports) | set(passive_ports))

        console.print(f"[cyan][🌐 Recon] Stage 3: Native Port Scanner → {ip}...[/cyan]")
        try:
            results = await self.native_port_scanner.scan(ip, ports)
            
            # Formatting results for the pipeline
            services = []
            for r in results:
                services.append({
                    "port": r.get("port", 0),
                    "state": r.get("state", "unknown"),
                    "service": r.get("service", "unknown"),
                    "version": r.get("banner", "") # Mapping banner to 'version' for legacy compatibility
                })
                console.print(f"[green]  [+] {ip}:{r.get('port')} open → {r.get('service')} {r.get('banner', '')[:30]}[/green]")
            
            # Path 3 Integration: Trigger InfraReaper if infra ports found
            open_ports = [r["port"] for r in results if r["state"] == "open"]
            await self.infra_reaper.audit_host(ip, open_ports)
            
            return services
        except Exception as e:
            console.print(f"[red][!] Native Port Scanner failed for {ip}: {e}[/red]")
            return []

    # ─── Stage 4: Katana Deep Crawling (v25.0 Go-Arsenal) ─────────────────────

    async def stage4_katana(self, target_urls: list[str]) -> list[str]:
        """v38.0 OMEGA: Resilient Katana execution with deep-crawl fallback."""
        if not self._has_katana or not target_urls:
            return []

        console.print(f"[cyan][🌐 Recon] Stage 4: Katana → Deep crawling {len(target_urls)} HTTP services...[/cyan]")
        try:
            discovered_links = await self._run_katana_core(target_urls, depth=3)
            if not discovered_links and target_urls:
                console.print("[bold yellow][!] Katana: No results. Triggering Deep-Dive Headless Fallback...[/bold yellow]")
                discovered_links = await self._run_katana_core(target_urls, depth=5, extra_args=["-js-lu", "-js-crawl", "-automatic-form-fill"])
            
            console.print(f"[bold red][🔥] Katana Complete: Discovered {len(discovered_links)} deep endpoints/files![/bold red]")
            return discovered_links
        except Exception as e:
            console.print(f"[yellow][!] Katana: Systemic execution error: {e}[/yellow]")
        return []

    async def _run_katana_core(self, target_urls: list[str], depth: int = 3, extra_args: list[str] = None) -> list[str]:
        """v38.0: Core Katana execution logic with JSON parsing."""
        discovered = set()
        input_hosts = "\n".join(target_urls)
        cmd = [self.katana_path, "-silent", "-jc", "-kf", "all", "-d", str(depth), "-hl"]
        if extra_args:
            cmd.extend(extra_args)
            
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(input=input_hosts.encode()), timeout=400)
            for line in stdout.decode('utf-8', 'ignore').splitlines():
                try:
                    data = json.loads(line)
                    req_url = data.get("request", {}).get("endpoint")
                    if req_url: discovered.add(req_url)
                except: pass
        except asyncio.TimeoutError:
            try: proc.kill()
            except: pass
        return list(discovered)

    async def _run_beginner_recon(self, domain: str, results: dict):
        """v51.0: Populates beginner-friendly data (Dorks, Tips, soft-target scanning)."""
        console.print(f"[bold yellow][🎓 CLINIC] Beginner Recon engaged for {domain}...[/bold yellow]")
        
        # 1. Load templates
        templates_path = os.path.join(os.path.dirname(__file__), "..", "..", "data", "recon_templates.json")
        if os.path.exists(templates_path):
            try:
                with open(templates_path, "r") as f:
                    templates = json.load(f)
                    results["dorks"] = [d.replace("{{domain}}", domain) for d in templates.get("dorks", [])]
                    console.print(f"  [+] Loaded {len(results['dorks'])} specialized Google Dorks.")
            except: pass
        
        # 2. Add Educational Tips
        results["beginner_tips"] = [
            "Always check subdomains for 'dev' or 'staging' environments; they often have weaker auth.",
            "Look for exposed .git or .env files in the root directory.",
            "If you see a 403, try adding 'X-Forwarded-For: 127.0.0.1' to your headers."
        ]

    # ─── Full Pipeline ────────────────────────────────────────────────────────

    async def run(self, domain: str, target_ip: str = None, intel_data: dict = None, stealth_mode: bool = False, beginner_mode: bool = False) -> dict:
        """
        Runs the full Stage1→Stage2→Stage3 recon pipeline.
        Merges passive data (Shodan, VirusTotal, SecurityTrails) into active checks.
        Returns a structured dict for the 'Reconnaissance' section of the report.
        """
        intel_data = intel_data or {}
        console.print(f"\n[bold cyan][🌐 RECON PIPELINE] Starting 3-stage pipeline for {domain}...[/bold cyan]")

        # Initialize results dictionary for beginner mode and general use
        results = {
            "subdomains": [],
            "http_services": [],
            "open_ports": [],
            "deep_links": [],
            "tech_stack": [],
            "tool_chain": "",
            "dorks": [] # Added for beginner mode
        }

        if state.BEGINNER_MODE:
            await self._run_beginner_recon(domain, results)
            # In beginner mode, we might want to simplify or skip some active stages
            # For now, we'll let the full pipeline run and just add dorks.
            # Future: Add logic to conditionally run stages based on beginner_mode.

        # v22.1: Pre-flight DNS Check
        try:
            await asyncio.get_event_loop().run_in_executor(None, socket.gethostbyname, domain)
        except socket.gaierror:
            console.print(f"[bold red][!] DNS ERROR: Could not resolve {domain}. Target appears offline or DNS is blocked.[/bold red]")
            # We continue, as OSINT might still work, but we log the failure.

        # Stage 1
        subdomains = await self.stage1_subfinder(domain)
        if not subdomains: subdomains = []
        if domain not in subdomains: subdomains.insert(0, domain)
        
        # Merge Passive Subdomains
        passive_subs = set()
        if "securitytrails" in intel_data:
            for sub in intel_data["securitytrails"].get("subdomains", []):
                passive_subs.add(f"{sub}.{domain}")
        if "virustotal" in intel_data:
            vt_subs = intel_data["virustotal"].get("stats", {})
            # VT endpoint used in threat_intel doesn't return full subdomain list cleanly in 'stats', 
            # but usually it's fetched via subdomains endpoint. Assuming we have them in intel_data if added later.
            pass
            
        if passive_subs:
            console.print(f"[green][+] Aggregating {len(passive_subs)} passive subdomains from SecurityTrails/OSINT...[/green]")
            subdomains = list(set(subdomains) | passive_subs)

        # Stage 2
        all_hosts = [domain] + subdomains
        http_data = await self.stage2_httpx(all_hosts, stealth_mode=stealth_mode)

        # Stage 3
        ip = target_ip or domain
        try:
            if not target_ip:
                ip = socket.gethostbyname(domain)
        except: pass
        
        passive_ports = []
        if "shodan" in intel_data:
            passive_ports.extend(intel_data["shodan"].get("ports", []))
        if "censys" in intel_data:
            for srv in intel_data["censys"].get("services", []):
                if srv.get("port"): passive_ports.append(srv.get("port"))
        passive_ports = list(set(passive_ports))

        nmap_data = await self.stage3_nmap(ip, stealth_mode=stealth_mode, passive_ports=passive_ports)

        # Stage 4: Katana Deep Crawl
        deep_links = [] # Placeholder for future Katana integration results
        
        # Path 3 Integration: Cloud Recon
        from aura.core.storage import AuraStorage
        self.cloud_recon.storage = AuraStorage() # Initialize storage for the result
        await self.cloud_recon.hunt(domain)

        # Path 2/3 Apex Integration: HTTP Request Smuggling Audit
        self.desync_prober.storage = self.cloud_recon.storage
        active_http_urls = [r["url"] for r in http_data if r.get("url")]
        await self.desync_prober.audit_endpoints(active_http_urls)

        results.update({
            "subdomains": subdomains,
            "http_services": http_data,
            "open_ports": nmap_data,
            "deep_links": deep_links,
            "tech_stack": list({t for h in http_data for t in h.get("tech", []) if t}),
            "tool_chain": (
                f"{'Subfinder' if self._has_subfinder else 'DNS-Brute'} → "
                f"{'HTTPX' if self._has_httpx else 'Python-HTTP'} → "
                f"{'Nmap' if self._has_nmap else 'TCP-Scan'} → "
                f"{'Katana' if self._has_katana else 'Spider-Skipped'}"
            )
        })

        console.print(f"[bold green][✔ RECON PIPELINE] Complete: {len(subdomains)} subdomains, "
                      f"{len(http_data)} HTTP services, {len(nmap_data)} open ports, {len(deep_links)} deep links.[/bold green]")
        self._status = "completed"
        return results

    def get_status(self) -> dict:
        return {"id": self.ENGINE_ID, "status": self._status}
