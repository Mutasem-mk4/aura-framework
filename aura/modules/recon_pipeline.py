"""
Aura v5.0: Hybrid Reconnaissance Pipeline
Subfinder → HTTPX → Nmap pipeline with Python-native fallback.

If external tools (subfinder, httpx, nmap) are installed on PATH, they are used for
maximum speed and accuracy. If not, Aura falls back to its internal DNS/HTTP/TCP engines.
This ensures the MISSING KEY problem is fully solved — no external API needed.
"""
import asyncio
import socket
import subprocess
import shutil
import re
import json
from rich.console import Console

console = Console()


class ReconPipeline:
    """
    v5.0 Multi-layered Recon Pipeline:
      Stage 1: Subfinder (or DNS brute-force fallback) → alive subdomains
      Stage 2: HTTPX (or aiohttp fallback) → HTTP probe, title, status, tech
      Stage 3: Nmap (or TCP scanner fallback) → open ports, service banners
    """

    SUBDOMAINS_WORDLIST = [
        "www", "api", "dev", "staging", "admin", "mail", "blog", "app",
        "test", "shop", "cdn", "static", "assets", "auth", "login",
        "portal", "dashboard", "vpn", "remote", "ftp", "smtp", "pop",
        "m", "mobile", "web", "secure", "beta", "old", "new", "v2",
        "jenkins", "gitlab", "bitbucket", "jira", "confluence", "wiki",
    ]
    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                    3306, 5432, 6379, 8080, 8443, 8888, 27017]

    def __init__(self, session=None):
        self.session = session
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
        
        self._has_subfinder = self.subfinder_path is not None
        self._has_httpx = self.httpx_path is not None
        self._has_nmap = self.nmap_path is not None
        self._has_katana = self.katana_path is not None

    # ─── Stage 1: Subdomain Discovery ────────────────────────────────────────

    async def stage1_subfinder(self, domain: str) -> list[str]:
        """Discovers live subdomains using Native OSINT Engines (HackerTarget, OTX, crt.sh) + Resolving."""
        console.print(f"[cyan][🌐 Recon] Stage 1 (Native OSINT): Gathering subdomains for {domain}...[/cyan]")
        subdomains = set([domain])

        # Always include the basic fallback list
        for sub in self.SUBDOMAINS_WORDLIST:
            subdomains.add(f"{sub}.{domain}")

        async def fetch_otx(d):
            try:
                import aiohttp
                async with aiohttp.ClientSession() as s:
                    async with s.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{d}/passive_dns", timeout=15) as r:
                        if r.status == 200:
                            data = await r.json()
                            for active in data.get('passive_dns', []):
                                sub = active.get('hostname', '')
                                if sub.endswith(d): subdomains.add(sub.lower())
            except: pass

        async def fetch_hackertarget(d):
            try:
                import aiohttp
                async with aiohttp.ClientSession() as s:
                    async with s.get(f"https://api.hackertarget.com/hostsearch/?q={d}", timeout=15) as r:
                        if r.status == 200:
                            text = await r.text()
                            for line in text.splitlines():
                                sub = line.split(',')[0]
                                if sub.endswith(d): subdomains.add(sub.lower())
            except: pass

        async def fetch_crtsh(d):
            try:
                import aiohttp
                async with aiohttp.ClientSession() as s:
                    async with s.get(f"https://crt.sh/?q=%25.{d}&output=json", timeout=20) as r:
                        if r.status == 200:
                            try:
                                data = await r.json()
                            except:
                                text = await r.text()
                                data = json.loads(text)
                            for item in data:
                                name = item.get('name_value', '')
                                for sub in name.split('\\n'):
                                    sub = sub.strip().lstrip('*.')
                                    if sub.endswith(d): subdomains.add(sub.lower())
            except: pass

        # Run OSINT sources concurrently
        await asyncio.gather(fetch_otx(domain), fetch_hackertarget(domain), fetch_crtsh(domain))

        console.print(f"[yellow][↻] OSINT Aggregated: {len(subdomains)} unique potential subdomains. Resolving...[/yellow]")

        found = []
        loop = asyncio.get_event_loop()

        # Batch resolve to filter out dead subdomains
        async def resolve(sub):
            try:
                ip = await loop.run_in_executor(None, socket.gethostbyname, sub)
                if ip:
                    found.append(sub)
            except: pass

        # Limit concurrency for resolving to avoid overwhelming the DNS resolver
        sem = asyncio.Semaphore(100)
        async def sem_resolve(sub):
            async with sem:
                await resolve(sub)

        await asyncio.gather(*[sem_resolve(sub) for sub in subdomains])

        console.print(f"[bold green][+] Stage 1 Complete: {len(found)} LIVE subdomains discovered natively.[/bold green]")
        return found

    # ─── Stage 2: HTTP Probing ────────────────────────────────────────────────

    async def stage2_httpx(self, hosts: list[str], stealth_mode: bool = False) -> list[dict]:
        """Probes hosts for live HTTP services using httpx CLI or aiohttp fallback."""
        if self._has_httpx:
            console.print(f"[cyan][🌐 Recon] Stage 2: HTTPX → probing {len(hosts)} hosts...[/cyan]")
            try:
                input_hosts = "\n".join(hosts)
                
                # Base httpx command
                cmd_args = ["-silent", "-json", "-title", "-tech-detect", "-status-code", "-k"]
                
                if stealth_mode:
                    console.print("[yellow][!] Stealth Mode: Adding randomized browsers headers and rate limiting to HTTPX.[/yellow]")
                    import random
                    user_agents = [
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0"
                    ]
                    # Add jitter, rate limits, and custom headers
                    cmd_args.extend([
                        "-H", f"User-Agent: {random.choice(user_agents)}",
                        "-H", "Accept-Language: en-US,en;q=0.9",
                        "-H", "Sec-Fetch-Dest: document",
                        "-H", "Sec-Fetch-Mode: navigate",
                        "-H", "Sec-Fetch-Site: none",
                        "-rl", "5",        # 5 requests per second
                        "-c", "2",         # Low concurrency
                        "-delay", "2s"     # Delay between requests
                    ])
                
                proc = await asyncio.create_subprocess_exec(
                    self.httpx_path, *cmd_args,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL
                )
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(input=input_hosts.encode()), timeout=120
                )
                results = []
                for line in stdout.decode().splitlines():
                    try:
                        data = json.loads(line)
                        results.append({
                            "host": data.get("host", ""),
                            "url": data.get("url", ""),
                            "status": data.get("status-code", 0),
                            "title": data.get("title", ""),
                            "tech": data.get("tech", []),
                        })
                    except: pass
                console.print(f"[green][+] HTTPX: {len(results)} live HTTP services.[/green]")
                if not results:
                    return await self.stage2_fallback(hosts)
                return results
            except Exception as e:
                console.print(f"[yellow][!] HTTPX failed: {e}. Falling back to Python HTTP probe.[/yellow]")

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
        """Port scanning using nmap CLI or raw TCP scanner fallback. Utilizes passive ports if available."""
        ports = ports or self.COMMON_PORTS

        if passive_ports:
            console.print(f"[cyan][🌐 Recon] Stage 3: Discovered {len(passive_ports)} passive ports via OSINT.[/cyan]")
            if stealth_mode:
                console.print(f"[bold yellow][!] Stealth Mode Active: Skipping active Nmap scan. Relying ONLY on passive OSINT ports.[/bold yellow]")
                return [{"port": p, "service": "unknown", "version": "passive-intel"} for p in passive_ports]
            else:
                console.print(f"[green][+] Accelerating Nmap scan using precisely {len(passive_ports)} known OSINT ports.[/green]")
                ports = passive_ports # Overwrite COMMON_PORTS to only scan known open ports

        if self._has_nmap:
            console.print(f"[cyan][🌐 Recon] Stage 3: Nmap → {ip}...[/cyan]")
            try:
                port_str = ",".join(str(p) for p in ports)
                result = await asyncio.create_subprocess_exec(
                    self.nmap_path, "-sV", "--open", "-p", port_str, ip,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL
                )
                stdout, _ = await asyncio.wait_for(result.communicate(), timeout=90)
                raw = stdout.decode()
                services = []
                for line in raw.splitlines():
                    m = re.match(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line)
                    if m:
                        port, svc, ver = m.groups()
                        services.append({"port": int(port), "service": svc, "version": ver.strip()})
                        console.print(f"[green]  [+] {ip}:{port} → {svc} {ver}[/green]")
                return services
            except Exception as e:
                console.print(f"[yellow][!] Nmap failed: {e}. Falling back to TCP scanner.[/yellow]")

        # Fallback: raw TCP banner grab
        console.print(f"[cyan][🌐 Recon] Stage 3 (TCP Fallback): Scanning {ip}...[/cyan]")
        services = []
        loop = asyncio.get_event_loop()

        def _grab(port):
            try:
                s = socket.socket()
                s.settimeout(2)
                s.connect((ip, port))
                s.send(b"HEAD / HTTP/1.0\r\n\r\n" if port in [80, 8080, 443, 8443] else b"\r\n")
                banner = s.recv(512).decode("utf-8", "ignore").strip()
                s.close()
                return {"port": port, "service": "unknown", "version": banner[:80]}
            except: return None

        tasks = [loop.run_in_executor(None, _grab, p) for p in ports]
        results = await asyncio.gather(*tasks)
        for r in results:
            if r:
                services.append(r)
                console.print(f"[green]  [+] {ip}:{r['port']} open → {r['version'][:60]}[/green]")
        return services

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

    # ─── Full Pipeline ────────────────────────────────────────────────────────

    async def run(self, domain: str, target_ip: str = None, intel_data: dict = None, stealth_mode: bool = False) -> dict:
        """
        Runs the full Stage1→Stage2→Stage3 recon pipeline.
        Merges passive data (Shodan, VirusTotal, SecurityTrails) into active checks.
        Returns a structured dict for the 'Reconnaissance' section of the report.
        """
        intel_data = intel_data or {}
        console.print(f"\n[bold cyan][🌐 RECON PIPELINE] Starting 3-stage pipeline for {domain}...[/bold cyan]")

        # v22.1: Pre-flight DNS Check
        try:
            await asyncio.get_event_loop().run_in_executor(None, socket.gethostbyname, domain)
        except socket.gaierror:
            console.print(f"[bold red][!] DNS ERROR: Could not resolve {domain}. Target appears offline or DNS is blocked.[/bold red]")
            # We continue, as OSINT might still work, but we log the failure.

        # Stage 1
        subdomains = await self.stage1_subfinder(domain)
        
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
        active_http_urls = [h.get("url") for h in http_data if h.get("url")]
        deep_links = await self.stage4_katana(active_http_urls)

        result = {
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
        }

        console.print(f"[bold green][✔ RECON PIPELINE] Complete: {len(subdomains)} subdomains, "
                      f"{len(http_data)} HTTP services, {len(nmap_data)} open ports, {len(deep_links)} deep links.[/bold green]")
        return result
