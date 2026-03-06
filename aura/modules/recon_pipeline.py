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
        self._has_subfinder = shutil.which("subfinder") is not None
        self._has_httpx = shutil.which("httpx") is not None
        self._has_nmap = shutil.which("nmap") is not None

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

    async def stage2_httpx(self, hosts: list[str]) -> list[dict]:
        """Probes hosts for live HTTP services using httpx CLI or aiohttp fallback."""
        if self._has_httpx:
            console.print(f"[cyan][🌐 Recon] Stage 2: HTTPX → probing {len(hosts)} hosts...[/cyan]")
            try:
                input_hosts = "\n".join(hosts)
                proc = await asyncio.create_subprocess_exec(
                    "httpx", "-silent", "-json", "-title", "-tech-detect", "-status-code", "-k",
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

    async def stage3_nmap(self, ip: str, ports: list[int] = None) -> list[dict]:
        """Port scanning using nmap CLI or raw TCP scanner fallback."""
        ports = ports or self.COMMON_PORTS

        if self._has_nmap:
            console.print(f"[cyan][🌐 Recon] Stage 3: Nmap → {ip}...[/cyan]")
            try:
                port_str = ",".join(str(p) for p in ports)
                result = await asyncio.create_subprocess_exec(
                    "nmap", "-sV", "--open", "-p", port_str, ip,
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

    # ─── Full Pipeline ────────────────────────────────────────────────────────

    async def run(self, domain: str, target_ip: str = None) -> dict:
        """
        Runs the full Stage1→Stage2→Stage3 recon pipeline.
        Returns a structured dict for the 'Reconnaissance' section of the report.
        """
        console.print(f"\n[bold cyan][🌐 RECON PIPELINE] Starting 3-stage pipeline for {domain}...[/bold cyan]")

        # Stage 1
        subdomains = await self.stage1_subfinder(domain)

        # Stage 2
        all_hosts = [domain] + subdomains
        http_data = await self.stage2_httpx(all_hosts)

        # Stage 3
        ip = target_ip or domain
        try:
            if not target_ip:
                ip = socket.gethostbyname(domain)
        except: pass
        nmap_data = await self.stage3_nmap(ip)

        result = {
            "subdomains": subdomains,
            "http_services": http_data,
            "open_ports": nmap_data,
            "tech_stack": list({t for h in http_data for t in h.get("tech", []) if t}),
            "tool_chain": (
                f"{'Subfinder' if self._has_subfinder else 'DNS-Brute'} → "
                f"{'HTTPX' if self._has_httpx else 'Python-HTTP'} → "
                f"{'Nmap' if self._has_nmap else 'TCP-Scan'}"
            )
        }

        console.print(f"[bold green][✔ RECON PIPELINE] Complete: {len(subdomains)} subdomains, "
                      f"{len(http_data)} HTTP services, {len(nmap_data)} open ports.[/bold green]")
        return result
