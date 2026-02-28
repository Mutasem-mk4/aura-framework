import socket
import dns.resolver
import asyncio
from urllib.parse import urlparse
from rich.console import Console
from aura.modules.threat_intel import ThreatIntel
from aura.core.stealth import StealthEngine, AuraSession

console = Console()

class AuraScanner:
    """Internal scanning engine to replace external tools."""
    
    def __init__(self, stealth: StealthEngine = None):
        self.common_subdomains = ["www", "dev", "api", "staging", "admin", "vpn", "mail", "blog", "test"]
        self.stealth = stealth or StealthEngine()
        self.stealth_session = AuraSession(self.stealth)

    async def discover_subdomains(self, domain):
        """Discovers subdomains via DNS brute-forcing with rate-limiting & Threat Intel."""
        console.print(f"[blue][*] Starting subdomain discovery for: {domain}[/blue]")
        
        # Threat Intel: Check VT and OTX for domain reputation
        intel_module = ThreatIntel(stealth=self.stealth)
        vt_data = await intel_module.query_virustotal(domain)
        otx_data = await intel_module.query_otx(domain)
        
        found = []
        for sub in self.common_subdomains:
            target = f"{sub}.{domain}"
            await asyncio.sleep(0.1)  # Network Stability: Intentional jitter
            try:
                # Use to_thread for blocking DNS lookups
                answers = await asyncio.to_thread(dns.resolver.resolve, target, 'A')
                for rdata in answers:
                    found.append({"type": "subdomain", "value": target, "source": "Aura-Scan", "ip": str(rdata)})
                    console.print(f"[green][+] Found: {target} ({rdata})[/green]")
            except:
                continue
        return found

    async def scan_ports(self, target_ip, ports=[80, 443, 8080, 8443, 3000, 4280, 5000, 22, 21, 3306]):
        """Phase 23: Async TCP port scanner targeting common web and service ports."""
        
        # Gather Passive Threat Intel first (in a non-blocking way ideally, but kept simple here)
        intel_module = ThreatIntel(stealth=self.stealth)
        intel_data = await intel_module.query_shodan(target_ip)
        
        open_ports = []
        if intel_data and intel_data.get("ports"):
            for p in intel_data["ports"]:
                if p not in open_ports and p in ports:
                    open_ports.append(p)
                    
        console.print(f"[blue][*] Active Port Scanning on: {target_ip}...[/blue]")
        
        async def check_port(port):
            if port in open_ports: return port
            try:
                # 0.5 sec timeout
                fut = asyncio.open_connection(target_ip, port)
                reader, writer = await asyncio.wait_for(fut, timeout=0.5)
                writer.close()
                await writer.wait_closed()
                console.print(f"[green][+] Port {port} is OPEN[/green]")
                return port
            except:
                return None

        tasks = [check_port(p) for p in ports]
        results = await asyncio.gather(*tasks)
        for r in results:
            if r and r not in open_ports:
                open_ports.append(r)
                
        return open_ports

    async def dirbust(self, base_url):
        """Phase 23: Active Directory Brute Forcing to find hidden paths."""
        common_dirs = [
            "admin", "login", "api", "dvwa", "phpmyadmin", "backup", "db", 
            "test", "config", "setup", "dashboard", "portal", "old",
            "index.php", "home.php", "main.php", ".env", ".git", ".svn",
            "docker-compose.yml", "jenkins", "gitlab", "bitbucket", "jira"
        ]
        
        if not base_url.startswith("http"):
            base_url = f"http://{base_url}"
        base_url = base_url.rstrip('/')
            
        console.print(f"[magenta][*] DirBusting {base_url} for hidden paths...[/magenta]")
        discovered_urls = []
        
        # Phase 23: Catch-all 200 detection
        # Get baseline length to identify parked domains/catch-all servers
        baseline_len = 0
        try:
            base_res = await self.stealth_session.get(base_url, timeout=5)
            baseline_len = len(base_res.text)
        except: pass

        async def check_dir(directory):
            url = f"{base_url}/{directory}"
            try:
                res = await self.stealth_session.get(url, timeout=3, allow_redirects=False)
                # Ignore if it matches the baseline length (likely a redirect/catch-all)
                if abs(len(res.text) - baseline_len) < 10:
                    return None
                    
                if res.status_code in [200, 301, 302, 403, 401]:
                    console.print(f"[green][+] Found hidden path: {url} (Status: {res.status_code})[/green]")
                    return url
            except:
                pass
            return None
            
        tasks = [check_dir(d) for d in common_dirs]
        results = await asyncio.gather(*tasks)
        
        for r in results:
            if r: discovered_urls.append(r)
            
        return discovered_urls
