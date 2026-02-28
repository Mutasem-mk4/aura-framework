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

    # These paths are LEAF nodes — never recurse into them
    DIRBUST_NO_RECURSE = {
        ".env", ".git", ".svn", "docker-compose.yml",
        "index.php", "home.php", "main.php", "robots.txt",
        "phpmyadmin", "dvwa",  # Tool/UI paths, not real directories
    }

    async def dirbust(self, base_url, _depth=0):
        """
        Phase 23: Active Directory Brute Forcing to find hidden paths.
        v3.0 Fix: Only recurse into 200 responses. Never recurse into 403 or
        sensitive leaf-file paths. Hardcapped at depth 2 to prevent explosion.
        """
        MAX_DEPTH = 2  # Only go 2 levels deep from the base URL
        
        common_dirs = [
            "admin", "login", "api", "backup", "db",
            "test", "config", "setup", "dashboard", "portal", "old",
            "index.php", "home.php", "main.php", ".env", ".git", ".svn",
            "docker-compose.yml", "jenkins", "gitlab", "phpmyadmin", "dvwa"
        ]
        
        if not base_url.startswith("http"):
            base_url = f"http://{base_url}"
        base_url = base_url.rstrip('/')
        
        if _depth == 0:  # Only show the top-level message
            console.print(f"[magenta][*] DirBusting {base_url} for hidden paths (max depth {MAX_DEPTH})...[/magenta]")
        
        discovered_urls = []
        
        # Baseline to detect catch-all servers
        baseline_len = 0
        try:
            base_res = await self.stealth_session.get(base_url, timeout=5)
            baseline_len = len(base_res.text)
        except: pass

        async def check_dir(directory):
            url = f"{base_url}/{directory}"
            try:
                res = await self.stealth_session.get(url, timeout=3, allow_redirects=False)
                if abs(len(res.text) - baseline_len) < 10:
                    return None, False  # Catch-all / redirect, ignore
                    
                if res.status_code == 200:
                    console.print(f"[green][+] Found hidden path: {url} (Status: 200)[/green]")
                    return url, True   # 200 = real content, CAN recurse
                    
                elif res.status_code in [301, 302]:
                    console.print(f"[green][+] Found hidden path: {url} (Status: {res.status_code})[/green]")
                    return url, False  # Redirect = exists but don't recurse
                    
                elif res.status_code in [403, 401]:
                    # EXISTS but ACCESS DENIED — log it but DO NOT recurse
                    console.print(f"[yellow][~] Restricted path: {url} (Status: {res.status_code} - Access Denied)[/yellow]")
                    return url, False  # 403 = dead end, no recursion
                    
            except: pass
            return None, False
            
        tasks = [check_dir(d) for d in common_dirs]
        results = await asyncio.gather(*tasks)
        
        for url, can_recurse in results:
            if not url:
                continue
            discovered_urls.append(url)
            
            # Recurse ONLY into 200-status directories, not files, not 403s
            last_segment = url.rstrip('/').split('/')[-1]
            if (can_recurse
                    and _depth < MAX_DEPTH
                    and last_segment not in self.DIRBUST_NO_RECURSE
                    and '.' not in last_segment):  # Never recurse into files
                sub_paths = await self.dirbust(url, _depth=_depth + 1)
                discovered_urls.extend(sub_paths)
            
        return discovered_urls
