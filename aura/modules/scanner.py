import socket
import dns.resolver
from rich.console import Console

console = Console()

class AuraScanner:
    """Internal scanning engine to replace external tools."""
    
    def __init__(self):
        self.common_subdomains = ["www", "dev", "api", "staging", "admin", "vpn", "mail", "blog", "test"]

    def discover_subdomains(self, domain):
        """Discovers subdomains via DNS brute-forcing."""
        console.print(f"[blue][*] Starting subdomain discovery for: {domain}[/blue]")
        found = []
        for sub in self.common_subdomains:
            target = f"{sub}.{domain}"
            try:
                answers = dns.resolver.resolve(target, 'A')
                for rdata in answers:
                    found.append({"type": "subdomain", "value": target, "source": "Aura-Scan", "ip": str(rdata)})
                    console.print(f"[green][+] Found: {target} ({rdata})[/green]")
            except:
                continue
        return found

    def scan_ports(self, target_ip, ports=[80, 443, 8080, 22, 21, 3306]):
        """Simple TCP port scanner."""
        console.print(f"[blue][*] Scanning ports on: {target_ip}[/blue]")
        open_ports = []
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                open_ports.append(port)
                console.print(f"[green][+] Port {port} is OPEN[/green]")
            sock.close()
        return open_ports
