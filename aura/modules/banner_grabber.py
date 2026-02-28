"""
Aura v3.0: Banner Grabbing & OSINT Resiliency Module
When external API keys (Shodan, VirusTotal) are missing, Aura fills the intelligence gap
by performing active Banner Grabbing and Service Fingerprinting.
"""
import asyncio
import socket
from rich.console import Console

console = Console()

class BannerGrabber:
    """
    v3.0 OSINT Resiliency: Grabs service banners via raw TCP connections.
    Used when Shodan/Censys API keys are missing to fill intelligence gaps.
    """
    
    COMMON_PORTS = [21, 22, 23, 25, 80, 443, 110, 143, 3306, 5432, 6379, 8080, 8443, 27017]
    TIMEOUT = 3
    
    # Map banner keywords to known service vulnerabilities
    BANNER_INTEL = {
        "openssh": {"type": "SSH Service", "check": "CVE scan recommended for version"},
        "apache": {"type": "Web Server", "check": "Check version for known CVEs (mod_cgi, etc.)"},
        "nginx": {"type": "Web Server", "check": "Check for misconfig and directory traversal"},
        "mysql": {"type": "Database Exposed", "check": "CRITICAL: DB port exposed to internet"},
        "postgresql": {"type": "Database Exposed", "check": "CRITICAL: DB port exposed to internet"},
        "redis": {"type": "Redis Exposed", "check": "CRITICAL: Unauthenticated Redis instance"},
        "mongodb": {"type": "MongoDB Exposed", "check": "CRITICAL: Unauthenticated MongoDB"},
        "ftp": {"type": "FTP Service", "check": "Check for anonymous FTP login"},
        "smtp": {"type": "SMTP Service", "check": "Check for Open Relay"},
        "microsoft": {"type": "Windows Service", "check": "Version fingerprinting for patch gap analysis"},
    }

    async def grab_banner(self, host: str, port: int) -> str | None:
        """Attempts to grab a banner from a specific host:port via raw TCP."""
        try:
            loop = asyncio.get_event_loop()
            
            def _grab():
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(self.TIMEOUT)
                    s.connect((host, port))
                    banner = b""
                    # Send HTTP request for web ports, else just read
                    if port in [80, 8080, 8443, 443]:
                        s.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                    banner = s.recv(1024)
                    s.close()
                    return banner.decode('utf-8', errors='ignore')
                except: return None
            
            return await loop.run_in_executor(None, _grab)
        except: return None

    async def run_fingerprinting(self, host: str, open_ports: list = None) -> list:
        """
        Runs Banner Grabbing on discovered open ports and returns intelligence findings.
        This is the OSINT Resiliency failover when API keys are missing.
        """
        console.print(f"[bold cyan][🔍] Banner Grabber: Active fingerprinting {host} (API keys missing — self-reliant mode)...[/bold cyan]")
        
        ports_to_scan = open_ports or self.COMMON_PORTS
        findings = []
        
        tasks = [self.grab_banner(host, port) for port in ports_to_scan]
        banners = await asyncio.gather(*tasks, return_exceptions=True)
        
        for port, banner in zip(ports_to_scan, banners):
            if not banner or isinstance(banner, Exception): continue
            
            console.print(f"[dim green]  [+] Port {port}: {banner[:80].strip()}[/dim green]")
            
            # Intel matching
            banner_lower = banner.lower()
            for keyword, intel in self.BANNER_INTEL.items():
                if keyword in banner_lower:
                    severity = "CRITICAL" if "CRITICAL" in intel["check"] else "MEDIUM"
                    findings.append({
                        "type": intel["type"],
                        "severity": severity,
                        "cvss_score": 9.8 if severity == "CRITICAL" else 5.3,
                        "owasp": "A05:2021-Security Misconfiguration",
                        "mitre": "T1046 - Network Service Scanning",
                        "content": f"Service Fingerprint on {host}:{port} | Banner: '{banner[:120].strip()}' | {intel['check']}",
                        "remediation_fix": "Restrict exposed services via firewall. Patch to latest version. Disable unnecessary services.",
                        "impact_desc": f"Exposed service {intel['type']} on port {port} provides attack surface for exploitation.",
                        "patch_priority": "IMMEDIATE" if severity == "CRITICAL" else "HIGH"
                    })
                    break

        console.print(f"[cyan][🔍] Banner Grabber: {len(findings)} service intelligence finding(s) from {host}.[/cyan]")
        return findings
