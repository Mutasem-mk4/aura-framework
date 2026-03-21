import asyncio
import socket
import json
import logging
from typing import List, Dict, Any, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from aura.core.nexus_bridge import NexusBridge

from aura.ui.formatter import console
logger = logging.getLogger("aura")

class NativePortScanner:
    """
    v50.0 OMEGA: Native Port Scanning Engine.
    Replaces Nmap CLI with high-speed asynchronous TCP probing and banner grabbing.
    """
    
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 873, 993, 995, 1080, 1433, 
        1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9000, 9200, 27017
    ]

    def __init__(self, timeout: float = 1.5, concurrency: int = 100):
        self.timeout = timeout
        self.concurrency = concurrency
        try:
            self.nexus = NexusBridge()
        except:
            self.nexus = None

    async def scan(self, ip: str, ports: List[int] = None) -> List[Dict[str, Any]]:
        """Scans a list of ports using Nexus (Go) or native fallback."""
        if not ports:
            ports = self.COMMON_PORTS
            
        console.print(f"[cyan][🛡️ Scanner] Starting native scan for {ip}...[/cyan]")
        
        if self.nexus:
            console.print("[yellow][⚡] Nexus Core Active: Accelerating scan with Go engines...[/yellow]")
            # Go timeout is in ms
            return self.nexus.scan_ports(ip, ports, self.concurrency, int(self.timeout * 1000))
        
        # Native Fallback
        results = []
        sem = asyncio.Semaphore(self.concurrency)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task(f"Scanning {ip}...", total=len(ports))
            
            async def probe(port):
                async with sem:
                    res = await self.probe_port(ip, port)
                    if res["state"] == "open":
                        results.append(res)
                    progress.advance(task)

            await asyncio.gather(*[probe(p) for p in ports])
            
        console.print(f"[bold green][+] Scan Complete: {len(results)} open ports identified on {ip}.[/bold green]")
        return sorted(results, key=lambda x: x["port"])

    async def probe_port(self, ip: str, port: int) -> Dict[str, Any]:
        """Probes a single port for open state and grabs banner."""
        result = {
            "port": port,
            "state": "closed",
            "service": self._guess_service(port),
            "banner": ""
        }
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), 
                timeout=self.timeout
            )
            result["state"] = "open"
            
            # Attempt banner grab
            try:
                # Some services talk first (SSH, FTP), some need a nudge (HTTP)
                if port in [80, 443, 8080, 8443]:
                    writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    await writer.drain()
                
                banner_data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                if banner_data:
                    banner_text = banner_data.decode('utf-8', errors='ignore').strip()
                    result["banner"] = banner_text
                    # Refining service based on banner
                    result["service"] = self._refine_service(result["service"], banner_text)
            except Exception:
                pass
            finally:
                writer.close()
                await writer.wait_closed()
        except Exception:
            pass
            
        return result

    def _guess_service(self, port: int) -> str:
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 443: "HTTPS", 445: "Microsoft-DS", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
            27017: "MongoDB"
        }
        return services.get(port, "unknown")

    def _refine_service(self, current: str, banner: str) -> str:
        banner_low = banner.lower()
        if "ssh" in banner_low: return "SSH"
        if "ftp" in banner_low: return "FTP"
        if "http" in banner_low or "html" in banner_low: return "HTTP/HTTPS"
        if "mysql" in banner_low: return "MySQL"
        return current

if __name__ == "__main__":
    import sys
    async def main():
        ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
        scanner = NativePortScanner()
        results = await scanner.scan(ip)
        print(json.dumps(results, indent=2))
    
    asyncio.run(main())
