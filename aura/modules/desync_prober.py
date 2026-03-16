"""
Aura v51.0 — DesyncProber (Deep-Sea Protocol) 🌊💀
==================================================
Automated HTTP Request Smuggling detection engine.
Uses Nexus Go core for high-precision desync discovery.
"""
import asyncio
from typing import List, Dict, Any
from rich.console import Console
from rich.panel import Panel
from aura.core.nexus_bridge import NexusBridge
from aura.core.storage import AuraStorage

console = Console()

class DesyncProber:
    """
    v51.0 OMEGA: DesyncProber.
    Exploits discrepancies between front-end and back-end HTTP parsers.
    """

    def __init__(self, storage: AuraStorage):
        self.bridge = NexusBridge()
        self.storage = storage
        self.findings = []

    async def audit_endpoints(self, urls: List[str], timeout: int = 5000):
        """Audits a list of URLs for HTTP Request Smuggling potential."""
        console.print(f"[bold cyan][DesyncProber] Auditing {len(urls)} endpoints for Smuggling/Desync...[/bold cyan]")
        
        # We process these in small batches to avoid overwhelming the bridge/network
        batch_size = 5
        for i in range(0, len(urls), batch_size):
            batch = urls[i:i+batch_size]
            tasks = [self._check_url(u, timeout) for u in batch]
            await asyncio.gather(*tasks)

    async def _check_url(self, url: str, timeout: int):
        """Checks a single URL using the Nexus Go core."""
        console.print(f"[dim]  [*] Analyzing {url}...[/dim]")
        
        # Run the smuggle check via Nexus Go
        # This is a blocking call within the thread pool usually, 
        # but here we call it directly as a subprocess via the bridge.
        results = await asyncio.to_thread(self.bridge.smuggle_check, url, timeout)
        
        if not results:
            return

        for r in results:
            evidence = f"Potential {r['type']} Vulnerability\nProof: {r['proof']}"
            console.print(Panel(evidence, title="[bold red]CRITICAL: HTTP REQUEST SMUGGLING[/bold red]", border_style="red"))
            
            self.storage.add_finding(
                target_value=url,
                content=evidence,
                finding_type="HTTP Request Smuggling",
                proof=r['proof']
            )
            self.findings.append(r)

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        # Mock storage for CLI test
        class MockStorage:
            def add_finding(self, **kwargs): print(f"Finding logged: {kwargs}")
        
        asyncio.run(DesyncProber(MockStorage()).audit_endpoints(sys.argv[1:]))
