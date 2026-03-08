import asyncio
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
from aura.core.orchestrator import NeuralOrchestrator
from rich.console import Console

console = Console()

async def test_chaining():
    console.print("[+] Initializing Neural Orchestrator for Chaining Test...")
    orc = NeuralOrchestrator()
    
    domain = "vulnerable-target.com"
    
    # Simulate finding an Open Redirect
    console.print("[*] Simulating Discovery: Open Redirect at /redirect?url=...")
    redirect_finding = {
        "type": "Open Redirect",
        "evidence_url": "http://vulnerable-target.com/redirect"
    }
    await orc._process_exploit_chain(domain, "Open Redirect", redirect_finding)
    
    # Simulate finding an SSRF sink
    console.print("[*] Simulating Discovery: SSRF Sink at /api/fetch?url=...")
    ssrf_finding = {
        "type": "SSRF",
        "evidence_url": "http://vulnerable-target.com/api/fetch"
    }
    chain_result = await orc._process_exploit_chain(domain, "SSRF", ssrf_finding)
    
    if chain_result:
        console.print(f"\n[green]SUCCESS: Exploit Chain Synthesized![/green]")
        console.print(f"Type: {chain_result['type']}")
        console.print(f"Chained Payload: {chain_result['evidence_url']}")
    else:
        console.print("\n[red]FAILED: Exploit chain not synthesized.[/red]")

if __name__ == "__main__":
    asyncio.run(test_chaining())
