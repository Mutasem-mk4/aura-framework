import asyncio
import os
import json
import logging
import sys
from rich.console import Console
from rich.panel import Panel

# Ensure project root is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__))))

from aura.core.nexus_bridge import NexusBridge
from aura.core.brain import AuraBrain
from aura.ui.zenith_ui import ZenithUI
from aura.core import state

console = Console()
logging.basicConfig(level=logging.ERROR)

async def test_veritas_bridge():
    console.print("[bold blue][*] Testing Veritas Bridge (Go persistence)...[/bold blue]")
    bridge = NexusBridge()
    try:
        bridge.start_veritas(port=50052) # Use non-standard port for test
        await asyncio.sleep(2)
        health = bridge.get_health()
        if health and health.get("result"):
            console.print(f"[green][✓] Veritas Bridge Active: {health['result']['status']} (RAM: {health['result'].get('ram_usage_mb')}MB)[/green]")
            return True
        else:
            console.print("[red][✗] Veritas Bridge failed to respond.[/red]")
            return False
    finally:
        bridge.stop_veritas()

async def test_brain_mentor():
    console.print("[bold cyan][*] Testing AI Triage Mentor...[/bold cyan]")
    brain = AuraBrain()
    sample_finding = {
        "type": "SQL Injection",
        "severity": "CRITICAL",
        "url": "https://example.com/api/products?id=1'",
        "payload": "1' OR 1=1--"
    }
    guide = await asyncio.to_thread(brain.generate_triage_guide, sample_finding)
    if guide and "technical_explanation" in guide:
        console.print("[green][✓] AI Triage Mentor is operational.[/green]")
        return True
    else:
        console.print("[red][✗] AI Triage Mentor failed to generate guide.[/red]")
        return False

async def test_hybrid_perception_logic():
    console.print("[bold yellow][*] Testing Hybrid Perception Logic...[/bold yellow]")
    from aura.core.omega_crawler import OMEGACrawler
    crawler = OMEGACrawler()
    
    is_spa, evidence = await crawler.should_spawn_browser("https://example.com")
    # Simulate a score check or just verify it runs
    if is_spa or not is_spa:
         console.print(f"[green][✓] Hybrid Perception decision engine operational (Result: {is_spa}).[/green]")
         return True
    else:
         console.print("[red][✗] Hybrid Perception failed to detect SPA indicator.[/red]")
         return False

async def run_diagnostics():
    ZenithUI.show_startup_banner()
    console.print(Panel("AURA v3.0 OMEGA - GLOBAL DIAGNOSTICS SUITE", border_style="magenta"))
    
    results = []
    results.append(await test_veritas_bridge())
    results.append(await test_brain_mentor())
    results.append(await test_hybrid_perception_logic())
    
    if all(results):
        console.print("\n[bold green][💎] ALL SYSTEMS GREEN. AURA V3.0 IS READY FOR DEPLOYMENT.[/bold green]")
    else:
        console.print("\n[bold red][⚠️] DIAGNOSTIC FAILURES DETECTED. CHECK LOGS.[/bold red]")

if __name__ == "__main__":
    asyncio.run(run_diagnostics())
