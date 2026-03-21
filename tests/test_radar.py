import asyncio
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
from aura.modules.threat_intel import ThreatIntel
from rich.console import Console

from aura.ui.formatter import console

async def test_0day_radar():
    console.print("[+] Initializing 0-Day Radar (ThreatIntel)...")
    intel = ThreatIntel()
    
    # Mock tech stack (Aura typically extracts this via visual analysis)
    tech_stack = ["WordPress", "PHP", "Nginx"]
    
    console.print(f"[*] Testing tech stack: {tech_stack}")
    
    # Run the radar
    found = await intel.query_github_0days(tech_stack)
    
    if found:
        console.print(f"\n[green]Radar identified {len(found)} recent PoCs![/green]")
        for f in found:
            console.print(f" - {f['tech']}: {f['repo']}")
            console.print(f"   Desc: {f['description']}")
    else:
        console.print("\n[yellow]No recent PoCs found for this stack (or rate limited).[/yellow]")

if __name__ == "__main__":
    asyncio.run(test_0day_radar())
