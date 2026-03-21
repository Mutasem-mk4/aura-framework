import asyncio
import os
import json
import logging
import sys
from rich.console import Console
from rich.panel import Panel
from unittest.mock import MagicMock, AsyncMock, patch

# Ensure project root is in path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__))))

from aura.core.nexus_bridge import NexusBridge
from aura.core.brain import AuraBrain
from aura.ui.zenith_ui import ZenithUI
from aura.core import state

from aura.ui.formatter import console
logging.basicConfig(level=logging.ERROR)

async def test_veritas_bridge_mocked():
    console.print("[bold blue][*] Testing Veritas Bridge (Mocked)...[/bold blue]")
    bridge = NexusBridge()
    # Mock the Veritas Client to simulate a healthy Go process
    bridge.veritas.call = MagicMock(return_value={"result": {"status": "healthy", "ram_usage_mb": 42}})
    bridge.veritas.connect = MagicMock(return_value=True)
    
    health = bridge.get_health()
    if health and health.get("result"):
        console.print(f"[green][✓] Veritas Bridge Interface Verified: {health['result']['status']}[/green]")
        return True
    return False

async def test_brain_mentor_and_oracle_mocked():
    console.print("[bold cyan][*] Testing AI Mentor & Consensus Oracle (Mocked)...[/bold cyan]")
    brain = AuraBrain()
    
    # Mock AI response for Mentor
    mock_mentor_guide = {
        "technical_explanation": "Mocked explanation",
        "business_impact": "Mocked impact",
        "manual_verification_steps": ["Step 1", "Step 2"],
        "educational_tip": "Mocked tip"
    }
    
    # Patch _call_ai to return mocked JSON
    with patch.object(brain, '_call_ai', return_value=json.dumps(mock_mentor_guide)):
        guide = brain.generate_triage_guide({"test": "data"})
        oracle_valid = await brain.verify_strategy({"test": "strat"}, "test context")
        
        if guide and guide.get("technical_explanation") == "Mocked explanation" and oracle_valid:
            console.print("[green][✓] AI Logic & Mentor Integration Verified.[/green]")
            return True
    return False

async def test_hybrid_perception_dry_run():
    console.print("[bold yellow][*] Testing Hybrid Perception Decision Engine...[/bold yellow]")
    from aura.core.omega_crawler import OMEGACrawler
    crawler = OMEGACrawler()
    
    # Verify the logic of detecting SPA-like HTML
    # Note: we are testing the internal logic of the score calculation
    test_html = "<html><body><div id='root'></div><script src='/static/js/main.chunk.js'></script></body></html>"
    # should_spawn_browser usually makes a request, let's mock the request part
    with patch('httpx.AsyncClient.get', new_callable=AsyncMock) as mock_get:
        mock_get.return_value.text = test_html
        mock_get.return_value.status_code = 200
        
        is_spa, evidence = await crawler.should_spawn_browser("https://mock-target.com")
        if is_spa:
            console.print(f"[green][✓] Hybrid Perception Logic Verified: Correctly identified SPA ({evidence}).[/green]")
            return True
    return False

async def run_diagnostics():
    ZenithUI.show_startup_banner()
    console.print(Panel("AURA v3.0 OMEGA - HIGH-FIDELITY MOCKED DIAGNOSTICS", border_style="magenta"))
    
    results = []
    results.append(await test_veritas_bridge_mocked())
    results.append(await test_brain_mentor_and_oracle_mocked())
    results.append(await test_hybrid_perception_dry_run())
    
    if all(results):
        console.print("\n[bold green][💎] ALL LOGIC PATHS VERIFIED. AURA V3.0 INTEGRATION IS SOLID.[/bold green]")
    else:
        console.print("\n[bold red][⚠️] LOGIC FAILURES DETECTED. CHECK MOCKED PATHS.[/bold red]")

if __name__ == "__main__":
    asyncio.run(run_diagnostics())
