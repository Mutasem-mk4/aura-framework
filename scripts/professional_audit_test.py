import asyncio
import os
import sys
import json
from rich.console import Console

# Ensure Aura is in the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from aura.modules.api_reaper import APIReaper
from aura.modules.frontend_deconstructor import FrontendDeconstructor
from aura.modules.graphql_reaper import GraphQLReaper

from aura.ui.formatter import console

async def test_api_reaper():
    """Verify API Reaper's spec ingestion and parameter mapping."""
    console.print("[bold cyan][TEST] Sector: API Reaper (Spec Deconstruction)...[/bold cyan]")
    reaper = APIReaper(None)
    
    # Mock Swagger Spec
    mock_spec = {
        "paths": {
            "/api/v1/user": {
                "get": {"parameters": [{"name": "id", "schema": {"type": "integer"}}]},
                "post": {"requestBody": {"content": {"application/json": {"schema": {"properties": {"name": {"type": "string"}, "is_admin": {"type": "boolean"}}}}}}}
            }
        }
    }
    
    await reaper._parse_spec(mock_spec, "https://api.test.local")
    
    if len(reaper.endpoints) == 2 and reaper.endpoints[1]["params"].get("is_admin") is False:
        console.print("[bold green]  [✓] API Reaper successfully mapped endpoints and privileged parameters.[/bold green]")
        return True
    return False

async def test_frontend_deconstructor():
    """Verify JS mining and hidden endpoint extraction."""
    console.print("[bold cyan][TEST] Sector: Frontend Deconstructor (AST Mining)...[/bold cyan]")
    deconstructor = FrontendDeconstructor(None)
    
    mock_js = "const url = '/api/v1/internal/config'; let key = 'AIzaSyA1234567890123456789012345678901';"
    deconstructor._mine_text(mock_js, "app.js")
    
    results = deconstructor.get_results()
    console.print(f"[dim]  Debug - Endpoints: {results['endpoints']}[/dim]")
    console.print(f"[dim]  Debug - Secrets: {len(results['secrets'])} found[/dim]")
    
    if "/api/v1/internal/config" in results["endpoints"] and any(s["type"] == "Google API Key" for s in results["secrets"]):
        console.print("[bold green]  [✓] Frontend Deconstructor successfully extracted hidden routes and high-value keys.[/bold green]")
        return True
    return False

async def main():
    console.print("\n[bold magenta]AURA v25.0 OMEGA — PROFESSIONAL DECONSTRUCTION TEST[/bold magenta]\n")
    results = [
        await test_api_reaper(),
        await test_frontend_deconstructor()
    ]
    
    if all(results):
        console.print("\n[bold green]✅ PROFESSIONAL SUITE IS OPERATIONAL. DECONSTRUCTION DOCTRINE VALIDATED.[/bold green]\n")
    else:
        console.print("\n[bold red]❌ SYSTEM INTEGRITY COMPROMISED. REVIEW PROFESSIONAL SECTORS.[/bold red]\n")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
