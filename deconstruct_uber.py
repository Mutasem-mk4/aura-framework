import asyncio
import os
import json
from aura.modules.frontend_deconstructor import FrontendDeconstructor
from aura.ui.formatter import console

async def main():
    js_url = "https://auth.uber.com/v2/_static/client-legacy-main-a25c2c3a57630f6f.js"
    target = "https://auth.uber.com"
    
    console.print(f"[bold green]🚀 Starting Raw JS Mining Strike on Uber Auth Script...[/bold green]")
    console.print(f"Target JS: {js_url}")
    
    declon = FrontendDeconstructor(target=target)
    
    import httpx
    async with httpx.AsyncClient(verify=False) as client:
        try:
            resp = await client.get(js_url, timeout=30)
            if resp.status_code == 200:
                console.print(f"[green][✓] Successfully fetched JS bundle ({len(resp.text)} bytes).[/green]")
                
                # Execute raw mining (JS AST analysis + Regex)
                await declon._mine_raw_js(resp.text, js_url)
                
                results = declon.get_results()
                
                console.print("\n[bold cyan]💎 Mining Results:[/bold cyan]")
                console.print(f"Discovered {len(results['endpoints'])} Hidden Endpoints")
                console.print(f"Discovered {len(results['secrets'])} Secrets/Keys")
                
                # Save findings to a report
                with open("uber_auth_mining_results.json", "w", encoding="utf-8") as f:
                    json.dump(results, f, indent=2)
                
                console.print(f"\n[bold yellow]Findings saved to 'uber_auth_mining_results.json'[/bold yellow]")
            else:
                console.print(f"[red]❌ Failed to fetch JS: HTTP {resp.status_code}[/red]")
        except Exception as e:
            console.print(f"[red]❌ Error during mining: {e}[/red]")

if __name__ == "__main__":
    asyncio.run(main())
