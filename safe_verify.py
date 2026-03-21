import asyncio
import httpx
from aura.ui.formatter import console

async def verify_uber():
    console.print("[bold cyan]🛡️ SAFE VERIFY: UBER SOURCE MAP[/bold cyan]")
    url = "https://auth.uber.com/static/js/main.bc0c9c49.js.map" # Example path from previous recon
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
    
    async with httpx.AsyncClient(verify=False) as client:
        try:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200 and '"sources":' in resp.text:
                console.print(f"  [bold green][!] SUCCESS: Source Map identified and accessible on {url}[/bold green]")
                console.print(f"  [white]First 100 bytes: {resp.text[:100]}[/white]")
            else:
                console.print(f"  [yellow][?] Source map not found or restricted (Status: {resp.status_code})[/yellow]")
        except Exception as e:
            console.print(f"  [red]Error: {e}[/red]")

async def verify_discord():
    console.print("\n[bold cyan]🛡️ SAFE VERIFY: DISCORD EXPERIMENTS[/bold cyan]")
    url = "https://discord.com/api/v9/experiments"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
    
    async with httpx.AsyncClient(verify=False) as client:
        try:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                console.print(f"  [bold green][!] SUCCESS: Experiments API accessible.[/bold green]")
                if "STAFF_ONLY" in resp.text or "INTERNAL_EMPLOYEE" in resp.text:
                    console.print(f"  [bold green][!] CONFIRMED: Internal staff flags detected in response.[/bold green]")
                else:
                    console.print(f"  [yellow][?] Experiments API accessible but flags not found (Rotation?)[/yellow]")
            else:
                console.print(f"  [yellow][?] Experiments API restricted (Status: {resp.status_code})[/yellow]")
        except Exception as e:
            console.print(f"  [red]Error: {e}[/red]")

async def verify_gitlab():
    console.print("\n[bold cyan]🛡️ SAFE VERIFY: GITLAB AI DUO API[/bold cyan]")
    url = "https://gitlab.com/api/v4/ai/duo_workflows/workflows/"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
    
    async with httpx.AsyncClient(verify=False) as client:
        try:
            # HEAD request to check existence without payload
            resp = await client.head(url, headers=headers)
            if resp.status_code in [401, 403]:
                console.print(f"  [bold green][!] SUCCESS: Endpoint exists and requires auth (Status: {resp.status_code})[/bold green]")
            elif resp.status_code == 404:
                console.print(f"  [yellow][?] Endpoint not found (Likely internal-only routing or false positive).[/yellow]")
            else:
                console.print(f"  [blue][*] Unexpected status: {resp.status_code}[/blue]")
        except Exception as e:
            console.print(f"  [red]Error: {e}[/red]")

async def main():
    await verify_uber()
    await verify_discord()
    await verify_gitlab()

if __name__ == "__main__":
    asyncio.run(main())
