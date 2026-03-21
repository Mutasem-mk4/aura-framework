import asyncio
import httpx
import re
from aura.ui.formatter import console

async def hunt_latest():
    console.print("[bold cyan]💀 AURA LATEST HUNT: UBER AUTH[/bold cyan]")
    url = "https://auth.uber.com/login/"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
    
    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        try:
            resp = await client.get(url, headers=headers)
            # Match any .js file
            matches = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', resp.text)
            for m in matches:
                if "static" in m or "auth" in m:
                    if not m.startswith("http"):
                        m = "https://auth.uber.com" + (m if m.startswith("/") else "/" + m)
                    console.print(f"  [green][+] Found Latest Bundle: {m}[/green]")
                    # Try map
                    map_url = m + ".map"
                    map_resp = await client.head(map_url, headers=headers)
                    if map_resp.status_code == 200:
                        console.print(f"    [bold green][!] ALERT: Source Map FOUND at {map_url}[/bold green]")
        except Exception as e:
            console.print(f"  [red]Error: {e}[/red]")

if __name__ == "__main__":
    asyncio.run(hunt_latest())
