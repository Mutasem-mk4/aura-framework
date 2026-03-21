import asyncio
import httpx
from aura.ui.formatter import console

async def download():
    url = "https://auth.uber.com/login/static/js/main.bc0c9c49.js.map"
    output = "C:\\Users\\User\\.gemini\\antigravity\\scratch\\aura\\uber_main.js.map"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
    
    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        try:
            console.print(f"[*] Downloading {url}...")
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                with open(output, "w", encoding="utf-8") as f:
                    f.write(resp.text)
                console.print(f"[bold green][!] SUCCESS: Uber Source Map saved to {output}[/bold green]")
            else:
                console.print(f"  [red]Error: Download failed with status {resp.status_code}[/red]")
        except Exception as e:
            console.print(f"  [red]Error: {e}[/red]")

if __name__ == "__main__":
    asyncio.run(download())
