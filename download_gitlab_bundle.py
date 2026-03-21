import asyncio
import httpx
from aura.ui.formatter import console

async def download():
    url = "https://gitlab.com/assets/webpack/main.bc0c9c49.chunk.js"
    output = "C:\\Users\\User\\.gemini\\antigravity\\scratch\\aura\\main.bc0c9c49.chunk.js"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
    
    async with httpx.AsyncClient(verify=False) as client:
        try:
            console.print(f"[*] Downloading {url}...")
            resp = await client.get(url, headers=headers)
            with open(output, "w", encoding="utf-8") as f:
                f.write(resp.text)
            console.print(f"[bold green][!] SUCCESS: Bundle saved to {output}[/bold green]")
        except Exception as e:
            console.print(f"  [red]Error: {e}[/red]")

if __name__ == "__main__":
    asyncio.run(download())
