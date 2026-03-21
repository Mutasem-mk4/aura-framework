import asyncio
import httpx
from aura.ui.formatter import console

async def read_env_header(url):
    console.print(f"[*] Reading .env header -> {url}")
    try:
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            r = await client.get(url)
            if r.status_code == 200:
                console.print(f"    Preview (500 chars):")
                console.print(f"    {r.text[:500]}")
            else:
                console.print(f"  [red][!] Failed: {r.status_code}[/red]")
    except Exception as e:
        console.print(f"  [red][!] Error: {e}[/red]")

if __name__ == "__main__":
    asyncio.run(read_env_header("https://status.blockscout.com/.env"))
