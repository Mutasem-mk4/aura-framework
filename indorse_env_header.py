import asyncio
import httpx
from aura.ui.formatter import console

async def read_env_header(url):
    console.print(f"[*] Reading .env header -> {url}")
    try:
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            r = await client.get(url)
            if r.status_code == 200:
                lines = r.text.splitlines()[:100]
                for l in lines:
                    console.print(f"    {l}")
            else:
                console.print(f"  [red][!] Failed: {r.status_code}[/red]")
    except Exception as e:
        console.print(f"  [red][!] Error: {e}[/red]")

if __name__ == "__main__":
    asyncio.run(read_env_header("https://indorse.io/.env"))
