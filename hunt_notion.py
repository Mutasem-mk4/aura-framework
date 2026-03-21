import asyncio
import httpx
import re
from aura.ui.formatter import console

async def hunt():
    console.print("[bold cyan]💀 AURA BUNDLE HUNT: NOTION STRIKE (PHASE 20)[/bold cyan]")
    targets = [
        "https://www.notion.so/login",
        "https://www.notion.so/product"
    ]
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}

    bundles = set()
    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        for url in targets:
            try:
                console.print(f"[*] Scouting {url}...")
                resp = await client.get(url, headers=headers)
                matches = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', resp.text)
                for m in matches:
                    if not m.startswith("http"):
                        m = "https://www.notion.so" + (m if m.startswith("/") else "/" + m)
                    bundles.add(m)
            except Exception as e:
                console.print(f"  [red]Error: {e}[/red]")

    console.print(f"\n[bold green][!] IDENTIFIED {len(bundles)} UNIQUE NOTION BUNDLES[/bold green]")
    with open("notion_bundles.txt", "w") as f:
        for b in bundles:
            f.write(b + "\n")
            console.print(f"  [white]{b}[/white]")

if __name__ == "__main__":
    asyncio.run(hunt())
