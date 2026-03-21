import asyncio
import httpx
import re
from aura.ui.formatter import console
import os

async def hunt():
    console.print("[bold cyan]💀 AURA BUNDLE HUNT: GITLAB STRIKE (PHASE 12)[/bold cyan]")
    
    # High-value GitLab entry points
    targets = [
        "https://gitlab.com/users/sign_in",
        "https://gitlab.com/explore",
        "https://gitlab.com/gitlab-org/gitlab"
    ]
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    bundles = set()
    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        for url in targets:
            try:
                console.print(f"[*] Scouting {url}...")
                resp = await client.get(url, headers=headers)
                # Find JS bundles (webpack/vite/etc)
                matches = re.findall(r'src=["\']([^"\']+\.js\??[^"\']*)["\']', resp.text)
                for m in matches:
                    if not m.startswith("http"):
                        m = "https://gitlab.com" + (m if m.startswith("/") else "/" + m)
                    bundles.add(m)
            except Exception as e:
                console.print(f"  [red]Error scouting {url}: {e}[/red]")

    console.print(f"\n[bold green][!] IDENTIFIED {len(bundles)} UNIQUE BUNDLES[/bold green]")
    
    # Save for mining
    with open("gitlab_bundles.txt", "w") as f:
        for b in bundles:
            f.write(b + "\n")
            console.print(f"  [white]{b}[/white]")

if __name__ == "__main__":
    asyncio.run(hunt())
