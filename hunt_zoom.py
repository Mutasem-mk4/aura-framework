import asyncio
import httpx
import re
from aura.ui.formatter import console
import os

async def hunt():
    console.print("[bold cyan]💀 AURA BUNDLE HUNT: ZOOM STRIKE (PHASE 7)[/bold cyan]")
    
    # High-value Zoom entry points
    targets = [
        "https://zoom.us",
        "https://zoom.us/join",
        "https://zoom.us/signin",
        "https://app.zoom.us/wc/join"
    ]
    
    all_bundles = set()
    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        for url in targets:
            try:
                console.print(f"[*] Scouting -> {url}")
                resp = await client.get(url, timeout=20)
                if resp.status_code != 200: continue
                
                content = resp.text
                # Find all script tags
                bundles = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', content)
                
                # Filter/Normalize
                zoom_bundles = []
                for b in bundles:
                    if "zoom" in b.lower() or "app" in b.lower() or "wc" in b.lower() or "static" in b.lower():
                        if b.startswith("//"): b = "https:" + b
                        elif b.startswith("/"): b = "https://zoom.us" + b
                        zoom_bundles.append(b)
                
                all_bundles.update(zoom_bundles)
                console.print(f"  [+] Found {len(zoom_bundles)} potential bundles.")
            except Exception as e:
                console.print(f"  [red]Error scouting {url}: {e}[/red]")

    # Save
    output_file = "zoom_bundles.txt"
    with open(output_file, "w") as f:
        for b in sorted(all_bundles):
            f.write(f"{b}\n")
    
    console.print(f"\n[bold green][!] Total unique bundles found: {len(all_bundles)}[/bold green]")
    console.print(f"[*] Bundle list saved to: {output_file}")

if __name__ == "__main__":
    asyncio.run(hunt())
