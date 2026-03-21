import asyncio
import httpx
import re
from aura.ui.formatter import console
import os

async def hunt():
    console.print("[bold cyan]💀 AURA BUNDLE HUNT: MICROSOFT ENTRA STRIKE (PHASE 8)[/bold cyan]")
    
    # High-value Entra entry points
    targets = [
        "https://login.microsoftonline.com",
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "https://login.microsoftonline.com/common/reprocess"
    ]
    
    all_bundles = set()
    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        for url in targets:
            try:
                console.print(f"[*] Scouting -> {url}")
                # We use a common User-Agent to avoid generic blocks
                headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
                resp = await client.get(url, headers=headers, timeout=20)
                if resp.status_code not in [200, 401]: continue # 401 is common for direct auth URLs
                
                content = resp.text
                # Find all script tags
                bundles = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', content)
                
                # Filter/Normalize
                entra_bundles = []
                for b in bundles:
                    # Focus on MS bundles (often on cdn-origin or similar)
                    if "microsoft" in b.lower() or "aad" in b.lower() or "login" in b.lower() or "converged" in b.lower():
                        if b.startswith("//"): b = "https:" + b
                        elif b.startswith("/"): b = "https://login.microsoftonline.com" + b
                        entra_bundles.append(b)
                
                all_bundles.update(entra_bundles)
                console.print(f"  [+] Found {len(entra_bundles)} potential Entra bundles.")
            except Exception as e:
                console.print(f"  [red]Error scouting {url}: {e}[/red]")

    # Save
    output_file = "entra_bundles.txt"
    with open(output_file, "w") as f:
        for b in sorted(all_bundles):
            f.write(f"{b}\n")
    
    console.print(f"\n[bold green][!] Total unique bundles found: {len(all_bundles)}[/bold green]")
    console.print(f"[*] Bundle list saved to: {output_file}")

if __name__ == "__main__":
    asyncio.run(hunt())
