import asyncio
import httpx
import re
from aura.ui.formatter import console

async def get_subdomains_crtsh(domain):
    console.print(f"[*] Orion: Fetching subdomains for {domain} from CRT.sh...")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains = set()
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.get(url)
            if r.status_code == 200:
                data = r.json()
                for entry in data:
                    name = entry['name_value']
                    if "\n" in name:
                        for sub in name.split("\n"):
                            subdomains.add(sub.strip().replace("*.", ""))
                    else:
                        subdomains.add(name.strip().replace("*.", ""))
                console.print(f"  [green][+] Found {len(subdomains)} unique subdomains for {domain}[/green]")
            else:
                console.print(f"  [red][-] CRT.sh failed: {r.status_code}[/red]")
    except Exception as e:
        console.print(f"  [red][!] Error: {e}[/red]")
    return subdomains

async def main():
    targets = ["blockscout.com", "indorse.io", "syfe.com"]
    all_subs = []
    for t in targets:
        subs = await get_subdomains_crtsh(t)
        all_subs.extend(list(subs))
    
    # Save to file
    import json
    save_path = r"c:\Users\User\.gemini\antigravity\scratch\aura\reports\scavenger_targets_v2.json"
    with open(save_path, "w") as f:
        json.dump(all_subs, f, indent=4)
    console.print(f"\n[bold green][!!] PHASE 2 RECON COMPLETE. Target list saved to {save_path}[/bold green]")

if __name__ == "__main__":
    asyncio.run(main())
