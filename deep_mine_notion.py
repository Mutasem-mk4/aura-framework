import asyncio
import httpx
import re
import os
from aura.ui.formatter import console

PATTERNS = {
    "Notion Internal APIs": r'/api/v3/[a-zA-Z0-9\-\_/]+',
    "Internal Flags": r'INTERNAL_[a-zA-Z0-9_]+',
    "Workspace Metadata": r'workspace[a-zA-Z0-9_]+'
}

async def mine_bundle(client, url):
    try:
        resp = await client.get(url)
        content = resp.text
        findings = {}
        for name, pattern in PATTERNS.items():
            matches = re.findall(pattern, content)
            if matches:
                findings[name] = list(set(matches))
        return findings
    except:
        return {}

async def main():
    if not os.path.exists("notion_bundles.txt"): return
    with open("notion_bundles.txt", "r") as f:
        bundles = [line.strip() for line in f if line.strip()]
    
    async with httpx.AsyncClient(verify=False) as client:
        tasks = [mine_bundle(client, b) for b in bundles]
        results = await asyncio.gather(*tasks)
        
        for i, res in enumerate(results):
            if res:
                console.print(f"[bold yellow][!] FOUND {len(res)} CATEGORIES IN {os.path.basename(bundles[i])}[/bold yellow]")
                for k, v in res.items():
                    console.print(f"  [+] {k}: {len(v)} findings")

if __name__ == "__main__":
    asyncio.run(main())
