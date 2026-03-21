import asyncio
import httpx
import re
import json
import os
from aura.ui.formatter import console

# Industrial-grade Regex Patterns for GitLab Strike
PATTERNS = {
    "GraphQL Fragments & Queries": r'(?:query|mutation)\s+([a-zA-Z0-9_]+)\s*\{',
    "Internal API & Routes": r'/(?:api/v4/|/-/|/internal/)[a-zA-Z0-9\-\_/]+',
    "Feature Flags (GitLab)": r'(?:feature_flag|gon\.features)\.([a-zA-Z0-9_]+)',
    "Env/Config Leaks": r'gon\.(?:[a-zA-Z0-9_]+)\s*=\s*(\{.*?\})',
    "Sensitive Keywords": r'(?:secret|token|password|auth|key|cred)[a-zA-Z0-9\-_]{16,}'
}

async def mine_bundle(client, url):
    try:
        console.print(f"[*] Mining {url}...")
        resp = await client.get(url)
        content = resp.text
        
        bundle_findings = {}
        for name, pattern in PATTERNS.items():
            matches = re.findall(pattern, content)
            if matches:
                bundle_findings[name] = list(set(matches))
        
        return bundle_findings
    except Exception as e:
        console.print(f"  [red]Error mining {url}: {e}[/red]")
        return {}

async def main():
    if not os.path.exists("gitlab_bundles.txt"):
        console.print("[red]No bundles found. Run hunt_gitlab.py first.[/red]")
        return

    with open("gitlab_bundles.txt", "r") as f:
        bundles = [line.strip() for line in f if line.strip()]

    all_findings = {}
    async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
        tasks = [mine_bundle(client, b) for b in bundles]
        results = await asyncio.gather(*tasks)
        
        for i, res in enumerate(results):
            if res:
                all_findings[bundles[i]] = res

    # Save results
    output_path = "C:\\Users\\User\\Desktop\\gitlab_phase12_recon.json" # Place on desktop for visibility as requested before
    # Better: place in scratch as per latest instructions
    output_path = "C:\\Users\\User\\.gemini\\antigravity\\scratch\\aura\\gitlab_phase12_recon.json"
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(all_findings, f, indent=4)

    # Summary report
    console.print(f"\n[bold green][!] DEEP MINE COMPLETE[/bold green]")
    total_leaks = sum(len(v) for b in all_findings.values() for v in b.values())
    console.print(f"  [+] Total potential leaks identified: {total_leaks}")
    
    # Highlight specific findings
    for bundle, data in all_findings.items():
        if "GraphQL Fragments & Queries" in data:
            console.print(f"  [bold yellow][!] FOUND {len(data['GraphQL Fragments & Queries'])} GRAPHQL QUERIES in {os.path.basename(bundle)}[/bold yellow]")
        if "Feature Flags (GitLab)" in data:
            console.print(f"  [bold yellow][!] FOUND {len(data['Feature Flags (GitLab)'])} FEATURE FLAGS in {os.path.basename(bundle)}[/bold yellow]")

if __name__ == "__main__":
    asyncio.run(main())
