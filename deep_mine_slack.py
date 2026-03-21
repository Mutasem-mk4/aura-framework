import asyncio
import httpx
import re
import json
import os
from aura.ui.formatter import console

# Industrial-grade Regex Patterns for Slack Strike
PATTERNS = {
    "Internal API Paths": r'/(?:api|v[0-9]|flannel)/[\w\-\/]+',
    "Slack Internal Endpoints": r'https?://(?:[\w\-]+\.)*slack\.(?:internal|corp)[\w\-\.\/]+',
    "Legacy API Tokens": r'xox(?:p|b|a|n|s|r)-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,}',
    "Hardcoded Secrets": r'(?:SECRET|TOKEN|auth_token|client_secret|access_token|aws_secret|slack_webhook|vault_token)[\s:=]+["\']([\w\-\.\/]{10,})["\']',
    "Internal Comments & TODOs": r'//\s*(?:TODO|FIXME|HACK|WTF|internal|REMOVEME)[\s:]+(.*)',
    "RPC & Command Logic": r'[\"\'](?:rpc|flannel|api\.slack\.com|method|call)[\"\']',
    "Cloud Metadata/IPs": r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b'
}

async def fetch_and_mine(client: httpx.AsyncClient, url: str) -> dict:
    try:
        console.print(f"[*] Mining -> {url.split('/')[-1]}...")
        resp = await client.get(url, timeout=20)
        if resp.status_code != 200:
            return {}
        
        content = resp.text
        findings = {}
        for key, pattern in PATTERNS.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                 findings[key] = list(set(matches))
        return findings
    except Exception as e:
        console.print(f"  [red]Error mining {url}: {e}[/red]")
        return {}

async def main():
    console.print("[bold cyan]💀 AURA DEEP MINE: SLACK STRIKE (PHASE 4)[/bold cyan]")
    
    if not os.path.exists("slack_bundles.txt"):
        console.print("[red]Error: slack_bundles.txt not found. Run hunt_slack.py first.[/red]")
        return

    with open("slack_bundles.txt", "r") as f:
        urls = [line.strip() for line in f if line.strip()]

    all_findings = {}
    async with httpx.AsyncClient(verify=False) as client:
        batch_size = 5
        for i in range(0, len(urls), batch_size):
            batch = urls[i:i + batch_size]
            tasks = [fetch_and_mine(client, url) for url in batch]
            results = await asyncio.gather(*tasks)
            
            for res in results:
                if not isinstance(res, dict): continue
                for k, v in res.items():
                    console.print(f"  [yellow][!] Found {len(v)} matches for {k}[/yellow]")
                    if k not in all_findings:
                        all_findings[k] = []
                    all_findings[k].extend(v)
            
            # for key in all_findings:
            #    all_findings[key] = list(set(all_findings[key]))

    # Final Output
    output_path = "slack_phase4_recon.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(all_findings, f, indent=4)
    
    total_findings = sum(len(v) for v in all_findings.values())
    console.print(f"\n[bold green][!] RECON COMPLETE. Found {total_findings} potential leaks across {len(urls)} bundles.[/bold green]")
    console.print(f"[*] Results saved to: {output_path}")

if __name__ == "__main__":
    asyncio.run(main())
