import asyncio
import httpx
import re
import json
import os
from aura.ui.formatter import console

# Industrial-grade Regex Patterns for Airbnb Strike
PATTERNS = {
    "Internal API Paths": r'/(?:api|v[0-9])/[\w\-\/]+',
    "Airbnb Internal Endpoints": r'https?://(?:[\w\-]+\.)*airbnb\.internal[\w\-\.\/]+',
    "Hardcoded Secrets": r'(?:api_key|SECRET|TOKEN|auth_token|client_secret|access_token|aws_secret|slack_webhook|vault_token)[\s:=]+["\']([\w\-\.\/]{10,})["\']',
    "Internal Comments & TODOs": r'//\s*(?:TODO|FIXME|HACK|WTF|internal|REMOVEME)[\s:]+(.*)',
    "Feature Flags": r'[\"\'](?:is_internal|enable_experimental|dev_only|feature_flag_[\w\-]+)[\"\'][\s:]+(?:true|1)',
    "Cloud Metadata/IPs": r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b'
}

async def fetch_and_mine(client, url):
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
    console.print("[bold red]💀 AURA DEEP MINE: AIRBNB STRIKE (PHASE 3)[/bold red]")
    
    if not os.path.exists("airbnb_bundles.txt"):
        console.print("[red]Error: airbnb_bundles.txt not found. Run hunt_airbnb.py first.[/red]")
        return

    with open("airbnb_bundles.txt", "r") as f:
        urls = [line.strip() for line in f if line.strip()]

    all_findings = {}
    async with httpx.AsyncClient(verify=False) as client:
        # We process in batches to avoid overwhelming the network or CPU
        batch_size = 5
        for i in range(0, len(urls), batch_size):
            batch = urls[i:i + batch_size]
            tasks = [fetch_and_mine(client, url) for url in batch]
            results = await asyncio.gather(*tasks)
            
            for res in results:
                for k, v in res.items():
                    if k not in all_findings:
                        all_findings[k] = []
                    all_findings[k].extend(v)
            
            # De-duplicate each category
            for k in all_findings:
                all_findings[k] = list(set(all_findings[k]))

    # Final Output
    output_path = "airbnb_phase3_recon.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(all_findings, f, indent=4)
    
    console.print(f"\n[bold green][!] RECON COMPLETE. Found {sum(len(v) for v in all_findings.values())} potential leaks across {len(urls)} bundles.[/bold green]")
    console.print(f"[*] Results saved to: {output_path}")

if __name__ == "__main__":
    asyncio.run(main())
