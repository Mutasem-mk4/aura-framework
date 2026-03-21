import asyncio
import httpx
import re
import json
import os
from aura.ui.formatter import console

# Industrial-grade Regex Patterns for Microsoft Entra Strike
PATTERNS = {
    "Entra API & Internal Paths": r'/(?:api/v[0-9]|v[0-9]/[\w\-\/]+|common/[\w\-\/]+)',
    "Tenant & Auth Signatures": r'[\"\'](?:tenant_id|client_id|tid|oid|preferred_username)[\"\'][\s:=]+["\']([\w\-\.]{10,})["\']',
    "OpenID / OAuth Constants": r'[\"\'](?:openid|profile|email|offline_access|prompt|nonce|state)[\"\']',
    "Internal & Beta Flags": r'[\"\'](?:Experimental|Beta|Internal|Private|SDR|Preview)[\w\-]+[\"\']',
    "Hardcoded Secrets": r'(?:SECRET|TOKEN|auth_token|client_secret|access_token|aws_secret|vault_token)[\s:=]+["\']([\w\-\.\/]{10,})["\']',
    "Architectural TODOs": r'//\s*(?:TODO|FIXME|HACK|internal|Legacy)[\s:]+(.*)',
    "VPC / Internal IPs": r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})\b'
}

async def fetch_and_mine(client: httpx.AsyncClient, url: str) -> dict:
    try:
        console.print(f"[*] Mining -> {url.split('/')[-1]}...")
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
        resp = await client.get(url, headers=headers, timeout=20)
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
    console.print("[bold cyan]💀 AURA DEEP MINE: MICROSOFT ENTRA STRIKE (PHASE 8)[/bold cyan]")
    
    if not os.path.exists("entra_bundles.txt"):
        console.print("[red]Error: entra_bundles.txt not found. Run hunt_entra.py first.[/red]")
        return

    with open("entra_bundles.txt", "r") as f:
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
                    if k not in all_findings:
                        all_findings[k] = []
                    all_findings[k].extend(v)
            
            # De-duplicate each category
            for key in all_findings:
                all_findings[key] = list(set(all_findings[key]))

    # Final Output
    output_path = "entra_phase8_recon.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(all_findings, f, indent=4)
    
    total_findings = sum(len(v) for v in all_findings.values())
    console.print(f"\n[bold green][!] RECON COMPLETE. Found {total_findings} potential leaks across {len(urls)} bundles.[/bold green]")
    console.print(f"[*] Results saved to: {output_path}")

if __name__ == "__main__":
    asyncio.run(main())
