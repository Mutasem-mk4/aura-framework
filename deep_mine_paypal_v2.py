import asyncio
import httpx
import re
import json
import os
from aura.ui.formatter import console

# Targeted Regex Patterns for PayPal Strike (V2 - Anti-Noise)
PATTERNS = {
    "Merchant & Partner IDs": r'[\"\'](?:merchantId|partnerId|bnCode|payerId|accountNumber)[\"\'][\s:=]+["\']([\w\-]{10,})["\']',
    "PayPal API Gateway Paths": r'https?://(?:api|api\-m)\.paypal\.com/(?:v1|v2|checkout|merchant)/[\w\-\/]+',
    "Client IDs & Secrets (High Confidence)": r'[\"\'](?:clientId|clientSecret|secret)[\"\'][\s:=]+["\']([a-zA-Z0-9\-_]{20,})["\']',
    "Internal Feature Flags": r'[\"\'](?:isInternal|enableDebug|experimental|stage_env|is_staff)[\"\'][\s:=]+(?:true|false|["\'][\w\-]+["\'])',
    "Internal Component Names": r'[\"\'](?:Internal|Debug|Experimental)[\w\-]+(?:Button|Modal|Header|View)[\"\']',
    "Contextual TODOs (Strict)": r'//\s*(?:TODO|FIXME|HACK)[\s:]+(.*)'
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
    console.print("[bold cyan]💀 AURA DEEP MINE V2: PAYPAL STRIKE (PHASE 9)[/bold cyan]")
    
    if not os.path.exists("paypal_bundles.txt"):
        console.print("[red]Error: paypal_bundles.txt not found. Run hunt_paypal.py first.[/red]")
        return

    with open("paypal_bundles.txt", "r") as f:
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
                    print(f"DEBUG: Found {len(v)} matches for {k}")
            
            # De-duplicate each category
            for key in all_findings:
                all_findings[key] = list(set(all_findings[key]))

    # Final Output
    output_path = "paypal_phase9_recon_v2.json"
    print(f"DEBUG: Final all_findings keys: {all_findings.keys()}")
    final_json = json.dumps(all_findings, indent=4)
    print(f"DEBUG: JSON CONTENT START\n{final_json}\nDEBUG: JSON CONTENT END")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(final_json)
    
    total_findings = sum(len(v) for v in all_findings.values())
    console.print(f"\n[bold green][!] RECON V2 COMPLETE. Found {total_findings} cleaned findings across {len(urls)} bundles.[/bold green]")
    console.print(f"[*] Results saved to: {output_path}")

if __name__ == "__main__":
    asyncio.run(main())
