import asyncio
import httpx
import json
from aura.ui.formatter import console

async def extract_api_manifest(url):
    console.print(f"[*] Extracting API manifest from {url}...")
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            r = await client.get(url)
            if r.status_code == 200:
                manifest = r.json()
                # Save to reports
                output_file = r"c:\Users\User\.gemini\antigravity\scratch\aura\reports\syfe_api_manifest.json"
                with open(output_file, "w") as f:
                    json.dump(manifest, f, indent=4)
                
                console.print(f"  [bold green][+] SUCCESS: {len(manifest.get('paths', {}))} endpoints discovered.[/bold green]")
                console.print(f"  [.] Manifest saved to: {output_file}")
                
                # Check for sensitive keywords
                sensitive = ["user", "transaction", "bank", "pii", "auth", "secret", "config"]
                for path in manifest.get('paths', {}).keys():
                    if any(s in path.lower() for s in sensitive):
                        console.print(f"    [!] Sensitive Endpoint: {path}")
            else:
                console.print(f"  [red][-] Failed: {r.status_code}[/red]")
    except Exception as e:
        console.print(f"  [red][!] Error: {e}[/red]")

if __name__ == "__main__":
    url = "https://uat-bugbounty.nonprod.syfe.com/v2/api-docs"
    loop = asyncio.get_event_loop()
    loop.run_until_complete(extract_api_manifest(url))
