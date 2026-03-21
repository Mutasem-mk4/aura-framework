import asyncio
import httpx
import json
from aura.ui.formatter import console

async def check_takeover_pattern(url, domain):
    takeover_patterns = {
        "NoSuchBucket": "Amazon S3",
        "There is no app configured": "GitHub Pages",
        "Heroku | No such app": "Heroku",
        "The specified bucket does not exist": "Google Cloud",
        "unrecognized domain": "Pantheon",
        "Welcome to Cloudfront": "Cloudfront",
        "404 Not Found": "General 404"
    }
    
    try:
        async with httpx.AsyncClient(verify=False, timeout=5) as client:
            r = await client.get(url)
            if r.status_code == 404:
                for pattern, service in takeover_patterns.items():
                    if pattern in r.text:
                        console.print(f"  [bold green][!!] TAKEOVER DETECTED: {domain} ({service})[/bold green]")
                        return {"domain": domain, "service": service, "url": url}
    except: pass
    return None

async def sweep_all(subdomain_file):
    with open(subdomain_file, "r") as f:
        targets = json.load(f)
    
    console.print(f"[*] Sweeping {len(targets)} subdomains for Takeover/404s...")
    results = []
    
    # Run in batches for speed
    batch_size = 50
    for i in range(0, len(targets), batch_size):
        batch = targets[i:i+batch_size]
        tasks = [check_takeover_pattern(f"https://{t['domain']}", t['domain']) for t in batch]
        responses = await asyncio.gather(*tasks)
        results.extend([r for r in responses if r])
    
    return results

if __name__ == "__main__":
    subdomain_file = r"c:\Users\User\.gemini\antigravity\scratch\aura\reports\reachable_uber_subdomains.json"
    loop = asyncio.get_event_loop()
    takeovers = loop.run_until_complete(sweep_all(subdomain_file))
    
    if takeovers:
        console.print(f"\n[bold green][+] Found {len(takeovers)} potential takeovers![/bold green]")
        with open(r"c:\Users\User\.gemini\antigravity\scratch\aura\reports\takeover_hits.json", "w") as f:
            json.dump(takeovers, f, indent=4)
    else:
        console.print("[yellow]No takeovers found in this sweep.[/yellow]")
