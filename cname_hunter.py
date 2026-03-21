import asyncio
import dns.resolver
import json
import os
from aura.ui.formatter import console

async def check_cname(subdomain):
    takeover_signatures = {
        "herokuapp.com": "Heroku",
        "s3.amazonaws.com": "S3",
        "zendesk.com": "Zendesk",
        "azurewebsites.net": "Azure",
        "github.io": "GitHub Pages",
        "ghost.io": "Ghost",
        "bitbucket.io": "Bitbucket",
        "wpengine.com": "WPEngine"
    }
    
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        answers = resolver.resolve(subdomain, 'CNAME')
        for rdata in answers:
            target = str(rdata.target).lower()
            for sig, service in takeover_signatures.items():
                if sig in target:
                    # Potential hit. Now check if the service is actually dead.
                    # This is just a DNS-level check first.
                    console.print(f"  [bold red][!!!] DANGLING CNAME: {subdomain} -> {target} ({service})[/bold red]")
                    return {"subdomain": subdomain, "target": target, "service": service}
    except: pass
    return None

async def run_hunter():
    target_file = r"c:\Users\User\.gemini\antigravity\scratch\aura\reports\scavenger_targets_v2.json"
    if not os.path.exists(target_file):
        console.print(f"[red][!] Error: {target_file} not found.[/red]")
        return

    with open(target_file, "r") as f:
        targets = json.load(f)
    
    console.print(f"[*] Running CNAME Hunter on {len(targets)} subdomains...")
    
    semaphore = asyncio.Semaphore(50)
    async def limited_check(sub):
        async with semaphore:
            return await check_cname(sub)
            
    tasks = [limited_check(sub) for sub in targets]
    results = await asyncio.gather(*tasks)
    
    hits = [r for r in results if r]
    console.print(f"\n[bold green][!!] CNAME AUDIT COMPLETE. Found {len(hits)} potential takeovers.[/bold green]")
    for h in hits:
        console.print(f"  -> {h['subdomain']} (Points to {h['service']})")

if __name__ == "__main__":
    asyncio.run(run_hunter())
