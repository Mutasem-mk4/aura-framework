import asyncio
import httpx
from aura.ui.formatter import console

async def strict_verify(url, search_string):
    console.print(f"[*] Strict Verify -> {url}")
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            r = await client.get(url)
            if r.status_code == 200:
                if search_string in r.text:
                    console.print(f"  [bold red][!!!] VERIFIED HIT: {url}[/bold red]")
                    return True
                else:
                    # console.print(f"  [yellow][.] False Positive (No content match).[/yellow]")
                    pass
    except: pass
    return False

async def run_last_stand():
    checks = [
        ("https://blockscout.com/.git/config", "[core]"),
        ("https://indorse.io/.git/config", "[core]"),
        ("https://api-au.syfe.com/actuator/jolokia", "jolokia"),
        ("https://api-au.syfe.com/actuator/prometheus", "jvm_memory_used_bytes"),
        ("https://uat-bugbounty.nonprod.syfe.com/actuator/jolokia", "jolokia")
    ]
    
    console.print(f"[*] Running Last Stand Audit: Filtering for real content only...")
    tasks = [strict_verify(url, s) for url, s in checks]
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(run_last_stand())
