import asyncio
import httpx
from aura.ui.formatter import console

async def audit_internal_paths(url):
    paths = [
        "/admin", "/login", "/api-docs", "/v2/api-docs", "/v3/api-docs",
        "/swagger-ui.html", "/swagger-ui/", "/actuator", "/health",
        "/env", "/metrics", "/config", "/api/v1/users"
    ]
    
    console.print(f"[*] Auditing internal paths for {url}...")
    try:
        async with httpx.AsyncClient(verify=False, timeout=5) as client:
            for p in paths:
                try:
                    r = await client.get(f"{url}{p}")
                    if r.status_code == 200:
                        console.print(f"  [bold green][!!] EXPOSED: {url}{p}[/bold green]")
                        if "swagger" in r.text.lower() or "api" in r.text.lower():
                            console.print(f"    -> Potential API leakage detected.")
                    elif r.status_code == 401:
                        console.print(f"  [yellow][.] Protected: {url}{p}[/yellow]")
                except: continue
    except Exception as e:
        console.print(f"  [red]Audit failed: {e}[/red]")

if __name__ == "__main__":
    url = "https://uat-bugbounty.nonprod.syfe.com"
    loop = asyncio.get_event_loop()
    loop.run_until_complete(audit_internal_paths(url))
