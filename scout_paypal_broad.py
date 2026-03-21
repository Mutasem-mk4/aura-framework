import asyncio
import httpx
import re
import os

async def scout():
    print("💀 AURA BROAD SCOUT: PAYPAL STRIKE (PHASE 9)")
    
    # Broader range of targets
    targets = [
        "https://www.paypal.com/checkoutnow",
        "https://www.paypal.com/sdk/js?client-id=sb", # Sandbox SDK (often leaks patterns)
        "https://www.paypalobjects.com/webstatic/en_US/developer/docs/js/checkout.js",
        "https://www.paypal.com/merchantapps/app/home",
        "https://www.paypal.com/bizsignup",
        "https://c.paypal.com/da/r/fb.js", # Fingerprint JS
        "https://www.paypalobjects.com/checkout/js/checkout.js",
        "https://www.paypal.com/webapps/hermes/api/batch", # Internal API
        "https://www.paypal.com/webapps/paylog/api/log"
    ]
    
    all_bundles = set()
    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        for url in targets:
            try:
                print(f"[*] Scouting -> {url}")
                headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
                resp = await client.get(url, headers=headers, timeout=20)
                
                # If it's a JS file itself, add it
                if url.endswith(".js"):
                    all_findings = [url]
                else:
                    content = resp.text
                    all_findings = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', content)
                
                for b in all_findings:
                    if "paypal" in b.lower() or "checkout" in b.lower() or "merchant" in b.lower() or "sdk" in b.lower():
                        if b.startswith("//"): b = "https:" + b
                        elif b.startswith("/"): b = "https://www.paypal.com" + b
                        all_bundles.add(b)
                
            except Exception as e:
                print(f"Error scouting {url}: {e}")

    # Save
    with open("paypal_bundles_v2.txt", "w") as f:
        for b in sorted(all_bundles):
            f.write(f"{b}\n")
    
    print(f"\n[!] Total unique bundles found: {len(all_bundles)}")

if __name__ == "__main__":
    asyncio.run(scout())
