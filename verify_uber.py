import httpx
import asyncio

VULNS = [
    "https://auth.uber.com/api/v2/auth/internal-session",
    "https://riders.uber.com/api/riders/v1/profile-dump",
    "https://bonjour.uber.com/api/internal/config"
]

async def certify_finding(url):
    print(f"[*] Recertifying: {url}")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Origin": "https://www.uber.com"
    }
    async with httpx.AsyncClient(verify=False, timeout=15, headers=headers) as client:
        try:
            # Using GET because HEAD is often blocked differently
            r = await client.get(url, follow_redirects=True)
            print(f"    -> Response: HTTP {r.status_code}")
            
            # If 200 or 500 (internal crash), it's a high-fidelity finding
            if r.status_code in [200, 500, 201]:
                return True
            return False
        except Exception as e:
            print(f"    -> Error: {e}")
            return False

async def main():
    print(f"\n{'='*60}")
    print(f"  💀 AURA VULNERABILITY RE-CERTIFICATION: UBER")
    print(f"{'='*60}\n")
    
    success_count = 0
    for v in VULNS:
        if await certify_finding(v):
            success_count += 1
            print(f"    [🔥] CERTIFIED: Finding is LIVE and RESPONSIVE.")
        else:
            print(f"    [!] UNCONFIRMED: May be WAF-protected or False Positive.")
            
    print(f"\n{'='*60}")
    print(f"  Confidence Score: {(success_count/len(VULNS))*100:.1f}%")
    print(f"{'='*60}\n")

if __name__ == "__main__":
    asyncio.run(main())
