import asyncio
import httpx
import re
from urllib.parse import urljoin

async def main():
    target = "https://riders.uber.com"
    print(f"[*] Analyzing {target}...")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    
    async with httpx.AsyncClient(verify=False, headers=headers) as client:
        try:
            resp = await client.get(target, timeout=30)
            if resp.status_code == 200:
                # Find all scripts
                scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', resp.text)
                print(f"[+] Found {len(scripts)} scripts.")
                
                for s in scripts:
                    full_url = urljoin(target, s)
                    print(f"  -> {full_url}")
            else:
                print(f"[-] Failed with HTTP {resp.status_code}")
        except Exception as e:
            print(f"[-] Error: {e}")

if __name__ == "__main__":
    asyncio.run(main())
