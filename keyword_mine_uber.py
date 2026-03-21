import asyncio
import httpx
import re

async def main():
    js_url = "https://auth.uber.com/v2/_static/client-legacy-main-a25c2c3a57630f6f.js"
    print(f"[*] Fetching {js_url}...")
    
    async with httpx.AsyncClient(verify=False) as client:
        resp = await client.get(js_url, timeout=60)
        if resp.status_code == 200:
            content = resp.text
            print(f"[+] Bundle fetched. Size: {len(content)}")
            
            keywords = [
                "internal-session",
                "profile-dump",
                "admin",
                "staging",
                "internal",
                "apiKey",
                "password",
                "secret",
                "token",
                "uber-internal",
                "vault",
                "sandbox"
            ]
            
            findings = {}
            for kw in keywords:
                # Find occurrences with some context
                matches = re.findall(r'.{0,50}' + re.escape(kw) + r'.{0,50}', content)
                if matches:
                    findings[kw] = matches[:5] # Top 5 occurrences
                    
            print(f"\n[!] Keyword Findings:")
            for kw, occur in findings.items():
                print(f"  - '{kw}': Found {len(occur)} examples.")
                for o in occur:
                    print(f"    | {o.strip()}")
        else:
            print(f"[-] Failed: {resp.status_code}")

if __name__ == "__main__":
    asyncio.run(main())
