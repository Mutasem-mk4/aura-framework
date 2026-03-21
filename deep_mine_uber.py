import asyncio
import httpx
import re
import json

async def main():
    js_url = "https://auth.uber.com/v2/_static/client-legacy-main-a25c2c3a57630f6f.js"
    target = "https://auth.uber.com"
    
    print(f"[*] AURA OMEGA STRIKE: Deep Mining {js_url}")
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    async with httpx.AsyncClient(verify=False, headers=headers) as client:
        try:
            resp = await client.get(js_url, timeout=60)
            if resp.status_code != 200:
                print(f"[-] Failed to fetch JS: {resp.status_code}")
                return
            
            content = resp.text
            print(f"[+] Bundle Loaded. Analyzing {len(content)} bytes...")
            
            # 1. Professional Tier Patterns
            patterns = {
                "Internal Environments": r'["\'][\w.-]+\.(?:staging|dev|internal|local|test)\.uber\.com[\w./-]*["\']',
                "Hardcoded Credentials": r'(?:api_key|apiKey|secret|token|password|auth|creds)["\']?\s*[:=]\s*["\']([\w-]{10,})["\']',
                "Internal Comments/Markers": r'(?:TODO|FIXME|BUG|DEPRECATED|DEBUG|TESTME|REMOVE_BEFORE_PROD)[:\s](.*)',
                "Hidden Parameters": r'["\'](\?[\w.-]+=[^"\']+)["\']',
                "Sensitive API Paths": r'["\'](/api/(?:v\d|internal|admin|debug|management)/[\w/.-]+)["\']',
                "Cloud Storage": r'["\'](https?://[\w.-]+\.(?:s3|blob|storage)\.googleapis\.com/[\w./-]+)["\']',
                "IP Addresses": r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
                "GitHub/Slack Leaks": r'(?:github\.com/uber|hooks\.slack\.com/services/\w+/\w+/\w+)'
            }

            findings = {}
            for category, regex in patterns.items():
                matches = re.findall(regex, content, re.IGNORECASE)
                if matches:
                    findings[category] = list(set(matches))
            
            # 2. Output and Save
            print(f"\n[!] RECON COMPLETE. Found {sum(len(v) for v in findings.values())} potential leaks.")
            for cat, items in findings.items():
                print(f"  [+] {cat}: {len(items)} hits.")
                for item in items[:10]: # Top 10 for terminal
                    print(f"    - {item}")
            
            with open("uber_phase2_recon.json", "w", encoding="utf-8") as f:
                json.dump(findings, f, indent=2)
                
            print(f"\n[✔] Full results saved to 'uber_phase2_recon.json'")

        except Exception as e:
            print(f"[-] Mining Crash: {e}")

if __name__ == "__main__":
    asyncio.run(main())
