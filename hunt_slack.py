import httpx
import re
import os

def hunt():
    urls = ["https://slack.com", "https://app.slack.com"]
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    
    all_bundles = []
    for url in urls:
        print(f"[*] Scouting: {url}...")
        try:
            r = httpx.get(url, headers=headers, follow_redirects=True, verify=False, timeout=15)
            if r.status_code != 200:
                print(f"[!] Error: Status {r.status_code}")
                continue
                
            # Find all script sources
            scripts = re.findall(r'src="([^"]+\.js[^"]*)"', r.text)
            
            # Filter for Slack-related bundles and EXCLUDE marketing if on app subdomain
            bundles = [s for s in scripts if ("slack-edge" in s or "slack" in s)]
            if "app.slack.com" in url:
                bundles = [b for b in bundles if "marketing" not in b.lower()]
            
            all_bundles.extend(bundles)
            print(f"[+] Found {len(bundles)} candidate bundles on {url}.")
            for b in bundles[:3]:
                print(f"  - {b}")
                
        except Exception as e:
            print(f"[!] Error scouting {url}: {e}")
            
    # Save all unique bundles
    unique_bundles = list(set(all_bundles))
    print(f"[*] Total unique bundles found: {len(unique_bundles)}")
    
    with open("slack_bundles.txt", "w") as f:
        for b in unique_bundles:
            f.write(b + "\n")

if __name__ == "__main__":
    hunt()
