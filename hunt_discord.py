import httpx
import re
import os

def hunt():
    urls = ["https://discord.com", "https://discord.com/login"]
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    
    all_bundles = []
    for url in urls:
        print(f"[*] Scouting Discord: {url}...")
        try:
            r = httpx.get(url, headers=headers, follow_redirects=True, verify=False, timeout=15)
            if r.status_code != 200:
                print(f"[!] Error: Status {r.status_code}")
                continue
                
            # Find all script sources
            scripts = re.findall(r'src="([^"]+\.js[^"]*)"', r.text)
            
            # Filter for Discord-related or common bundle patterns
            bundles = [s for s in scripts if "discord" in s or "assets" in s]
            all_bundles.extend(bundles)
            print(f"[+] Found {len(bundles)} candidate bundles on {url}.")
            
        except Exception as e:
            print(f"[!] Critical Error on {url}: {e}")
            
    # Save all unique bundles
    unique_bundles = list(set(all_bundles))
    print(f"[*] Total unique bundles found: {len(unique_bundles)}")
    
    with open("discord_bundles.txt", "w") as f:
        for b in unique_bundles:
            f.write(b + "\n")

if __name__ == "__main__":
    hunt()
