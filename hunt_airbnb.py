import httpx
import re
import os

def hunt():
    url = "https://www.airbnb.com"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    
    print(f"[*] Scouting Airbnb: {url}...")
    try:
        r = httpx.get(url, headers=headers, follow_redirects=True, verify=False, timeout=15)
        if r.status_code != 200:
            print(f"[!] Error: Status {r.status_code}")
            return
            
        # Find all script sources
        scripts = re.findall(r'src="([^"]+\.js[^"]*)"', r.text)
        
        # Filter for airbnb bundles (usually hosted on a.muscache.com or similar)
        bundles = [s for s in scripts if "muscache" in s or "airbnb" in s]
        
        print(f"[+] Found {len(bundles)} candidate bundles.")
        for b in bundles[:5]:
            print(f"  - {b}")
            
        # Save the list to a file
        with open("airbnb_bundles.txt", "w") as f:
            for b in bundles:
                f.write(b + "\n")
                
    except Exception as e:
        print(f"[!] Critical Error: {e}")

if __name__ == "__main__":
    hunt()
