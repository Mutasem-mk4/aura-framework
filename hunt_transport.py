import httpx
import re
import os

def hunt():
    if not os.path.exists("airbnb_bundles.txt"):
        print("[!] airbnb_bundles.txt not found.")
        return
        
    with open("airbnb_bundles.txt", "r") as f:
        urls = [line.strip() for line in f if line.strip()]
        
    print(f"[*] Hunting transport in {len(urls)} bundles...")
    
    for url in urls[:10]:
        try:
            r = httpx.get(url, verify=False, timeout=15)
            content = r.text
            
            # Look for fetch calls to API endpoints
            fetches = re.findall(r'fetch\([\"\']([^\"\']+/api/[^\"\']+)[\"\']', content)
            if fetches:
                print(f"[+] Found fetches in {url.split('/')[-1]}:")
                for f in set(fetches):
                    print(f"  - {f}")
                    
            # Look for POST requests
            posts = re.findall(r'method\s*:\s*[\"\']POST[\"\']', content)
            if posts:
                print(f"[+] Found {len(posts)} POST definitions in {url.split('/')[-1]}")
                
        except Exception as e:
            print(f"[!] Error reading {url}: {e}")

if __name__ == "__main__":
    hunt()
