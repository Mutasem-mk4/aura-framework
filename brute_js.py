import requests
import json
import re
from concurrent.futures import ThreadPoolExecutor

def get_wayback_js(domain):
    url = f"http://web.archive.org/cdx/search/xd?url={domain}/*&output=json&fl=original&collapse=urlkey"
    try:
        r = requests.get(url, timeout=20)
        if r.status_code == 200:
            urls = r.json()
            return [u[0] for u in urls if u[0].endswith(".js")]
    except:
        return []

def check_url(url):
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            if "x-api-key" in r.text or "x-api-signature" in r.text:
                return url
    except:
        pass
    return None

def main():
    js_urls = get_wayback_js("coinhako.com")
    print(f"[*] Checking {len(js_urls)} URLs for API signatures...")
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        results = list(executor.map(check_url, js_urls))
    
    found = [r for r in results if r]
    print(f"[+] Found {len(found)} candidate bundles:")
    for f in found:
        print(f"  - {f}")

if __name__ == "__main__":
    main()
