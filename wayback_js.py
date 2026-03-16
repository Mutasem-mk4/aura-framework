import requests
import json

def get_wayback_js(domain):
    print(f"[*] Searching Wayback Machine for JS bundles on {domain}...")
    url = f"http://web.archive.org/cdx/search/xd?url={domain}/*&output=json&fl=original&collapse=urlkey"
    try:
        r = requests.get(url, timeout=20)
        if r.status_code == 200:
            urls = r.json()
            js_urls = [u[0] for u in urls if u[0].endswith(".js")]
            print(f"[+] Found {len(js_urls)} historical JS bundles.")
            for j in js_urls[:20]:
                print(f"  - {j}")
            return js_urls
    except Exception as e:
        print(f"[!] Wayback Error: {e}")
    return []

if __name__ == "__main__":
    get_wayback_js("coinhako.com")
