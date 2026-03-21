import httpx
import os

def hunt():
    if not os.path.exists("slack_bundles.txt"):
        return
        
    with open("slack_bundles.txt", "r") as f:
        urls = [line.strip() for line in f if line.strip()]
        
    print(f"[*] Scanning {len(urls)} bundles for core logic...")
    
    TARGETS = ["client.boot", "api.slack.com", "flannel", "rpc.internal", "T0", "W0"]
    
    for url in urls:
        try:
            r = httpx.get(url, verify=False, timeout=10)
            text = r.text.lower()
            found = [t for t in TARGETS if t.lower() in text]
            if found:
                print(f"[+] Found {found} in {url.split('/')[-1]}")
        except:
            pass

if __name__ == "__main__":
    hunt()
