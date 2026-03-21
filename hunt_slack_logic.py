import httpx
import re
import os

def hunt():
    if not os.path.exists("slack_bundles.txt"):
        print("[!] slack_bundles.txt not found.")
        return
        
    with open("slack_bundles.txt", "r") as f:
        urls = [line.strip() for line in f if line.strip()]
        
    print(f"[*] Hunting transport in {len(urls)} bundles...")
    
    # Common Slack API patterns
    patterns = [
        r'fetch\([\"\']([^\"\']+)[\"\']',
        r'[\"\'](?:POST|GET|PUT|DELETE)[\"\'][\s,]+[\"\']([^\"\']+)[\"\']',
        r'[\"\'](?:https?://[\w\-]+\.slack\.com/api/[^\"\']+)[\"\']',
        r'[\"\'](?:https?://[\w\-]+\.slack-edge\.com/[^\"\']+)[\"\']'
    ]
    
    for url in urls:
        try:
            r = httpx.get(url, verify=False, timeout=15)
            content = r.text
            
            for p in patterns:
                matches = re.findall(p, content)
                if matches:
                    print(f"[+] Found matches in {url.split('/')[-1]}:")
                    for m in set(matches[:5]):
                        print(f"  - {m}")
                    
        except Exception as e:
            # Silently skip errors for speed
            pass

if __name__ == "__main__":
    hunt()
