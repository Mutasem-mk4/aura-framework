import httpx
import re
import os

def hunt():
    if not os.path.exists("slack_bundles.txt"):
        print("[!] slack_bundles.txt not found.")
        return
        
    with open("slack_bundles.txt", "r") as f:
        urls = [line.strip() for line in f if line.strip()]
        
    print(f"[*] Hunting unique paths in {len(urls)} bundles...")
    
    # Catch all potential API paths
    pattern = r'["\'](?:https://[\w\-]+\.slack\.com/api/[^"\']+|/api/[\w\-\/]+)["\']'
    
    all_paths = []
    for url in urls:
        try:
            r = httpx.get(url, verify=False, timeout=15)
            matches = re.findall(pattern, r.text)
            all_paths.extend(matches)
        except:
            pass
            
    # De-duplicate
    unique_paths = list(set(all_paths))
    
    # Filter out noise (standard baggage)
    NOISE = ["list_of_spans", "track", "log", "metrics", "analytics"]
    filtered = [p for p in unique_paths if not any(n in p.lower() for n in NOISE)]
    
    print(f"[!] Found {len(filtered)} unique potential endpoints.")
    for p in sorted(filtered)[:20]:
        print(f"  - {p}")

if __name__ == "__main__":
    hunt()
