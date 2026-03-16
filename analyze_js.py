import requests
import re

def search_bundles(urls):
    print(f"[*] Analyzing {len(urls)} bundles for secrets...")
    patterns = [
        re.compile(r"x-api-key"),
        re.compile(r"secp256k1"),
        re.compile(r"x-api-signature"),
        re.compile(r"[a-fA-F0-9]{64}") # Potential 32-byte hex secret
    ]
    
    for url in urls:
        print(f"[*] Downloading {url}...")
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                for p in patterns:
                    if p.search(r.text):
                        print(f"[!!!] Match found in {url} for pattern: {p.pattern}")
                        # Print context
                        match = p.search(r.text)
                        start = max(0, match.start() - 50)
                        end = min(len(r.text), match.end() + 100)
                        print(f"    Context: {r.text[start:end]}")
        except:
            pass

if __name__ == "__main__":
    # Test top 10 newest
    test_urls = [
        "https://www.coinhako.com/1020.8712356b71aadff2f03a.js",
        "https://www.coinhako.com/1020.e270eabe06d1f022efc7.js",
        "https://www.coinhako.com/1125.3e41f9ebd25c81b9c1fa.js"
    ]
    search_bundles(test_urls)
