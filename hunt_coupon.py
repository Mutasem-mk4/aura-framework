import httpx
import re
import os

def hunt():
    if not os.path.exists("airbnb_bundles.txt"):
        print("[!] airbnb_bundles.txt not found.")
        return
        
    with open("airbnb_bundles.txt", "r") as f:
        urls = [line.strip() for line in f if line.strip()]
        
    print(f"[*] Hunting Coupon logic in {len(urls)} bundles...")
    
    for url in urls:
        try:
            r = httpx.get(url, verify=False, timeout=15)
            content = r.text
            
            # Find GraphQL queries containing "CouponPromotionQuery"
            matches = re.findall(r'[\"\'](?:query|mutation)\b.*?CouponPromotionQuery.*?\}[\"\']', content, re.DOTALL)
            if matches:
                print(f"[+] Found query in {url.split('/')[-1]}:")
                for m in matches:
                    print(f"  - {m[:200]}...")
                    
        except Exception as e:
            # Silently skip errors for speed
            pass

if __name__ == "__main__":
    hunt()
