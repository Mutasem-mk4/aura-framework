import httpx
import re
import os

def verify_high_confidence():
    if not os.path.exists("discord_bundles.txt"):
        print("[!] No bundles found.")
        return

    with open("discord_bundles.txt", "r") as f:
        urls = [line.strip() for line in f if line.strip()]

    CRITICAL_FLAGS = ["STAFF_ONLY_DM", "INTERNAL_EMPLOYEE_ONLY", "10.2.31.31"]
    
    print("[*] Starting High-Confidence Verification...")
    
    found_evidence = []
    for url in urls:
        try:
            full_url = url
            if url.startswith("//"):
                full_url = "https:" + url
            elif url.startswith("/"):
                full_url = "https://discord.com" + url
                
            print(f"[*] Fetching: {full_url}")
            r = httpx.get(full_url, verify=False, timeout=15)
            text = r.text
            for flag in CRITICAL_FLAGS:
                if flag in text:
                    # Extract 100 chars before and after for context
                    index = text.find(flag)
                    context = text[max(0, index-200):min(len(text), index+200)]
                    found_evidence.append({
                        "flag": flag,
                        "url": url.split("/")[-1],
                        "context": context
                    })
                    print(f"[+] Confirmed: {flag} in {url.split('/')[-1]}")
        except:
            pass

    with open("discord_final_verification.json", "w") as f:
        import json
        json.dump(found_evidence, f, indent=4)
        
    print(f"[*] Done. Found evidence for {len(found_evidence)} instances.")

if __name__ == "__main__":
    verify_high_confidence()
