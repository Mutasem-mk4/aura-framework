import requests
import urllib3
urllib3.disable_warnings()

url = "https://www.coinhako.com/public_api/v1/request_context"
headers = {
    "accept": "application/json, text/plain, */*",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "x-api-algorithm": "ecdsa-secp256k1-sha256",
    "x-api-key": "025D30A3E98F04EF6DD286C4BD1445C927BA38CBBDBB08C6B8D15287ECF4853552",
    "x-api-signature": "3045022016F266A8A49936CEDF0175D71BB32A8EC598AC83ACFABC2FEB896695306AF6ED022100C23689879CA460AC470C58127FCD7079D77A2F5BCDF8EFA544F41178BE3EE5B8",
    "x-api-timestamp": "1773377139667"
}

print(f"[*] Sending request to {url}...")
try:
    r = requests.get(url, headers=headers, verify=False, timeout=10)
    print(f"[+] Status Code: {r.status_code}")
    print(f"[+] Response Body: {r.text}")
except Exception as e:
    print(f"[!] Error: {e}")
