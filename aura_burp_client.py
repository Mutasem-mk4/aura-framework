import requests
import json
import argparse
import sys

BURP_API_URL = "http://127.0.0.1:8090"

def get_sitemap():
    print(f"[*] Fetching sitemap from Burp Suite via Aura Bridge ({BURP_API_URL})...")
    try:
        response = requests.get(f"{BURP_API_URL}/sitemap", timeout=10)
        if response.status_code == 200:
            data = response.json()
            sitemap = data.get('sitemap', [])
            print(f"[+] Retrieved {len(sitemap)} items from Burp Sitemap.")
            
            # Print a clean summary
            for item in sitemap[:15]:
                status = item['status']
                method = item['method']
                url = item['url']
                
                # Colorize status slightly for readability if in a basic terminal
                status_str = str(status)
                if status == 0:
                    status_str = "PENDING/ERR"
                
                print(f"  - [{method}] {status_str} : {url}")
                
            if len(sitemap) > 15:
                print(f"  ... and {len(sitemap) - 15} more. Use JSON processing tools to view all.")
        else:
            print(f"[!] Error: Server returned {response.status_code}")
    except requests.exceptions.ConnectionError:
        print("[!] Connection Error: Is Burp Suite running and the 'Aura Bridge' extension loaded?")
    except requests.exceptions.Timeout:
        print("[!] Timeout Error: Burp is taking too long to respond.")

def send_to_proxy(url):
    print(f"[*] Sending target to Burp Proxy: {url}")
    try:
        response = requests.post(
            f"{BURP_API_URL}/proxy",
            json={"url": url},
            timeout=10
        )
        if response.status_code == 200:
            print(f"[+] Success: Request successfully sent through Burp.")
        else:
            print(f"[!] Failed to proxy request. Status: {response.status_code}")
    except requests.exceptions.ConnectionError:
        print("[!] Connection Error: Is Burp Suite running and the 'Aura Bridge' extension loaded?")
    except requests.exceptions.Timeout:
        print("[!] Timeout Error: Burp is taking too long to respond.")

def main():
    parser = argparse.ArgumentParser(description="Aura-Burp Bridge CLI Client")
    parser.add_argument("--sitemap", action="store_true", help="Fetch and display the current Burp Suite sitemap")
    parser.add_argument("--proxy", metavar="URL", help="Send a specific URL through Burp's engine to add to sitemap")
    
    args = parser.parse_args()
    
    if args.sitemap:
        get_sitemap()
    elif args.proxy:
        send_to_proxy(args.proxy)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
