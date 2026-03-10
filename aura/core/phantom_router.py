"""
Aura v3 Omni — Phantom Router
=============================
Handles extreme WAF evasion by dynamically rotating:
  1. IP Addresses (via Proxy Swarms)
  2. Browser Fingerprints (User-Agents & Headers)
"""

import random
from typing import Optional, Dict

# Massive list of modern, realistic User-Agents to blend in with legitimate traffic
USER_AGENTS = [
    # Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
    # macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    # Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    # iOS
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
    # Android
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
]

# Randomized Accept-Languages to simulate global origins
LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.8,es;q=0.6",
    "de-DE,de;q=0.9,en-US;q=0.8",
    "fr-FR,fr;q=0.9,en-US;q=0.8",
    "ar-SA,ar;q=0.9,en-US;q=0.8",
    "zh-CN,zh;q=0.9,en-US;q=0.8",
]

class PhantomRouter:
    """
    Manages identity rotation and proxy routing to evade Web Application Firewalls (WAF).
    """

    def __init__(self, proxy_file: Optional[str] = None):
        self.proxies: list[str] = []
        self.current_proxy_index = 0
        self.is_active = False

        if proxy_file:
            self.load_proxies(proxy_file)

    def load_proxies(self, filename: str):
        """Loads a list of proxies from a text file."""
        try:
            with open(filename, "r", encoding="utf-8") as f:
                # Support http://ip:port or just ip:port
                lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                for p in lines:
                    if not p.startswith("http://") and not p.startswith("https://") and not p.startswith("socks5://"):
                        p = f"http://{p}"
                    self.proxies.append(p)
            
            if self.proxies:
                self.is_active = True
                # Shuffle proxies to ensure random distribution across runs
                random.shuffle(self.proxies)
        except Exception as e:
            print(f"[!] PhantomRouter failed to load proxy file '{filename}': {e}")

    def get_proxy(self) -> Optional[str]:
        """Returns a random proxy from the loaded list if active, else None."""
        if not self.is_active or not self.proxies:
            return None
        return random.choice(self.proxies)

    def get_user_agent(self) -> str:
        """Returns a highly realistic modern User-Agent."""
        return random.choice(USER_AGENTS)

    def get_evasion_headers(self) -> Dict[str, str]:
        """
        Generates a dictionary of headers designed to spoof a real browser
        and bypass basic WAF heuristic checks.
        """
        ua = self.get_user_agent()
        
        headers = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": random.choice(LANGUAGES),
            "Upgrade-Insecure-Requests": "1",
            "Connection": "keep-alive",
            "DNT": "1", # Do Not Track -> Some WAFs trust this
        }

        # Sec-Ch-Ua spoofing based on Chrome/Edge or Firefox
        if "Chrome" in ua:
            headers["Sec-Ch-Ua"] = '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"'
            headers["Sec-Ch-Ua-Mobile"] = "?1" if "Mobile" in ua else "?0"
            headers["Sec-Ch-Ua-Platform"] = '"Windows"' if "Windows" in ua else ('"macOS"' if "Mac OS" in ua else '"Android"')

        return headers
