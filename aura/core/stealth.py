from curl_cffi import requests as curlr
import random
import time
from typing import Dict, Optional

class StealthEngine:
    """The Ghost Mode engine for anonymizing and diversifying Aura's traffic."""
    
    # Supported browser impersonations for JA3 randomization
    IMPERSONATE_TYPES = ["chrome110", "chrome101", "safari15_5", "firefox108", "edge101"]
    
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0"
    ]

    def __init__(self, proxy_list: Optional[list] = None):
        self.proxy_list = proxy_list or []

    def get_stealth_params(self) -> Dict:
        """Returns randomized stealth parameters for a request."""
        return {
            "impersonate": random.choice(self.IMPERSONATE_TYPES),
            "headers": {"User-Agent": random.choice(self.USER_AGENTS)},
            "proxies": self.get_proxy_dict()
        }

    def get_proxy_dict(self) -> Optional[Dict]:
        """Returns a randomized proxy if available."""
        if not self.proxy_list:
            return None
        proxy = random.choice(self.proxy_list)
        return {"http": proxy, "https": proxy}

class AuraSession:
    """A high-stealth wrapper using curl_cffi for JA3 evasion."""
    
    def __init__(self, stealth: StealthEngine):
        self.stealth = stealth

    def request(self, method, url, **kwargs):
        """Executes a request with JA3 impersonation, randomized headers, and behavioral jitter."""
        params = self.stealth.get_stealth_params()
        
        # Behavioral Evasion: Human-like delay (jitter)
        # Random delay between 0.5s and 2.5s for sensitive web requests
        delay = random.uniform(0.5, 2.5)
        time.sleep(delay)
        
        # Merge kwargs with stealth params
        kwargs.setdefault("impersonate", params["impersonate"])
        kwargs.setdefault("headers", params["headers"])
        kwargs.setdefault("proxies", params["proxies"])
        kwargs.setdefault("timeout", 15)
        kwargs.setdefault("verify", False)
        
        return curlr.request(method, url, **kwargs)

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)
