from curl_cffi import requests as curlr
import random
import time
import asyncio
from typing import Dict, Optional, List
from aura.core import state

class StealthEngine:
    """The Ghost Mode v3 engine for anonymizing and diversifying Aura's traffic."""
    
    IMPERSONATE_TYPES = ["chrome110", "chrome116", "safari15_5", "safari15", "edge101"]
    
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0"
    ]

    def __init__(self, proxy_list: Optional[list] = None, proxy_file: Optional[str] = None):
        self.proxy_list = proxy_list or []
        self.active_waf = None
        
        from aura.core import state
        final_proxy_file = proxy_file or state.PROXY_FILE
        
        if final_proxy_file:
            self.load_proxies(final_proxy_file)
            
    def load_proxies(self, file_path: str):
        """Loads a list of HTTP/HTTPS proxies from a file."""
        import os
        from rich.console import Console
        console = Console()
        if os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    proxies = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                self.proxy_list.extend(proxies)
                console.print(f"[bold green][+] Loaded {len(proxies)} proxies from {file_path}[/bold green]")
            except Exception as e:
                console.print(f"[bold red][!] Failed to load proxies: {e}[/bold red]")
        else:
            console.print(f"[bold yellow][!] Proxy file not found: {file_path}[/bold yellow]")

    def detect_waf(self, response_headers: Dict, body: str) -> Optional[str]:
        """Ghost v3: WAFSense detection logic with expanded signatures for Phase 28."""
        waf_signatures = {
            "Cloudflare": ["cf-ray", "__cf_bm", "cloudflare-nginx"],
            "Akamai": ["ak_bmsc", "akamai-ghs"],
            "Incapsula": ["visid_incap", "incap_ses", "imperva"],
            "AWS WAF": ["x-amzn-requestid", "aws-waf"],
            "Fortinet": ["fortiwafsid", "fortigate"],
            "F5 BIG-IP": ["bigipserver", "x-wa-info"],
            "Sucuri": ["sucuri-cloudproxy"],
            "ModSecurity": ["mod_security", "no-cache=\"set-cookie\""]
        }
        
        for name, sigs in waf_signatures.items():
            for sig in sigs:
                if sig in str(response_headers).lower() or sig in body.lower():
                    self.active_waf = name
                    return name
        return None

    def get_evasion_headers(self, waf_type: str) -> Dict:
        """Phase 28: Generates smuggle/evasion headers based on WAF identity."""
        evasions = {
            "Cloudflare": {"Transfer-Encoding": "chunked", "X-Forwarded-For": "127.0.0.1"},
            "Akamai": {"Pragma": "akamai-x-get-cache-key, akamai-x-cache-on"},
            "AWS WAF": {"X-Amzn-Trace-Id": f"Root=1-{int(time.time())}-aura"},
            "Fortinet": {"X-Real-IP": "12.34.56.78"},
            "Generic": {"Transfer-Encoding": "chunked", "Connection": "keep-alive, Transfer-Encoding"}
        }
        return evasions.get(waf_type, evasions["Generic"])

    def get_stealth_params(self, force_rotate: bool = False) -> Dict:
        """Returns randomized stealth headers mimicking modern browsers (v5)."""
        impersonate = random.choice(self.IMPERSONATE_TYPES)
        ua = random.choice(self.USER_AGENTS)
        
        # Ghost v5: Randomized Traffic Signatures
        headers = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-GPC": "1"
        }
        
        # Add Chromium specific headers
        if any(x in impersonate for x in ["chrome", "edge"]):
            headers["Sec-Ch-Ua"] = '"Not/A)Brand";v="99", "Chromium";v="119"'
            headers["Sec-Ch-Ua-Mobile"] = "?0"
            headers["Sec-Ch-Ua-Platform"] = '"Windows"'
            
        if self.active_waf:
            headers.update(self.get_evasion_headers(self.active_waf))
            
        return {
            "impersonate": impersonate,
            "headers": headers,
            "proxies": self.get_proxy_dict()
        }

    def get_polymorphic_payload(self, raw_payload: str) -> str:
        """Ghost v5: Wraps a payload in a self-decoding JS layer to bypass WAF signatures."""
        import base64
        # simple polymorphic wrapping to bypass static string matching
        b64_payload = base64.b64encode(raw_payload.encode()).decode()
        templates = [
            f"eval(atob('{b64_payload}'))",
            f"new Function(atob('{b64_payload}'))()",
            f"window['ev'+'al'](window['at'+'ob']('{b64_payload}'))"
        ]
        return random.choice(templates)


    def get_proxy_dict(self) -> Optional[Dict]:
        if not self.proxy_list:
            return None
        proxy = random.choice(self.proxy_list)
        return {"http": proxy, "https": proxy}

class AuraSession:
    """A high-stealth wrapper using curl_cffi for Ghost v3 evasion."""
    
    # Global semaphore to prevent network saturation across all sessions
    _semaphore = asyncio.Semaphore(state.GLOBAL_CONCURRENCY_LIMIT)

    def __init__(self, stealth: StealthEngine):
        self.stealth = stealth
        self.retries = 3

    async def request(self, method, url, **kwargs):
        """Executes a request with JA3 impersonation and Ghost v3 adaptive evasion."""
        for attempt in range(self.retries):
            params = self.stealth.get_stealth_params(force_rotate=(attempt > 0))
            
            # Ghost v4: Advanced Behavioral Jitter (Humanized Delays)
            # We sleep BEFORE grabbing the semaphore to avoid blocking the whole framework
            if not self.stealth.active_waf:
                delay = random.uniform(0.5, 2.5)
            else:
                delay = random.uniform(3.0, 7.0)
            
            await asyncio.sleep(delay)
            
            async with self._semaphore:
                # Merge kwargs with Ghost v3 params
                req_kwargs = kwargs.copy()
                req_kwargs.setdefault("impersonate", params["impersonate"])
                req_kwargs.setdefault("headers", params["headers"])
                req_kwargs.setdefault("proxies", params["proxies"])
                req_kwargs.setdefault("timeout", 20)
                req_kwargs.setdefault("verify", False)
                
                try:
                    resp = await asyncio.to_thread(curlr.request, method, url, **req_kwargs)
                    
                    waf = self.stealth.detect_waf(resp.headers, resp.text)
                    if resp.status_code in [403, 429] and attempt < self.retries - 1:
                        continue
                        
                    return resp
                except Exception as e:
                    if attempt == self.retries - 1:
                        raise e
                    continue

    async def get(self, url, **kwargs):
        return await self.request("GET", url, **kwargs)

    async def post(self, url, **kwargs):
        return await self.request("POST", url, **kwargs)
