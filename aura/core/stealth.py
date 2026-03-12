from curl_cffi import requests as curlr
import random
import time
import asyncio
import os
import httpx
import requests
from urllib.parse import urlparse, urljoin
import concurrent.futures
from typing import Dict, Optional, List
from aura.core import state
from aura.ui.zenith_ui import ZenithUI, console

class SwarmManager:
    """v6.0: Manages a swarm of proxies and nodes with adaptive health tracking."""
    def __init__(self, proxies: List[str]):
        self.proxies = {p: {"hits": 0, "failures": 0, "status": "HEALTHY"} for p in proxies}
        self.active_index = 0

    def get_best_proxy(self) -> Optional[str]:
        healthy = [p for p, stats in self.proxies.items() if stats["status"] == "HEALTHY"]
        if not healthy: return None
        return random.choice(healthy)

    def report_failure(self, proxy: str):
        if proxy in self.proxies:
            self.proxies[proxy]["failures"] += 1
            if self.proxies[proxy]["failures"] > 5:
                self.proxies[proxy]["status"] = "BURNED"

    def report_success(self, proxy: str):
        if proxy in self.proxies:
            self.proxies[proxy]["hits"] += 1
            self.proxies[proxy]["failures"] = 0

class StealthEngine:
    """The Ghost Mode v3 engine for anonymizing and diversifying Aura's traffic."""
    
    IMPERSONATE_TYPES = ["chrome110", "chrome116", "chrome119", "chrome124", "safari15_5", "safari17_0", "safari18_0", "edge101"]
    
    MOBILE_IMPERSONATE = {
        "ios_iphone15": {
            "impersonate": "safari17_0",
            "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
            "headers": {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "X-Requested-With": "com.apple.mobilesafari"
            }
        },
        "android_pixel8": {
            "impersonate": "chrome119",
            "ua": "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
            "headers": {
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "en-US,en;q=0.9",
                "X-Requested-With": "com.google.android.apps.messaging"
            }
        }
    }

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    ]

    def __init__(self, proxy_list: Optional[list] = None, proxy_file: Optional[str] = None):
        self.proxy_list = proxy_list or []
        self.active_waf = None
        self.mobile_mode = getattr(state, "MOBILE_MODE", False) # Enable via GLOBAL_STATE
        
        final_proxy_file = proxy_file or state.PROXY_FILE
        if final_proxy_file:
            self.load_proxies(final_proxy_file)
        
        self.swarm = SwarmManager(self.proxy_list)
        self.battle_mode = False
            
    def load_proxies(self, file_path: str):
        if os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    proxies = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                self.proxy_list.extend(proxies)
            except Exception as e:
                console.print(f"[bold red][!] Failed to load proxies: {e}[/bold red]")

    def detect_waf(self, response_headers: Dict, body: str) -> Optional[str]:
        waf_signatures = {
            "Cloudflare": ["cf-ray", "__cf_bm", "cloudflare-nginx"],
            "Akamai": ["ak_bmsc", "akamai-ghs"],
            "AWS WAF": ["x-amzn-requestid", "aws-waf"]
        }
        for name, sigs in waf_signatures.items():
            for sig in sigs:
                if sig in str(response_headers).lower() or sig in body.lower():
                    self.active_waf = name
                    return name
        return None

    def get_evasion_headers(self, waf_type: str) -> Dict:
        """v25.0 OMEGA+: Akamai-Slayer Advanced Header Smuggling."""
        evasions = {
            "Cloudflare": {
                "Transfer-Encoding": "chunked", 
                "X-Forwarded-For": "127.0.0.1",
                "CF-Connecting-IP": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            },
            "Akamai": {
                "Pragma": "akamai-x-get-cache-key, akamai-x-cache-on, akamai-x-cache-remote-on, akamai-x-check-cacheable, akamai-x-get-true-cache-key, akamai-x-get-extracted-values, akamai-x-get-ssl-client-session-id, akamai-x-get-client-ip",
                "X-Akamai-Edge-Hop": "1",
                "X-Akamai-Staging": "ESSL",
                "Akamai-Origin-Hop": "true",
                "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"
            },
            "AWS WAF": {"X-Amzn-Trace-Id": f"Root=1-{int(time.time())}-aura"},
            "Generic": {"Transfer-Encoding": "chunked", "X-Real-IP": "127.0.0.1"}
        }
        return evasions.get(waf_type, evasions["Generic"])

    def get_morphic_delay(self) -> float:
        """v25.0 OMEGA+: Bio-Mimetic timing jitter to bypass Akamai Bot Manager."""
        # 80% chance of 'active browsing' (0.5s - 2s), 20% 'deep reading' (5s - 15s)
        if random.random() > 0.8:
            return random.uniform(5.0, 15.0)
        return random.uniform(0.5, 2.0)

    def get_stealth_params(self, force_rotate: bool = False) -> Dict:
        if self.mobile_mode:
            # 👻 MOBILE GHOST HUNTER MODE
            profile_name = random.choice(list(self.MOBILE_IMPERSONATE.keys()))
            profile = self.MOBILE_IMPERSONATE[profile_name]
            
            headers = profile["headers"].copy()
            headers.update({
                "User-Agent": profile["ua"],
                "Sec-Ch-Ua-Mobile": "?1",
                "Sec-Ch-Ua-Platform": "\"iOS\"" if "iphone" in profile_name else "\"Android\""
            })
            
            return {
                "impersonate": profile["impersonate"],
                "headers": headers,
                "proxies": self.get_proxy_dict()
            }

        headers = {
            "User-Agent": random.choice(self.USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "DNT": "1",
            "Sec-GPC": "1",
            "Upgrade-Insecure-Requests": "1"
        }
        
        # Inject Akamai evasion headers if Akamai is detected OR if targeting hardened domains
        waf = self.active_waf or "Akamai"
        headers.update(self.get_evasion_headers(waf))
        
        return {
            "impersonate": random.choice(self.IMPERSONATE_TYPES),
            "headers": headers,
            "proxies": self.get_proxy_dict()
        }

    def get_proxy_dict(self) -> Optional[Dict]:
        if not self.proxy_list: return None
        proxy = self.swarm.get_best_proxy() or random.choice(self.proxy_list)
        return {"http": proxy, "https": proxy}

class ShadowProxyManager:
    """v25.0 OMEGA: Shadow Proxy Manager with Active Health Validation."""
    def __init__(self, proxy_file: str = "proxies.txt"):
        self.proxy_file = proxy_file
        self.proxies = []
        self.failed_proxies = {} # proxy -> failure count
        self.cooldown_pool = {} # proxy -> unlock_time
        self._load_proxies()

    def _load_proxies(self):
        if os.path.exists(self.proxy_file):
            try:
                with open(self.proxy_file, "r", encoding="utf-8") as f:
                    raw_proxies = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                
                if not raw_proxies:
                    self._add_default_gateways()
                    return

                console.print(f"[cyan][*] ShadowProxy: Actively validating {len(raw_proxies)} endpoints...[/cyan]")
                
                def check_proxy(p):
                    try:
                        # Use a low-latency target for fast validation
                        requests.get("http://1.1.1.1", proxies={"http": p, "https": p}, timeout=3)
                        return p
                    except: return None
                        
                with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                    self.proxies = [p for p in executor.map(check_proxy, raw_proxies) if p]
                    
                if len(self.proxies) < 3:
                    self._add_default_gateways()
                console.print(f"[bold green][✓] ShadowProxy: {len(self.proxies)} active nodes verified.[/bold green]")
            except Exception:
                self._add_default_gateways()
        else:
            self._add_default_gateways()

    def _add_default_gateways(self):
        fallbacks = ["http://144.202.114.156:8080", "http://45.76.220.10:8080", "http://95.179.167.112:8080"]
        for f in fallbacks:
            if f not in self.proxies: self.proxies.append(f)

    def get_shadow_node(self) -> str:
        now = time.time()
        # Reclaim cooled down nodes
        recovered = [p for p, unlock in list(self.cooldown_pool.items()) if now > unlock]
        for p in recovered:
            if p not in self.proxies: self.proxies.append(p)
            del self.cooldown_pool[p]
            self.failed_proxies[p] = 0

        available = [p for p in self.proxies if self.failed_proxies.get(p, 0) < 3]
        if not available:
            if self.cooldown_pool:
                console.print("[bold red][⚡] CIRCUIT BREAKER: All nodes in cooldown. Waiting 60s...[/bold red]")
                time.sleep(60)
                return self.get_shadow_node()
            return random.choice(self.proxies) if self.proxies else "http://127.0.0.1:8080"
            
        return random.choice(available)

    def report_failure(self, proxy: str):
        self.failed_proxies[proxy] = self.failed_proxies.get(proxy, 0) + 1
        if self.failed_proxies[proxy] >= 3 and proxy in self.proxies:
            try:
                self.proxies.remove(proxy)
                self.cooldown_pool[proxy] = time.time() + 600
                console.print(f"[bold yellow][🕒] Node {proxy} moved to 10-min cooldown.[/bold yellow]")
            except: pass

    def report_success(self, proxy: str):
        """v38.0: Resets failure counter on successful node usage."""
        self.failed_proxies[proxy] = 0

class AuraSession:
    """v25.0 OMEGA: High-stealth async session with JA3 impersonation."""
    _semaphore = asyncio.Semaphore(state.GLOBAL_CONCURRENCY_LIMIT)

    def __init__(self, stealth: StealthEngine):
        from aura.core.brain import AuraBrain
        self.stealth = stealth
        self.brain = AuraBrain()
        self.shadow_manager = ShadowProxyManager()
        self.latency_log = []
        self.stats = {"total": 0, "blocked": 0, "success": 0}
        self.consecutive_blocks = 0
        self.evasion_lock = asyncio.Lock()
        
        # Ghost profile state
        self.active_ua = self.stealth.USER_AGENTS[0]
        self.active_impersonate = self.stealth.IMPERSONATE_TYPES[0]

    async def aclose(self):
        """Placeholder for async cleanup."""
        pass

    async def close(self):
        await self.aclose()

    async def request(self, method, url, **kwargs):
        """v25.0 OMEGA+: Resilient Akamai-Slayer request handler."""
        self.stats["total"] += 1
        
        # Apply bio-mimetic jitter before the request
        delay = self.stealth.get_morphic_delay()
        await asyncio.sleep(delay)

        max_attempts = 3
        for attempt in range(max_attempts):
            async with self._semaphore:
                shadow_node = self.shadow_manager.get_shadow_node()
                
                # Dynamic Stealth Parameters
                params = self.stealth.get_stealth_params()
                req_kwargs = kwargs.copy()
                req_kwargs.setdefault("proxies", {"http": shadow_node, "https": shadow_node})
                req_kwargs.setdefault("impersonate", self.active_impersonate)
                req_kwargs.setdefault("verify", False)
                req_kwargs.setdefault("timeout", 30) # Increased for Akamai latencies
                
                # Merge Headers
                headers = params["headers"].copy()
                headers["User-Agent"] = self.active_ua # Preserve active ghost UA
                if "headers" in req_kwargs:
                    headers.update(req_kwargs["headers"])
                req_kwargs["headers"] = headers
                
                try:
                    start = time.perf_counter()
                    resp = await asyncio.to_thread(curlr.request, method, url, **req_kwargs)
                    latency = (time.perf_counter() - start) * 1000
                    
                    if resp and resp.status_code < 400:
                        self.stats["success"] += 1
                        self.consecutive_blocks = 0 # Reset on success
                        self.shadow_manager.report_success(shadow_node)
                        return resp
                    
                    # WAF/Block Detection
                    waf = self.stealth.detect_waf(resp.headers if resp else {}, resp.text if resp else "")
                    if resp and (resp.status_code in [403, 429] or waf):
                        self.stats["blocked"] += 1
                        self.consecutive_blocks += 1
                        self.shadow_manager.report_failure(shadow_node)
                        
                        console.print(f"[bold red][🛡️ WAF] Blocked on node {shadow_node} ({resp.status_code}/{waf}). Attempt {attempt+1}/{max_attempts}[/bold red]")
                        
                        # Sentient Behavioral Evasion: 3 consecutive blocks
                        if self.consecutive_blocks >= 3:
                            async with self.evasion_lock:
                                if self.consecutive_blocks >= 3:
                                    console.print("[bold purple][👻 GHOST] Behavioral Evasion Triggered: Heavy blocking detected. Entering Deceptive Cooling Loop...[/bold purple]")
                                    
                                    # 1. Rotate Fingerprint & UA
                                    self._rotate_ghost_profile()
                                    
                                    # 2. Random Benign Request
                                    await self._perform_benign_request(url)
                                    
                                    # 3. Circuit Breaker Cooling
                                    await asyncio.sleep(random.uniform(10, 20))
                                    self.consecutive_blocks = 0
                        
                        # Circuit Breaker: If attempt 2 fails, wait longer
                        if attempt == 1:
                            await asyncio.sleep(random.uniform(5, 10))
                        continue # Retry with new proxy
                    
                    return resp
                except Exception as e:
                    self.shadow_manager.report_failure(shadow_node)
                    if attempt == max_attempts - 1:
                        return None
                    continue
        return None

    async def get(self, url, **kwargs): return await self.request("GET", url, **kwargs)
    async def post(self, url, **kwargs): return await self.request("POST", url, **kwargs)

    def _rotate_ghost_profile(self):
        """v38.0: Forces a hard rotation of TLS/UA fingerprints."""
        params = self.stealth.get_stealth_params()
        self.active_ua = params["headers"]["User-Agent"]
        self.active_impersonate = params["impersonate"]
        console.print(f"[dim purple][*] Ghost Profile shifted: {self.active_impersonate} mimicry enabled.[/dim purple]")

    async def _perform_benign_request(self, original_url: str):
        """v38.0: Injects a random 'safe' request to mimic real user behavior."""
        try:
            parsed = urlparse(original_url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            benign_paths = ["/", "/robots.txt", "/favicon.ico", "/assets/app.css", "/api/v1/health"]
            target = urljoin(base, random.choice(benign_paths))
            
            console.print(f"[dim blue][🎭] Deception: Fetching benign {target} to clear behavioral profile...[/dim blue]")
            
            # Use raw httpx or low-level request to avoid recursion
            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                await client.get(target, headers={"User-Agent": random.choice(self.stealth.USER_AGENTS)})
        except Exception:
            pass
