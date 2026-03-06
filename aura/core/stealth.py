from curl_cffi import requests as curlr
import random
import time
import asyncio
from typing import Dict, Optional, List
from aura.core import state

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
    
    USER_AGENTS = [
        # Windows - Chrome
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        # Windows - Firefox
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
        # Windows - Edge
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
        # macOS - Chrome
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        # macOS - Safari
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        # macOS - Firefox
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:123.0) Gecko/20100101 Firefox/123.0",
        # Linux - Chrome
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
        # Mobile - iOS
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPad; CPU OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
        # Mobile - Android
        "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.64 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.5563.57 Mobile Safari/537.36",
        # Extra Niche
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 OPR/108.0.0.0",
        "Mozilla/5.0 (Linux; x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Vivaldi/6.6.3271.45"
    ]

    def __init__(self, proxy_list: Optional[list] = None, proxy_file: Optional[str] = None):
        self.proxy_list = proxy_list or []
        self.active_waf = None
        
        from aura.core import state
        final_proxy_file = proxy_file or state.PROXY_FILE
        
        if final_proxy_file:
            self.load_proxies(final_proxy_file)
        
        self.swarm = SwarmManager(self.proxy_list)
        self.battle_mode = False
            
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

    # ── v6.0: Polymorphic Payload Mutation ────────────────────────────────
    _mutation_counter: int = 0
    MUTATION_STRATEGIES = ["url_encode", "double_url_encode", "unicode_escape", "hex_encode", "whitespace", "comment", "base64_wrap", "newline_inject"]

    def mutate_payload(self, payload: str) -> str:
        """
        v6.0 Adaptive WAF Evasion: Rotates through 6 mutation strategies on each call.
        This provides Polymorphic Payloads — same attack, different shape every retry.
        """
        import urllib.parse
        strategy = self.MUTATION_STRATEGIES[self._mutation_counter % len(self.MUTATION_STRATEGIES)]
        StealthEngine._mutation_counter = (self._mutation_counter + 1) % len(self.MUTATION_STRATEGIES)

        if strategy == "url_encode":
            return urllib.parse.quote(payload, safe="")
        elif strategy == "double_url_encode":
            return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")
        elif strategy == "unicode_escape":
            return "".join(f"\\u{ord(c):04x}" if c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-." else c for c in payload)
        elif strategy == "hex_encode":
            return "".join(f"%{ord(c):02x}" if ord(c) > 32 and c not in "0123456789" else c for c in payload)
        elif strategy == "whitespace":
            # Inject harmless whitespace at various positions
            import re
            return re.sub(r'(\s+)', '\t ', payload).replace("SELECT", "SELECT/**/").replace("OR", "OR/**/").replace("AND", "AND/**/")
        elif strategy == "base64_wrap":
            import base64
            return base64.b64encode(payload.encode()).decode()
        elif strategy == "newline_inject":
            return payload.replace(" ", "\r\n ").replace("OR", "OR\n").replace("AND", "AND\n")
        else:  # comment injection
            return payload.replace(" ", "/**/").replace("'", "'/**/")

    async def human_jitter(self, min_ms: float = 300, max_ms: float = 1200):
        """v6.0: Human-like delay between requests to avoid anti-bot detection."""
        delay = random.uniform(min_ms / 1000, max_ms / 1000)
        await asyncio.sleep(delay)


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
        
        # v15.1 Infiltrator: Client-IP Spoofing (Bypass Rate Limits / Geo-blocks)
        spoofed_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        headers["X-Forwarded-For"] = spoofed_ip
        headers["X-Client-IP"] = spoofed_ip
        headers["X-Real-IP"] = spoofed_ip
        headers["True-Client-IP"] = spoofed_ip
        
        if any(x in ua.lower() for x in ["chrome", "edge", "chromium"]):
            headers["Sec-Ch-Ua"] = f'"Not/A)Brand";v="99", "Chromium";v="124", "Google Chrome";v="124"'
            headers["Sec-Ch-Ua-Mobile"] = "?0"
            headers["Sec-Ch-Ua-Platform"] = '"Windows"'
            if "edge" in ua.lower():
                headers["Sec-Ch-Ua"] = f'"Not/A)Brand";v="99", "Chromium";v="124", "Microsoft Edge";v="124"'
            
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


    async def hunt_origin_ip(self, domain: str) -> List[str]:
        """v24.0: Attempts to find the origin IP to bypass Cloudflare/WAF using crt.sh OSINT."""
        from rich.console import Console
        import aiohttp
        console = Console()
        console.print(f"[bold cyan][*] Origin Hunter: Engaging Certificate OSINT for {domain}...[/bold cyan]")
        
        origin_ips = []
        try:
            # Query crt.sh for subdomains that might point to real IPs
            # Note: In a production tool, you'd want to use a more robust search
            search_domain = domain.replace("www.", "")
            url = f"https://crt.sh/?q=%25.{search_domain}&output=json"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        subdomains = set()
                        for entry in data:
                            name_value = entry.get("name_value", "")
                            for sub in name_value.split("\n"):
                                if sub.strip() and "*" not in sub:
                                    subdomains.add(sub.strip())
                        
                        console.print(f"[dim cyan][+] Origin Hunter: Found {len(subdomains)} historical subdomains via crt.sh[/dim cyan]")
                        
                        import socket
                        for sub in list(subdomains)[:15]: # Limit resolution to avoid lag
                            try:
                                ip = socket.gethostbyname(sub)
                                # Check if IP is NOT Cloudflare (simplified check)
                                if ip and not any(ip.startswith(cf) for cf in ["104.", "172.", "108.", "162."]):
                                    console.print(f"[bold green][!] Origin Hunter: POTENTIAL BACKEND FOUND: {sub} -> {ip}[/bold green]")
                                    origin_ips.append(ip)
                            except: pass
                            
                        return origin_ips
        except Exception as e:
            console.print(f"[dim red][!] Origin Hunter OSINT Error: {e}[/dim red]")
            
        return origin_ips

    def get_proxy_dict(self, rotate: bool = False) -> Optional[Dict]:
        if not self.proxy_list:
            return None
        proxy = self.swarm.get_best_proxy() or random.choice(self.proxy_list)
        return {"http": proxy, "https": proxy}


class SmartRateLimiter:
    """
    Tier 4: Adaptive rate limiter that automatically backs off when
    WAF/rate-limit signals are detected, then ramps back up.

    Usage (as async context manager before each request):
        async with rate_limiter:
            res = await session.get(url)
        rate_limiter.record(res.status_code, res.text)

    Strategy:
      - 429 / 503       → double delay, enter COOLING state
      - WAF fingerprint  → triple delay, enter BLOCKED state
      - 200 / 301        → reduce delay by 20% (ramp up)
      - Max delay: 30s   Min delay: 0.3s
    """

    STATE_NORMAL  = "NORMAL"
    STATE_COOLING = "COOLING"
    STATE_BLOCKED = "BLOCKED"

    # WAF indicator strings in body/headers
    WAF_SIGNALS = [
        "access denied", "forbidden by waf", "cloudflare ray id",
        "incapsula", "akamai", "__cf_chl", "request blocked",
        "automated access", "bot detected", "ddos protection",
        "security check", "captcha", "challenge",
    ]

    def __init__(self, base_delay: float = 0.4, max_delay: float = 30.0):
        self.base_delay   = base_delay
        self.current_delay = base_delay
        self.max_delay    = max_delay
        self.state        = self.STATE_NORMAL
        self._last_status_code = 200
        self._consecutive_blocks = 0

    # Async context manager — use before each request
    async def __aenter__(self):
        if self.current_delay > 0:
            await asyncio.sleep(self.current_delay)
        return self

    async def __aexit__(self, *args):
        pass

    def record(self, status_code: int, body: str = "", headers: dict = None) -> None:
        """
        Call after every response to update the rate limiter state.
        Automatically adjusts delay based on server signals.
        """
        headers = headers or {}
        body_lower = (body or "").lower()[:500]

        # Check for WAF block
        is_waf = any(sig in body_lower for sig in self.WAF_SIGNALS) or \
                 any(sig in str(headers).lower() for sig in self.WAF_SIGNALS)

        if is_waf or status_code == 403:
            self._consecutive_blocks += 1
            self.state = self.STATE_BLOCKED
            self.current_delay = min(self.current_delay * 3, self.max_delay)
            from rich.console import Console
            Console().print(
                f"[bold red][RateLimit] WAF/Block detected! "
                f"Backing off to {self.current_delay:.1f}s (state: BLOCKED)[/bold red]"
            )

        elif status_code in (429, 503):
            self._consecutive_blocks += 1
            self.state = self.STATE_COOLING
            self.current_delay = min(self.current_delay * 2, self.max_delay)
            from rich.console import Console
            Console().print(
                f"[yellow][RateLimit] Rate-limited ({status_code})! "
                f"Cooling down to {self.current_delay:.1f}s[/yellow]"
            )

        elif status_code in (200, 201, 204, 301, 302, 304):
            # Ramp up: reduce delay by 20% per successful request, back towards base
            self._consecutive_blocks = 0
            self.state = self.STATE_NORMAL
            self.current_delay = max(
                self.base_delay,
                self.current_delay * 0.8
            )

    def is_blocked(self) -> bool:
        """Returns True if currently in a blocked/cooling state."""
        return self.state in (self.STATE_BLOCKED, self.STATE_COOLING)

    def reset(self):
        """Resets to base delay (call between different target scans)."""
        self.current_delay = self.base_delay
        self.state = self.STATE_NORMAL
        self._consecutive_blocks = 0

    def status_line(self) -> str:
        """Returns a one-line status string for logging."""
        return f"delay={self.current_delay:.1f}s state={self.state}"


class CloudSwarmManager:
    """Phase 8: Manages rotation through transient cloud IPs (AWS/GCP bridge)."""
    def __init__(self):
        # v18.1: Clean High-Reputation Pseudo-Cloud Swarm

        self.gateways = [
            # Note: In a production enterprise environment, these would be private API Gateways.
            # For this version, we use a curated list of high-uptime elastic IP structures.
            "http://144.202.114.156:8080", # US - Vultr Elite
            "http://45.76.220.10:8080",   # JP - Vultr Elite
            "http://207.148.27.149:8080",  # DE - Vultr Elite
            "http://149.28.140.245:8080",  # AU - Vultr Elite
            "http://95.179.167.112:8080"   # UK - Vultr Elite
        ]
        self.failed_nodes = set()

    def get_swarm_node(self) -> str:
        """Rotates to a clean high-reputation cloud IP."""
        available = [n for n in self.gateways if n not in self.failed_nodes]
        if not available:
            self.failed_nodes.clear() # Reset if all fail
            available = self.gateways
        return random.choice(available)

    def report_failure(self, node: str):
        self.failed_nodes.add(node)


class MorphicEngine:
    """
    v18.0 NEBULA GHOST
    AI Traffic Morphing & Behavioral Evasion Engine.
    """
    def __init__(self, brain):
        self.brain = brain
        self.user_session_templates = [
            {"name": "YouTube-Standard", "min_delay": 0.5, "max_delay": 3.0, "headers": {"Referer": "https://www.youtube.com/"}, "burst_freq": 0.1},
            {"name": "Google-Search", "min_delay": 1.0, "max_delay": 5.0, "headers": {"Referer": "https://www.google.com/"}, "burst_freq": 0.05},
            {"name": "LinkedIn-Scroll", "min_delay": 2.0, "max_delay": 8.0, "headers": {"Referer": "https://www.linkedin.com/feed/"}, "burst_freq": 0.2},
            {"name": "Developer-API", "min_delay": 0.1, "max_delay": 0.5, "headers": {"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"}, "burst_freq": 0.01}
        ]
        self.current_template = random.choice(self.user_session_templates)
        self.burst_active = False

    async def apply_morphic_jitter(self):
        """Applies bio-inspired timing jitter to the request."""
        # Phase 8: Behavioral Persona simulation
        if random.random() < self.current_template.get("burst_freq", 0.1):
            # User becomes "active" and clicks multiple things quickly
            jitter = random.uniform(0.1, 0.4)
        else:
            jitter = random.uniform(self.current_template["min_delay"], self.current_template["max_delay"])
        
        await asyncio.sleep(jitter)

    def get_morphic_headers(self, original_headers: dict) -> dict:
        """Morphs headers to match the current session template."""
        morphed = original_headers.copy()
        morphed.update(self.current_template["headers"])
        # v18.0: Dynamic User-Agent rotation within the same session 'persona'
        morphed["User-Agent"] = self._get_persona_ua()
        return morphed

    def _get_persona_ua(self):
        # High-reputation desktop UAs
        uas = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0"
        ]
        return random.choice(uas)


class AuraOpSecError(BaseException):
    """Custom exception for fatal OpSec failures to prevent messy tracebacks."""
    pass

class AuraSession:
    """A high-stealth wrapper using curl_cffi for Ghost v3 evasion."""
    
    # Global semaphore to prevent network saturation across all sessions
    _semaphore = asyncio.Semaphore(state.GLOBAL_CONCURRENCY_LIMIT)

    def __init__(self, stealth: StealthEngine):
        from aura.core.brain import AuraBrain
        self.stealth = stealth
        self.brain = AuraBrain()
        self.morphic = MorphicEngine(self.brain) # v18.0 Nebula Ghost
        self.swarm_manager = CloudSwarmManager() # Phase 8: Cloud Predator
        self.retries = 1  # v19.6: Siege Optimization - Reduced default from 3 to 1 to fast-fail dead nodes
        self.base_delay = 1.0 # v15.0: Adaptive Throttling Baseline
        self._opsec_verified = False
        
        # v15.1 Evasion Analytics
        self.stats = {
            "total_requests": 0,
            "blocked_requests": 0,
            "successful_requests": 0,
            "mutated_requests": 0,
            "start_time": time.time()
        }
    
    raw_headers = {
        "User-Agent": "Aura Intelligence Engine/15.1 (OSINT)",
        "Accept": "application/json",
        "DNT": "1"
    }

    def verify_opsec(self):
        """Phase 7: Strict OpSec Verification. Placed synchronously to guarantee no leaks before async loop."""
        if getattr(self, "_opsec_verified", False): return
        
        from rich.console import Console
        import requests
        import sys
        
        console = Console()
        console.print("[bold yellow][*] OpSec: Verifying Tor socks5h routing & identity masking...[/bold yellow]")
        
        ports = [9050, 9150] # Common Tor ports (9050=Standard, 9150=Tor Browser Windows)
        active_port = None
        real_ip = None

        try:
            # 1. Fetch real identity natively
            real_ip = requests.get("https://api.ipify.org?format=json", timeout=10).json().get("ip")
            
            # 2. Try each port
            for port in ports:
                try:
                    proxies = {
                        "http": f"socks5h://127.0.0.1:{port}",
                        "https": f"socks5h://127.0.0.1:{port}"
                    }
                    tor_ip = requests.get("https://api.ipify.org?format=json", proxies=proxies, timeout=10).json().get("ip")
                    
                    if tor_ip and tor_ip != real_ip:
                        active_port = port
                        console.print(f"[bold green][STEALTH] OPSEC VERIFIED: Identity masked via Port {port}. Traffic routed via Tor Node ({tor_ip})[/bold green]")
                        break
                except:
                    continue

            if not active_port:
                if real_ip:
                    console.print(f"[bold red][FATAL] FATAL OPSEC ERROR: Tor service is NOT detected on any standard port (9050, 9150).[/bold red]")
                    console.print("[yellow]>>> To fix this:[/yellow]")
                    console.print("[white]    1. Open the Tor Browser (Bundle) and wait for it to connect.[/white]")
                    console.print("[white]    2. Or ensure 'tor.exe' is running as a background service.[/white]")
                    console.print("[dim]    (Kill-Switch engaged to prevent IP leak)[/dim]")
                else:
                    console.print(f"[bold red][FATAL] FATAL OPSEC ERROR: No internet connection detected.[/bold red]")
                raise AuraOpSecError("OpSec Leak Protection Triggered")
                
            self._opsec_verified = True
            state.TOR_PORT = active_port # Save for subsequent requests
            
        except AuraOpSecError:
            raise
        except Exception as e:
            console.print(f"[bold red][FATAL] FATAL OPSEC CONNECTION ERROR: {e}[/bold red]")
            raise AuraOpSecError(str(e))

    async def request(self, method, url, raw=False, **kwargs):
        """Executes a request with JA3 impersonation (unless raw=True) and Ghost v3 adaptive evasion."""
        brain = self.brain
        self.stats["total_requests"] += 1
        
        # Phase 7 Absolute Stealth: OpSec Enforcement
        if getattr(state, "TOR_MODE", False):
            if not getattr(self, "_opsec_verified", False):
                self.verify_opsec()
            
            port = getattr(state, "TOR_PORT", 9050)
            kwargs["proxies"] = {
                "http": f"socks5h://127.0.0.1:{port}",
                "https": f"socks5h://127.0.0.1:{port}"
            }
        
        # Phase 8: Cloud Swarm Routing
        if getattr(state, "CLOUD_SWARM_MODE", False):
            try:
                swarm_node = self.swarm_manager.get_swarm_node()
                kwargs["proxies"] = {"http": swarm_node, "https": swarm_node}
            except Exception as e:
                print(f"[bold yellow][!] Cloud Swarm Configuration Error: {e}. Falling back to Direct.[/bold yellow]")
        
        
        if raw:
            # v18.1 Clean Channel Upgrade: Direct API communication with silent retries
            req_kwargs = kwargs.copy()
            # v18.1 Centralized Timeout Guard
            timeout_val = req_kwargs.get("timeout", state.NETWORK_TIMEOUT)
            if (state.TOR_MODE or state.CLOUD_SWARM_MODE) and timeout_val < 15:
                # v19.6 Siege Fix: Decreased from 30s to 15s to fail faster on dead proxy links
                timeout_val = 15
            req_kwargs["timeout"] = timeout_val
            
            headers = req_kwargs.get("headers", {})
            headers.setdefault("User-Agent", "Aura Intelligence Engine/18.1 (OSINT)")
            req_kwargs["headers"] = headers
            
            for attempt in range(3): # Silent retries for OSINT APIs
                try:
                    return await asyncio.to_thread(curlr.request, method, url, **req_kwargs)
                except Exception as e:
                    err_msg = str(e).lower()
                    if ("timeout" in err_msg or "28" in err_msg) and attempt < 2:
                        # Silently rotate proxy 
                        if getattr(state, "CLOUD_SWARM_MODE", False):
                            current_node = req_kwargs.get("proxies", {}).get("http")
                            if current_node: self.swarm_manager.report_failure(current_node)
                            req_kwargs["proxies"] = {"http": self.swarm_manager.get_swarm_node(), "https": self.swarm_manager.get_swarm_node()}
                        continue
                    
                    if attempt == 2: # Only print on final failure
                        print(f"[dim red][!] Raw Session Error: {type(e).__name__} after 3 attempts.[/dim red]")
            return None

        # v19.6: Allow callers (like Siege) to force max_attempts
        max_attempts = kwargs.pop("max_attempts", self.retries + 3) # Allow callers to override or default to retries + 3
        for attempt in range(max_attempts):
            # v18.0 Nebula Ghost: Morphic Stealth Activation
            if self.stealth.active_waf:
                await self.morphic.apply_morphic_jitter()
                
            params = self.stealth.get_stealth_params(force_rotate=(attempt > 0))
            current_proxy = params["proxies"]["http"] if params["proxies"] else None
            
            # v15.1 Infiltrator Jitter: Adaptive delay matching human patterns
            delay = self.base_delay * random.uniform(0.5, 1.5)
            if self.stealth.active_waf:
                # If WAF detected or high-stealth required, enter "Ghost Crawl" mode (2-5s)
                delay = random.uniform(2.0, 5.0)
            
            if delay > 0.1:
                await asyncio.sleep(delay)
            
            # v15.1 Decoy Traffic: Occasionally blend in for the first request or periodically
            if attempt == 0 and random.random() > 0.8:
                await self._send_decoy_request(url)
            
            async with self._semaphore:
                # Merge kwargs with Ghost v3 params
                req_kwargs = kwargs.copy()
                req_kwargs.setdefault("impersonate", params["impersonate"])
                
                # v18.0 Morphic Headers
                if self.stealth.active_waf:
                    headers = self.morphic.get_morphic_headers(params["headers"])
                    req_kwargs.setdefault("headers", headers)
                else:
                    req_kwargs.setdefault("headers", params["headers"])
                    
                # Phase 16.4: Inject user-defined custom headers
                if state.CUSTOM_HEADERS:
                    current_headers = req_kwargs.get("headers", {})
                    current_headers.update(state.CUSTOM_HEADERS)
                    req_kwargs["headers"] = current_headers
                    
                # Phase 16.4: Inject user-defined custom cookies
                if state.CUSTOM_COOKIES:
                    current_cookies = req_kwargs.get("cookies", {})
                    current_cookies.update(state.CUSTOM_COOKIES)
                    req_kwargs["cookies"] = current_cookies
                    
                req_kwargs.setdefault("proxies", params["proxies"])
                
                # v18.1 Centralized Timeout Guard: Enforce state.NETWORK_TIMEOUT minimum for stability
                timeout_val = req_kwargs.get("timeout", state.NETWORK_TIMEOUT)
                if (state.TOR_MODE or state.CLOUD_SWARM_MODE) and timeout_val < 15:
                    timeout_val = 15 # v19.6 Siege Fix: Reduced Tor padding from 30s to 15s
                req_kwargs["timeout"] = timeout_val
                
                req_kwargs.setdefault("verify", False)
                
                try:
                    resp = await asyncio.to_thread(curlr.request, method, url, **req_kwargs)
                except Exception as e:
                    # Phase 8.1: Handle Proxy Errors (Cloud Swarm / Custom Proxy)
                    err_msg = str(e).lower()
                    if "proxy" in err_msg or "connection error" in err_msg or "11001" in err_msg:
                        if getattr(state, "CLOUD_SWARM_MODE", False):
                            current_node = req_kwargs.get("proxies", {}).get("http")
                            if current_node:
                                self.swarm_manager.report_failure(current_node)
                            print(f"[bold yellow][FIX] Cloud Swarm Node Failure ({type(e).__name__}). Rotating...[/bold yellow]")
                            if attempt < max_attempts - 1: continue
                        
                        # Fallback to Tor if Cloud fails and Tor is available
                        if getattr(state, "CLOUD_SWARM_MODE", False) and not getattr(state, "TOR_MODE", False):
                            print(f"[bold cyan][GUARD] Cloud Swarm Drained. Attempting Emergency Tor Routing...[/bold cyan]")
                            state.TOR_MODE = True
                            state.CLOUD_SWARM_MODE = False
                            if attempt < max_attempts - 1: continue

                    # v16.2 Stealth Hardening: Fallback Mechanism for ImpersonateError
                    if "impersonate" in err_msg or "not supported" in err_msg:
                        print(f"[bold yellow][FIX] Stealth Fallback: '{req_kwargs.get('impersonate')}' failed. Retrying with 'chrome110'...[/bold yellow]")
                        req_kwargs["impersonate"] = "chrome110"
                        try:
                            resp = await asyncio.to_thread(curlr.request, method, url, **req_kwargs)
                        except Exception as inner_e:
                            print(f"[bold red][!] Session Error (Fallback failed): {inner_e}[/bold red]")
                            if attempt == max_attempts - 1: return None
                            continue
                    else:
                        is_timeout = "timeout" in err_msg or "28" in err_msg
                        if is_timeout and attempt < 2 and max_attempts > 1:
                            # v18.1 Silent Rotation: Don't scream for transient timeouts
                            if getattr(state, "CLOUD_SWARM_MODE", False):
                                current_node = req_kwargs.get("proxies", {}).get("http")
                                if current_node: self.swarm_manager.report_failure(current_node)
                            if attempt < max_attempts - 1: continue
                        
                        print(f"[bold red][!] Session Error ({type(e).__name__}): {e}[/bold red]")
                        if attempt == max_attempts - 1:
                            return None
                        continue
                    
                if resp is None:
                    # Should rarely happen with curl_cffi but safety first
                    print(f"[bold red][!] Critical Network Error: Received null response for {url}[/bold red]")
                    if attempt < max_attempts - 1:
                        continue
                    return None # Or a mock response object

                waf = self.stealth.detect_waf(resp.headers, resp.text)
                if resp.status_code in [403, 429]:
                    self.stats["blocked_requests"] += 1
                    if current_proxy: self.stealth.swarm.report_failure(current_proxy)
                    
                    if resp.status_code == 429:
                        self.base_delay = min(self.base_delay * 1.5, 20.0) # Adaptive Backoff Trigger for Rate Limits
                    else:
                        self.base_delay = min(self.base_delay * 1.1, 5.0)  # Gentle backoff for WAF 403s
                    
                    # v16.0 Omni-Sovereign: Self-Healing Loop Activation
                    mutated = False
                    if brain.enabled and attempt < 2: # Limit payload mutations to 2 attempts max to prevent freezes
                         self.stats["mutated_requests"] += 1
                         print(f"[bold yellow][FIX] Self-Heal: Block detected ({resp.status_code}). Mutating payload...[/bold yellow]")
                         # Mutate POST data if string
                         if "data" in req_kwargs and isinstance(req_kwargs["data"], str):
                             req_kwargs["data"] = brain.self_heal_mutation(
                                 req_kwargs["data"], 
                                 resp.status_code, 
                                 resp.text, 
                                 attempt
                             )
                             mutated = True
                         # Mutate GET parameters
                         if "params" in req_kwargs and isinstance(req_kwargs["params"], dict):
                             for k, v in req_kwargs["params"].items():
                                 req_kwargs["params"][k] = brain.self_heal_mutation(
                                     str(v), 
                                     resp.status_code, 
                                     resp.text, 
                                     attempt
                                 )
                             mutated = True
                    
                    # If we successfully mutated, retry.
                    # Or if it's a 429 rate limit, we keep retrying up to max_attempts.
                    if mutated and attempt < 2: # [Fix] Strict mutation cap immediately applied
                        continue
                    if resp.status_code == 429 and attempt < max_attempts - 1:
                        continue
                        
                    return resp # For insurmountable 403s, just return rather than infinite looping
                             
                
                # v15.0: On Success, gradually increase speed
                if resp.status_code < 400:
                    self.stats["successful_requests"] += 1
                    self.base_delay = max(self.base_delay * 0.95, 0.3)
                    
                if current_proxy: self.stealth.swarm.report_success(current_proxy)
                return resp

    async def get(self, url, raw=False, **kwargs):
        return await self.request("GET", url, raw=raw, **kwargs)

    async def post(self, url, raw=False, **kwargs):
        return await self.request("POST", url, raw=raw, **kwargs)

    async def _send_decoy_request(self, target_url):
        """v15.1: Sends a benign request to a common asset to blend in with normal traffic."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            decoys = ["/favicon.ico", "/robots.txt", "/sitemap.xml", "/main.css", "/index.html", "/assets/images/logo.png"]
            decoy_path = random.choice(decoys)
            decoy_url = f"{base_url.rstrip('/')}{decoy_path}"
            
            params = self.stealth.get_stealth_params()
            # Low-overhead minimal fetch
            await asyncio.to_thread(
                curlr.get, 
                decoy_url, 
                impersonate=params["impersonate"], 
                headers=params["headers"], 
                timeout=3, 
                verify=False
            )
        except:
            pass
