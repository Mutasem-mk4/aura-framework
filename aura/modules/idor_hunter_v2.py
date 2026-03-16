"""
Aura v51.0 — IDOR 2.0 (Sentient Context Bleeding Engine) 🧠⚡
============================================================
A fully asynchronous, AI-powered Horizontal/Vertical Privilege Escalation engine.
Features:
- Cross-Tenant Auth Matrix (User A vs User B comparison)
- Context Bleeding Detection (AI identifies sensitive data leakage)
- Nexus Accelerated Probing (High-speed ID range testing)
- Deep Logic Integration (Seamlessly plugs into StatefulLogicFuzzer)
"""
import asyncio
import json
import os
import re
import time
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
import httpx
from aura.core.brain import AuraBrain
from aura.core.nexus_bridge import NexusBridge

console = Console()

class IDORHunterV2:
    """
    v51.0 OMEGA: IDOR 2.0.
    The ultimate BOLA/IDOR/Context-Bleeding engine.
    """

    def __init__(self, session: Optional[httpx.AsyncClient] = None):
        self.session = session
        self.brain = AuraBrain()
        self.findings: List[Dict[str, Any]] = []
        try:
            self.nexus = NexusBridge()
        except:
            self.nexus = None
            
        # Session state for cross-tenant comparison
        self.attacker_cookies = self._parse_env_cookies("AUTH_TOKEN_ATTACKER")
        self.victim_cookies = self._parse_env_cookies("AUTH_TOKEN_VICTIM")
        self.is_cross_tenant = bool(self.victim_cookies)

    def _parse_env_cookies(self, env_key: str) -> Dict[str, str]:
        raw = os.getenv(env_key, "")
        if not raw: return {}
        cookies = {}
        for part in raw.split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                cookies[k.strip()] = v.strip()
        return cookies

    async def _get_client(self, cookies: Dict[str, str]) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            cookies=cookies,
            headers={"User-Agent": "Aura-Sentient-Logic/51.0"},
            verify=False,
            follow_redirects=True,
            timeout=15
        )

    async def test_endpoint(self, url: str, method: str = "GET", data: Optional[Dict] = None, attacker_id: Optional[str] = None, victim_id: Optional[str] = None):
        """
        Tests for IDOR by swapping context between sessions.
        """
        if not self.is_cross_tenant:
            console.print("[dim yellow][!] IDOR 2.0: Victim token not set. Running in blind neighbor-probe mode.[/dim yellow]")
            return await self._neighbor_probe(url, method, data)

        console.print(f"[bold cyan][⚡ IDOR 2.0] Analyzing Context Matrix: {method} {url}[/bold cyan]")
        
        # 1. Attacker Accessing Own Resource (Baseline)
        async with await self._get_client(self.attacker_cookies) as attacker_client:
            r_baseline = await self._safe_req(attacker_client, method, url, data)
        
        # 2. Attacker Accessing Victim Resource (The actual IDOR attempt)
        # We assume 'url' or 'data' contains IDs that need to be swapped.
        malicious_url = url
        malicious_data = data.copy() if data else None
        
        if attacker_id and victim_id:
            malicious_url = url.replace(attacker_id, victim_id)
            if malicious_data:
                # Recursively swap IDs in JSON body
                malicious_data = self._swap_ids_in_dict(malicious_data, attacker_id, victim_id)
        
        async with await self._get_client(self.attacker_cookies) as attacker_client:
            r_attack = await self._safe_req(attacker_client, method, malicious_url, malicious_data)

        # 3. Decision Logic (Auth Matrix + AI)
        is_vuln = False
        reason = ""
        
        if r_attack["status"] == 200 and r_attack["status"] == r_baseline["status"]:
            # Potential Leak: Check if content actually belongs to victim
            if self.brain.enabled:
                ai_analysis = self.brain.analyze_business_logic(
                    {"url": malicious_url, "method": method, "data": malicious_data},
                    {"status": r_attack["status"], "body": r_attack["body"][:2000]}
                )
                # If AI confirms PII or unauthorized data
                if any("idor" in str(f).lower() or "bola" in str(f).lower() for f in ai_analysis):
                    is_vuln = True
                    reason = f"AI Confirmed Context Bleeding: {ai_analysis[0].get('reason')}"
            else:
                # Basic Comparison Fallback
                if len(r_attack["body"]) > 50 and r_attack["status"] == 200:
                    is_vuln = True
                    reason = "Response size and pattern matches unauthorized resource access."

        if is_vuln:
            evidence = (
                f"IDOR / BOLA Confirmed on {url}\n"
                f"Attacker accessed resource {victim_id} using their own session.\n"
                f"Status: {r_attack['status']} | Length: {len(r_attack['body'])}\n"
                f"Reasoning: {reason}"
            )
            console.print(Panel(evidence, title="[bold red]IDOR CONFIRMED[/bold red]", border_style="red"))
            self.findings.append({
                "type": "IDOR / BOLA",
                "severity": "CRITICAL" if method != "GET" else "HIGH",
                "url": url,
                "evidence": evidence
            })

    async def _safe_req(self, client: httpx.AsyncClient, method: str, url: str, data: Optional[Dict]) -> Dict:
        try:
            if method.upper() == "POST":
                resp = await client.post(url, json=data)
            elif method.upper() == "PUT":
                resp = await client.put(url, json=data)
            elif method.upper() == "PATCH":
                resp = await client.patch(url, json=data)
            elif method.upper() == "DELETE":
                resp = await client.delete(url)
            else:
                resp = await client.get(url)
            return {"status": resp.status_code, "body": resp.text, "headers": dict(resp.headers)}
        except Exception as e:
            return {"status": 0, "body": str(e), "headers": {}}

    def _swap_ids_in_dict(self, d: Any, old_id: str, new_id: str) -> Any:
        if isinstance(d, dict):
            return {k: self._swap_ids_in_dict(v, old_id, new_id) for k, v in d.items()}
        elif isinstance(d, list):
            return [self._swap_ids_in_dict(i, old_id, new_id) for i in d]
        elif str(d) == old_id:
            return new_id
        return d

    async def _neighbor_probe(self, url: str, method: str, data: Optional[Dict]):
        # Fallback for single account: probe +/- 5 around numeric IDs
        num_ids = re.findall(r'/(\d{3,})(?:/|$|\?)', url)
        if not num_ids: return
        
        base_id = int(num_ids[-1])
        console.print(f"[yellow][!] Neighbor Probing around {base_id}...[/yellow]")
        
        if self.nexus and method.upper() == "GET":
            # Accelerated range probing via Nexus
            probe_urls = [url.replace(str(base_id), str(i)) for i in range(base_id - 50, base_id + 51) if i != base_id]
            console.print(f"[bold cyan][Nexus] Bursting {len(probe_urls)} ID probes...[/bold cyan]")
            
            # Go result is [Result{URL, StatusCode, Length, Server, Title}, ...]
            results = self.nexus.probe_urls(probe_urls)
            for r in results:
                if r["status"] == 200 and r["length"] > 100:
                    console.print(f"  [red][!] ID Probe Hit: {r['url']} (Size: {r['length']})[/red]")
                    self.findings.append({
                        "type": "IDOR / BOLA",
                        "severity": "HIGH",
                        "url": r["url"],
                        "evidence": f"Nexus ID Probe confirmed accessibility of resource: {r['url']}"
                    })
            return

        async with await self._get_client(self.attacker_cookies) as client:
            for i in range(base_id - 5, base_id + 6):
                if i == base_id: continue
                test_url = url.replace(str(base_id), str(i))
                resp = await self._safe_req(client, method, test_url, data)
                if resp["status"] == 200 and len(resp["body"]) > 50:
                    console.print(f"  [red][!] Neighbor ID {i} accessible! Possible IDOR.[/red]")
                    self.findings.append({"type": "IDOR", "url": test_url, "severity": "MEDIUM"})
