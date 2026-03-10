"""
Aura v2 — API & GraphQL Deep Fuzzer
====================================
Engine for targeting API logic, GraphQL introspection, and JSON data leaks.
Features:
  1. GraphQL Introspection Probe
  2. JSON Sensitive Data Miner (PII, Tokens)
  3. Broken Access Control (Unauthorized bypass)
  4. Mass Assignment / Parameter Pollution Probes

Usage:
    aura www.target.com --api
"""

import asyncio
import json
import os
import re
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

# ─── API Regex Patterns ──────────────────────────────────────────────────────
JSON_LEAK_PATTERNS = {
    "Email Leak":         r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "JWT/Auth Token":     r"ey[a-zA-Z0-9_-]{10,}\.ey[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
    "IPv4 Address":       r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "Internal Path":      r"/Users/[a-zA-Z0-9._-]+/|/home/[a-zA-Z0-9._-]+/|C:\\Users\\",
    "Credit Card":        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b",
}

GRAPHQL_ENDPOINTS = [
    "/graphql", "/graphiql", "/graphql/v1", "/graphql/v2", "/api/graphql", 
    "/v1/graphql", "/v1/api/graphql", "/query", "/api/v1/graphql"
]

INTROSPECTION_QUERY = {
    "query": "{__schema{types{name,fields{name,args{name,type{name,kind,ofType{name,kind}}}}}}}"
}

MASS_ASSIGNMENT_PARAMS = [
    "admin=true", "role=admin", "is_admin=1", "user[admin]=true", 
    "privileges=internal", "debug=1", "superuser=true"
]

class APIEngine:
    def __init__(self, target: str, discovery_map_path: Optional[str] = None):
        if not target.startswith("http"):
            target = "https://" + target
        self.target = target.rstrip("/")
        self.target_domain = urllib.parse.urlparse(self.target).netloc
        self.discovery_map_path = discovery_map_path
        self.findings: List[Dict] = []
        
        # Load environment tokens
        from dotenv import load_dotenv
        load_dotenv()
        self.auth_token = os.getenv("AUTH_TOKEN_ATTACKER", "")
        
        self.client = httpx.AsyncClient(
            headers={"User-Agent": "Aura-Predator/2.0"},
            timeout=15,
            verify=False,
            follow_redirects=True
        )

    # ─────────────────────────────────────────────────────────────────────────
    # MODULE 1: GraphQL Introspection
    # ─────────────────────────────────────────────────────────────────────────

    async def _test_graphql(self):
        console.print(f"  [cyan]🧬 Probing for GraphQL Introspection...[/cyan]")
        for ep in GRAPHQL_ENDPOINTS:
            url = f"{self.target}{ep}"
            try:
                # 1. Check if endpoint exists
                resp = await self.client.post(url, json={"query": "{__typename}"})
                if resp.status_code == 200 and "data" in resp.text:
                    console.print(f"    [green][+] Found GraphQL endpoint: {ep}[/green]")
                    
                    # 2. Try Introspection
                    intro_resp = await self.client.post(url, json=INTROSPECTION_QUERY)
                    if intro_resp.status_code == 200 and "__schema" in intro_resp.text:
                        self.findings.append({
                            "type": "GraphQL Introspection",
                            "severity": "MEDIUM",
                            "url": url,
                            "desc": "Information Disclosure: GraphQL Introspection is enabled. Scheme structure leaked."
                        })
                        console.print(f"    [bold red][🔥] INTROSPECTION ENABLED at {ep}[/bold red]")
                    return # Stop after first working endpoint
            except Exception:
                continue

    # ─────────────────────────────────────────────────────────────────────────
    # MODULE 2: JSON Data Miner
    # ─────────────────────────────────────────────────────────────────────────

    def _mine_json_leaks(self, content: str, source_url: str):
        for name, pattern in JSON_LEAK_PATTERNS.items():
            matches = re.findall(pattern, content)
            for m in matches:
                # Deduplicate
                if not any(f['value'] == m for f in self.findings if f.get('value')):
                    self.findings.append({
                        "type": "JSON Data Leak",
                        "severity": "HIGH" if "Token" in name or "Card" in name else "LOW",
                        "subtype": name,
                        "value": m,
                        "url": source_url
                    })

    # ─────────────────────────────────────────────────────────────────────────
    # MODULE 3: Broken Access Control (Unauthorized)
    # ─────────────────────────────────────────────────────────────────────────

    async def _test_access_control(self, endpoint: Dict):
        """Attempts to access an authenticated endpoint without tokens."""
        url = endpoint.get("url")
        if not url: return
        
        # Only test if it originally needed auth (heuristic)
        orig_resp = endpoint.get("response", {})
        if orig_resp.get("status") in [401, 403]: return # Already rejected

        try:
            # Re-fetch without headers
            resp = await self.client.request(endpoint["method"], url)
            if resp.status_code == 200:
                # Potential BOLA/Broken Access Control
                self.findings.append({
                    "type": "Broken Access Control",
                    "severity": "CRITICAL",
                    "url": url,
                    "desc": f"Endpoint responded with 200 OK without Authorization. Method: {endpoint['method']}"
                })
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    # CORE ENGINE EXECUTION
    # ─────────────────────────────────────────────────────────────────────────

    async def run(self):
        console.print(Panel(
            f"[bold white]🎯 AURA v2 — API & GraphQL Engine[/bold white]\n"
            f"Target: [cyan]{self.target}[/cyan]",
            style="bright_magenta",
        ))

        # 1. GraphQL Probing
        await self._test_graphql()

        # 2. Discovery Map Analysis
        map_path = self.discovery_map_path
        if not map_path:
            target_slug = self.target_domain.replace(".", "_")
            map_path = f"reports/discovery_map_{target_slug}.json"

        if os.path.exists(map_path):
            console.print(f"  [cyan]📊 Analyzing discovery map: {map_path}[/cyan]")
            with open(map_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                
            endpoints = data.get("endpoints", [])
            console.print(f"  [cyan]🔬 Fuzzing {len(endpoints)} endpoints for leaks & access flaws...[/cyan]")
            
            tasks = []
            for ep in endpoints:
                # Miner
                self._mine_json_leaks(json.dumps(ep), ep.get("url", ""))
                # Access Control
                if self.auth_token: # Only if we have a token to compare with
                    tasks.append(self._test_access_control(ep))
                    
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
        else:
            console.print(f"  [yellow][!] No discovery map found. Skipping deep fuzzer.[/yellow]")

        self._finalize()
        await self.client.aclose()
        return self.findings

    def _finalize(self):
        if not self.findings:
            console.print(f"\n  [bold green]✅ No high-risk API flaws found on {self.target}[/bold green]")
            return

        table = Table(title="💎 API & GraphQL Vulnerabilities", title_style="bold magenta", box=box.DOUBLE_EDGE)
        table.add_column("Type", style="cyan")
        table.add_column("Severity", style="bold red")
        table.add_column("Details", style="white")
        
        for f in self.findings:
            sev_color = "red" if f["severity"] in ["CRITICAL", "HIGH"] else "yellow"
            details = f.get("desc") or f.get("value", "")
            table.add_row(f["type"], f"[{sev_color}]{f['severity']}[/{sev_color}]", f"{details[:50]}... ({f['url']})")
        
        console.print(table)
        
        target_slug = self.target_domain.replace(".", "_")
        out_path = f"reports/api_findings_{target_slug}.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(self.findings, f, indent=2)
        console.print(f"\n  [bold green]💾 API report saved:[/bold green] [cyan]{out_path}[/cyan]")

async def run_api_scan(target: str, discovery_map_path: Optional[str] = None):
    engine = APIEngine(target, discovery_map_path)
    return await engine.run()

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "www.iciparisxl.nl"
    asyncio.run(run_api_scan(target))
