"""
Aura v3 Omni — Web Security Engine (Hyper-Speed Async)
======================================================
High-impact, fast-running checks that catch real bugs.
Now powered by the AsyncRequester core for lightning-fast execution!

Modules:
  1. CORS Misconfiguration
  2. Open Redirect
  3. Rate Limiting
  4. Security Headers
"""

import asyncio
import json
import os
import re
import time
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict

from aura.core.async_requester import AsyncRequester

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

# ─── Configuration ─────────────────────────────────────────────────────────────

CORS_SENSITIVE_PATHS = [
    "/api/v1/me", "/api/v2/me", "/api/me", "/api/user",
    "/api/v1/profile", "/api/v2/profile", "/api/profile",
    "/api/v1/account", "/api/account",
    "/api/v1/users", "/api/v2/users",
    "/api/orders", "/api/v1/orders", "/api/v2/orders",
    "/api/payments", "/api/v1/payments",
    "/api/admin", "/api/v1/admin",
    "/api/v1/dashboard", "/api/dashboard",
    "/api/v1/settings", "/api/settings",
    "/graphql",
]

CORS_TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "https://{domain}.evil.com",
]

REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirect_url", "return", "returnUrl",
    "return_url", "next", "url", "target", "goto", "destination",
    "redir", "ref", "referer", "forward", "continue", "callback",
    "successUrl", "failureUrl",
]

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "https://evil.com%2F@{domain}",
    "https://{domain}.evil.com",
    "/\\evil.com",
    "https://evil.com?{domain}",
]

REDIRECT_TRIGGER_PATHS = [
    "/login", "/signin", "/auth/login", "/logout", "/signout",
    "/oauth/authorize", "/connect", "/auth/callback", "/sso",
    "/redirect", "/out", "/go", "/link",
]

RATE_LIMIT_TARGETS = [
    {"path": "/login", "method": "POST", "body": {"email": "test@example.com", "password": "WrongPass123!"}, "label": "Login brute-force protection"},
    {"path": "/forgot-password", "method": "POST", "body": {"email": "test@example.com"}, "label": "Password reset rate limit"},
    {"path": "/api/v1/auth/mfa/verify", "method": "POST", "body": {"code": "000000"}, "label": "OTP/2FA brute-force protection"},
]
RATE_LIMIT_ATTEMPTS = 20
RATE_LIMIT_THRESHOLD = 15

SECURITY_HEADERS = {
    "strict-transport-security": {"label": "HSTS", "severity": "MEDIUM", "impact": "Users can be attacked over HTTP", "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"},
    "content-security-policy": {"label": "CSP", "severity": "MEDIUM", "impact": "XSS attacks have higher impact", "recommendation": "Add: Content-Security-Policy: default-src 'self'"},
    "x-frame-options": {"label": "X-Frame-Options", "severity": "LOW", "impact": "Clickjacking risk", "recommendation": "Add: X-Frame-Options: DENY"},
}


class WebSecurityEngine:
    """
    Hyper-Speed Async Web Security Engine.
    """

    def __init__(self, target: str, cookies_str: str = "", output_dir: str = "./reports", timeout: int = 15, proxy_file: Optional[str] = None):
        if not target.startswith("http"):
            target = "https://" + target
        self.target = target.rstrip("/")
        self.target_domain = urllib.parse.urlparse(self.target).netloc
        self.cookies = self._parse_cookies(cookies_str)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.proxy_file = proxy_file
        self.findings: list[dict] = []

    @staticmethod
    def _parse_cookies(cookie_str: str) -> dict:
        cookies = {}
        for part in (cookie_str or "").split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                cookies[k.strip()] = v.strip()
        return cookies

    def _add_finding(self, finding: dict):
        self.findings.append(finding)

    async def scan_cors(self, requester: AsyncRequester) -> list[dict]:
        findings = []
        console.print("\n  [bold]🌐 CORS Misconfiguration Scan (Async)[/bold]")

        requests = []
        for path in CORS_SENSITIVE_PATHS:
            for origin_template in CORS_TEST_ORIGINS:
                origin = origin_template.replace("{domain}", self.target_domain)
                requests.append({
                    "method": "GET",
                    "url": self.target + path,
                    "cookies": self.cookies,
                    "headers": {"Origin": origin},
                    "follow_redirects": True
                })

        # Fire them all off concurrently!
        results = await requester.fetch_all(requests)

        for req, resp in zip(requests, results):
            if not resp or resp.status_code in (401, 404): continue

            origin = req["headers"]["Origin"]
            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "")

            if (acao == origin or acao == "*") and acac.lower() == "true":
                severity = "CRITICAL" if acao == origin else "HIGH"
                finding = {
                    "type": "CORS Misconfiguration",
                    "severity": severity,
                    "cvss_score": 8.8 if severity == "CRITICAL" else 7.4,
                    "url": req["url"],
                    "origin_sent": origin,
                    "acao_header": acao,
                    "acac_header": acac,
                    "timestamp": datetime.utcnow().isoformat(),
                }
                # Prevent duplicates
                if not any(f["url"] == finding["url"] for f in findings):
                    findings.append(finding)
                    self._add_finding(finding)
                    console.print(f"     [bold red]🚨 CORS! {req['url']} — ACAO: {acao} + ACAC: true[/bold red]")

        if not findings:
            console.print("     [green]✅ No CORS misconfiguration found[/green]")
        return findings

    async def scan_open_redirect(self, requester: AsyncRequester) -> list[dict]:
        findings = []
        console.print("\n  [bold]↪️  Open Redirect Scan (Async)[/bold]")

        requests = []
        for path in REDIRECT_TRIGGER_PATHS:
            for param in REDIRECT_PARAMS[:6]:
                for payload_template in REDIRECT_PAYLOADS:
                    payload = payload_template.replace("{domain}", self.target_domain)
                    test_url = f"{self.target}{path}?{param}={urllib.parse.quote(payload, safe=':/.')}"
                    requests.append({
                        "method": "GET",
                        "url": test_url,
                        "cookies": self.cookies,
                        "follow_redirects": False,
                    })

        results = await requester.fetch_all(requests)

        for req, resp in zip(requests, results):
            if not resp: continue
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location", "")
                if "evil.com" in location:
                    finding = {
                        "type": "Open Redirect",
                        "severity": "MEDIUM",
                        "cvss_score": 6.1,
                        "url": req["url"],
                        "redirect_to": location,
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                    if not any(f["url"].split("?")[0] == finding["url"].split("?")[0] for f in findings):
                        findings.append(finding)
                        self._add_finding(finding)
                        console.print(f"     [bold red]🚨 OPEN REDIRECT: {req['url']} → {location[:60]}[/bold red]")

        if not findings:
            console.print("     [green]✅ No open redirect found[/green]")
        return findings

    async def scan_rate_limiting(self, requester: AsyncRequester) -> list[dict]:
        findings = []
        console.print("\n  [bold]⏱️  Rate Limit Detection (Hyper-Speed Burst)[/bold]")

        for target_info in RATE_LIMIT_TARGETS:
            path = target_info["path"]
            method = target_info["method"]
            body = target_info["body"]
            label = target_info["label"]

            # Initial probe
            probe = await requester.fetch(method, self.target + path, json=body if method == "POST" else None)
            if probe is None or probe.status_code == 404:
                continue

            console.print(f"     🔍 Bombarding: {path} ({label})")
            
            # Prepare burst of 20 simultaneous requests
            requests = []
            for _ in range(RATE_LIMIT_ATTEMPTS):
                req = {
                    "method": method,
                    "url": self.target + path,
                    "cookies": self.cookies,
                    "follow_redirects": False
                }
                if method == "POST":
                    req["json"] = body
                requests.append(req)

            # Fire them ALL at the exact same time
            results = await requester.fetch_all(requests)
            
            statuses = [r.status_code for r in results if r]
            non_limited = [s for s in statuses if s not in (429, 423, 401, 403)]
            
            if len(non_limited) >= RATE_LIMIT_THRESHOLD:
                finding = {
                    "type": "Missing Rate Limiting (Async Confirmed)",
                    "severity": "MEDIUM",
                    "cvss_score": 5.3,
                    "url": self.target + path,
                    "attempts": len(statuses),
                    "statuses": statuses,
                    "timestamp": datetime.utcnow().isoformat(),
                }
                findings.append(finding)
                self._add_finding(finding)
                console.print(f"     [bold red]🚨 NO RATE LIMIT: {path} — {len(non_limited)}/{len(statuses)} requests went through[/bold red]")
            else:
                if 429 in statuses or 423 in statuses:
                    console.print(f"       ✅ Rate limit successfully triggered! WAF/Limit active.")

        if not findings:
            console.print("     [green]✅ Rate limiting blocking brute-force attacks[/green]")
        return findings

    async def scan_security_headers(self, requester: AsyncRequester) -> list[dict]:
        findings = []
        console.print("\n  [bold]🔒 Security Headers Check[/bold]")

        resp = await requester.fetch("GET", self.target + "/", follow_redirects=True)
        if not resp:
            console.print("     [yellow]⚠️  Could not reach homepage[/yellow]")
            return []

        resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        for header_name, info in SECURITY_HEADERS.items():
            if header_name not in resp_headers_lower:
                finding = {
                    "type": f"Missing Security Header: {info['label']}",
                    "severity": info["severity"],
                    "url": self.target + "/",
                    "header": header_name,
                    "timestamp": datetime.utcnow().isoformat(),
                }
                findings.append(finding)
                self._add_finding(finding)
                sev_color = "red" if info["severity"] == "MEDIUM" else "yellow"
                console.print(f"     [{sev_color}]⚠️  Missing [{info['severity']}]: {info['label']}[/{sev_color}]")

        return findings

    async def run_async(self) -> list[dict]:
        console.print(Panel(
            f"[bold white]⚡ AURA v3 OMNI — Web Security Engine (Async)[/bold white]\n"
            f"Target: [cyan]{self.target}[/cyan]\n"
            f"[dim]Modules: CORS · Open Redirect · Rate Limiting · Headers (Running in Asynchronous Hyper-Speed)[/dim]",
            box=box.DOUBLE_EDGE,
            style="bright_blue",
        ))

        # Use 100 concurrent connections for massive speed boost!
        async with AsyncRequester(concurrency_limit=100, timeout=10, proxy_file=self.proxy_file) as requester:
            cors_findings = await self.scan_cors(requester)
            redirect_findings = await self.scan_open_redirect(requester)
            rate_limit_findings = await self.scan_rate_limiting(requester)
            header_findings = await self.scan_security_headers(requester)

        all_findings = self.findings
        critical = [f for f in all_findings if f.get("severity") == "CRITICAL"]
        high     = [f for f in all_findings if f.get("severity") == "HIGH"]
        medium   = [f for f in all_findings if f.get("severity") == "MEDIUM"]

        print(f"\n{'='*65}")
        print(f"⚡ WEB ASYNC SCAN COMPLETE")
        print(f"{'='*65}")
        print(f"  🔴 Critical : {len(critical)}")
        print(f"  🟠 High     : {len(high)}")
        print(f"  🟡 Medium   : {len(medium)}")
        print(f"  📊 Total    : {len(all_findings)}")

        if all_findings:
            target_slug = self.target_domain.replace(".", "_").replace("www_", "")
            out_path = self.output_dir / f"web_omni_findings_{target_slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            out_path.write_text(
                json.dumps({"target": self.target, "findings": all_findings}, indent=2),
                encoding="utf-8"
            )
            console.print(f"\n  💾 Findings saved: [cyan]{out_path}[/cyan]")

        return all_findings

    def run(self) -> list[dict]:
        """Wrapper to call async from sync code."""
        return asyncio.run(self.run_async())


def run_web_scan(target: str, discovery_map_path: Optional[str] = None, proxy_file: Optional[str] = None) -> list[dict]:
    """CLI runner for `aura <target> --web`."""
    from dotenv import load_dotenv
    load_dotenv()
    cookies_str = os.getenv("AUTH_TOKEN_ATTACKER", "")
    engine = WebSecurityEngine(target=target, cookies_str=cookies_str, proxy_file=proxy_file)
    return engine.run()


if __name__ == "__main__":
    import sys
    t = sys.argv[1] if len(sys.argv) > 1 else "www.iciparisxl.nl"
    run_web_scan(t)
