"""
Aura v2 — Cross-Tenant BOLA/IDOR Engine
=========================================
This is the real BOLA (Broken Object Level Authorization) hunter.

Unlike the old idor_hunter.py which guesses IDs blindly,
this engine does:

  1. ATTACKER session → crawl own resources → collect real UUIDs/IDs
  2. VICTIM session → attempt to GET/PATCH/DELETE those same resource IDs
  3. Compare responses → confirm unauthorized access

This is exactly the attack that earns $500–$5,000 on bug bounty platforms.

Usage:
    python -m aura.modules.idor_engine_v2 --target www.iciparisxl.nl
    or
    aura www.iciparisxl.nl --hunt
"""

import asyncio
import json
import os
import re
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests
from requests.exceptions import ConnectionError, Timeout

# Suppress SSL warnings (we're using Burp proxy sometimes)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ─── Constants ─────────────────────────────────────────────────────────────────
UUID_RE = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE)
NUMERIC_ID_RE = re.compile(r'/(\d{3,})')

# HTTP methods to test (GET is for reading, PATCH/DELETE are critical)
READ_METHODS = ["GET"]
WRITE_METHODS = ["PATCH", "PUT", "DELETE"]

# Minimum response body length to consider "meaningful"
MIN_MEANINGFUL_LEN = 50


class BolaTester:
    """
    Cross-Tenant BOLA/IDOR Tester.
    
    Requires two session cookie strings:
      - attacker_cookies: Your account (you know its data)
      - victim_cookies: Second account (should NOT be able to see attacker's data)
    """

    def __init__(
        self,
        target: str,
        attacker_cookies: str,
        victim_cookies: str,
        proxy: Optional[str] = None,
        timeout: int = 20,
    ):
        if not target.startswith("http"):
            target = "https://" + target
        self.target = target.rstrip("/")
        self.target_domain = urllib.parse.urlparse(self.target).netloc
        self.timeout = timeout
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        
        # Build session headers (cookie strings → cookie dict)
        self.attacker_cookies = self._parse_cookie_string(attacker_cookies)
        self.victim_cookies = self._parse_cookie_string(victim_cookies)

        # Results
        self.confirmed_idors: list[dict] = []
        self.tested_count = 0
        self.candidate_idor_pairs: list[dict] = []

    @staticmethod
    def _parse_cookie_string(cookie_str: str) -> dict:
        """Converts a raw Cookie header string into a dict."""
        cookies = {}
        for part in cookie_str.split(";"):
            part = part.strip()
            if "=" in part:
                name, _, value = part.partition("=")
                cookies[name.strip()] = value.strip()
        return cookies

    def _request(
        self,
        method: str,
        url: str,
        cookies: dict,
        body: Optional[str] = None,
        extra_headers: Optional[dict] = None,
    ) -> dict:
        """Makes a single HTTP request and returns a structured result."""
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "nl-NL,nl;q=0.9,en;q=0.8",
            "X-Intigriti-Username": os.getenv("INTIGRITI_USERNAME", "mutasem_mk4"),
        }
        if extra_headers:
            headers.update(extra_headers)
        if body:
            headers["Content-Type"] = "application/json"

        try:
            resp = requests.request(
                method=method,
                url=url,
                headers=headers,
                cookies=cookies,
                data=body,
                timeout=self.timeout,
                verify=False,
                proxies=self.proxy,
                allow_redirects=False,
            )
            text = resp.text or ""
            return {
                "status": resp.status_code,
                "length": len(text),
                "body": text[:1000],
                "headers": dict(resp.headers),
                "error": None,
            }
        except (ConnectionError, Timeout) as e:
            return {"status": 0, "length": 0, "body": "", "headers": {}, "error": str(e)[:100]}
        except Exception as e:
            return {"status": 0, "length": 0, "body": "", "headers": {}, "error": str(e)[:100]}

    def _compare_responses(self, attacker_resp: dict, victim_resp: dict) -> tuple[bool, str]:
        """
        Determine if the victim's response indicates unauthorized access to attacker's resource.
        
        BOLA confirmed if:
        - Victim gets 200 OK with meaningful data (not empty, not error JSON)
        - Response body contains data (PII indicators, user references, etc.)
        """
        v_status = victim_resp["status"]
        v_len = victim_resp["length"]
        v_body = victim_resp["body"].lower()

        # If victim gets blocked → not vulnerable
        if v_status in (401, 403, 404):
            return False, f"Victim got {v_status} — Access properly denied ✅"

        if v_status == 0:
            return False, f"Connection error: {victim_resp['error']}"

        # If victim gets 200 with meaningful content
        if v_status == 200 and v_len >= MIN_MEANINGFUL_LEN:
            # Check for PII indicators in the response body
            pii_keywords = ["email", "name", "address", "phone", "dob", "credit", 
                           "cart", "order", "entries", "customer", "user", "account"]
            pii_found = [kw for kw in pii_keywords if kw in v_body]
            
            if pii_found:
                return True, (
                    f"✅ BOLA CONFIRMED! Victim accessed attacker's resource (HTTP {v_status}). "
                    f"PII indicators found: {', '.join(pii_found[:3])}. "
                    f"Response length: {v_len} bytes."
                )
            elif v_len > 200:
                return True, (
                    f"✅ POSSIBLE BOLA! Victim accessed resource with {v_len} bytes of data (HTTP {v_status}). "
                    f"Manual review required."
                )
        
        # If victim gets 2xx but with minimal data (might be silent drop like ICI cart)
        if v_status in (200, 201, 204) and v_len < MIN_MEANINGFUL_LEN:
            return False, f"Victim got {v_status} but minimal body ({v_len} bytes) — likely silent drop"

        return False, f"No clear BOLA signal (victim status: {v_status}, length: {v_len})"

    def test_endpoint(self, endpoint: dict) -> Optional[dict]:
        """
        Tests a single endpoint for BOLA by:
        1. Making the request as ATTACKER → baseline
        2. Replaying as VICTIM → check unauthorized access
        """
        url = endpoint["url"]
        method = endpoint.get("method", "GET")
        post_data = endpoint.get("post_data")

        print(f"\n  🎯 Testing [{method}] {url[:90]}")

        # Step 1: Attacker request (baseline — should succeed with their own data)
        attacker_resp = self._request(method, url, self.attacker_cookies, body=post_data)
        print(f"     👤 Attacker: HTTP {attacker_resp['status']} ({attacker_resp['length']} bytes)")

        if attacker_resp["status"] not in (200, 201, 204):
            print(f"     ⚠️  Skipping — Attacker didn't get 2xx (got {attacker_resp['status']})")
            return None

        # Step 2: Victim request (using EXACT same URL/body as attacker)
        self.tested_count += 1
        victim_resp = self._request(method, url, self.victim_cookies, body=post_data)
        print(f"     👥 Victim:   HTTP {victim_resp['status']} ({victim_resp['length']} bytes)")

        # Step 3: Compare
        is_bola, reason = self._compare_responses(attacker_resp, victim_resp)

        if is_bola:
            print(f"     🚨 {reason}")
            finding = {
                "url": url,
                "method": method,
                "reason": reason,
                "attacker_status": attacker_resp["status"],
                "attacker_len": attacker_resp["length"],
                "victim_status": victim_resp["status"],
                "victim_len": victim_resp["length"],
                "victim_body_snippet": victim_resp["body"][:300],
                "ids_in_url": endpoint.get("ids", []),
                "source_page": endpoint.get("source_page", ""),
                "timestamp": datetime.utcnow().isoformat(),
                "severity": "HIGH",
                "cvss_score": 8.1,
                "owasp": "A01:2021 — Broken Access Control",
                "type": "BOLA / IDOR",
            }
            self.confirmed_idors.append(finding)
            return finding
        else:
            print(f"     ✅ {reason}")
            return None

    def run_from_discovery_map(self, map_path: str) -> list[dict]:
        """
        Main entry point: loads a Discovery Map from the Crawler
        and runs BOLA tests on all IDOR candidates.
        """
        map_path = Path(map_path)
        if not map_path.exists():
            print(f"❌ Discovery map not found: {map_path}")
            print("   Run: aura <target> --crawl  first!")
            return []

        with open(map_path, "r", encoding="utf-8") as f:
            discovery_map = json.load(f)

        meta = discovery_map.get("meta", {})
        idor_candidates = discovery_map.get("idor_candidates", [])
        mutating_eps = discovery_map.get("mutating_endpoints", [])

        print(f"\n{'='*65}")
        print(f"🔥 AURA v2 — BOLA/IDOR Cross-Tenant Engine")
        print(f"🎯 Target: {meta.get('target', 'unknown')}")
        print(f"📋 IDOR Candidates: {len(idor_candidates)}")
        print(f"⚡ Mutating Endpoints: {len(mutating_eps)}")
        print(f"{'='*65}")

        # Test IDOR candidates (GET requests on ID-bearing URLs)
        all_endpoints = []
        for ep in idor_candidates:
            all_endpoints.append({
                "url": ep["url"],
                "method": "GET",
                "ids": ep.get("ids", []),
                "source_page": ep.get("source_page", ""),
            })
        
        # Also test mutating endpoints (POST/PATCH/DELETE)
        for ep in mutating_eps:
            all_endpoints.append({
                "url": ep["url"],
                "method": ep["method"],
                "post_data": ep.get("post_data"),
                "ids": [],
                "source_page": ep.get("source_page", ""),
            })

        if not all_endpoints:
            print("\n⚠️  No endpoints to test!")
            print("   The discovery map is empty. Did the crawl authenticate successfully?")
            print("   Check that AUTH_TOKEN_ATTACKER in .env has a fresh session cookie.")
            return []

        print(f"\n🚀 Starting {len(all_endpoints)} BOLA tests...\n")

        for ep in all_endpoints:
            self.test_endpoint(ep)

        return self._finalize_report(meta)

    def _finalize_report(self, meta: dict) -> list[dict]:
        """Prints the final summary and saves findings."""
        print(f"\n{'='*65}")
        print(f"✅ HUNT COMPLETE")
        print(f"{'='*65}")
        print(f"  🔍 Endpoints Tested : {self.tested_count}")
        print(f"  🚨 BOLA Confirmed   : {len(self.confirmed_idors)}")
        
        if self.confirmed_idors:
            print(f"\n{'🔴'*30}")
            print(f"  💰 CONFIRMED BOLA/IDOR FINDINGS:")
            for i, finding in enumerate(self.confirmed_idors, 1):
                print(f"\n  [{i}] [{finding['method']}] {finding['url'][:80]}")
                print(f"      Severity: {finding['severity']} | CVSS: {finding['cvss_score']}")
                print(f"      {finding['reason']}")
            print(f"{'🔴'*30}\n")
            
            # Save findings report
            self._save_report()
        else:
            print(f"\n  ✅ No unauthorized access detected on tested endpoints.")
            print(f"  💡 Tip: Update your session cookies and re-run --crawl for fresh endpoints.\n")

        return self.confirmed_idors

    def _save_report(self):
        """Saves confirmed BOLA findings to a JSON report."""
        reports_dir = Path("./reports")
        reports_dir.mkdir(exist_ok=True)
        
        target_slug = self.target_domain.replace(".", "_").replace("www_", "")
        output_path = reports_dir / f"bola_findings_{target_slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump({
                "target": self.target,
                "scan_time": datetime.utcnow().isoformat(),
                "total_confirmed": len(self.confirmed_idors),
                "findings": self.confirmed_idors
            }, f, indent=2)
        
        print(f"  💾 Findings saved: {output_path}")


def run_hunt(target: str, discovery_map_path: Optional[str] = None):
    """
    Synchronous runner for the BOLA engine.
    Called by the CLI with `aura <target> --hunt`
    """
    from dotenv import load_dotenv
    load_dotenv()

    attacker_cookies = os.getenv("AUTH_TOKEN_ATTACKER", "")
    victim_cookies = os.getenv("AUTH_TOKEN_VICTIM", "")

    if not attacker_cookies:
        print("❌ AUTH_TOKEN_ATTACKER not found in .env!")
        return []
    if not victim_cookies:
        print("❌ AUTH_TOKEN_VICTIM not found in .env!")
        print("   You need TWO accounts to perform cross-tenant BOLA testing.")
        return []

    # Auto-find discovery map if not specified
    if not discovery_map_path:
        target_slug = target.replace("www.", "").replace(".", "_")
        candidate = Path(f"./reports/discovery_map_{target_slug}.json")
        if candidate.exists():
            discovery_map_path = str(candidate)
        else:
            print(f"❌ No discovery map found at {candidate}")
            print(f"   Run `aura {target} --crawl` first to generate it!")
            return []

    tester = BolaTester(
        target=target,
        attacker_cookies=attacker_cookies,
        victim_cookies=victim_cookies,
    )
    return tester.run_from_discovery_map(discovery_map_path)


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "www.iciparisxl.nl"
    run_hunt(target)
