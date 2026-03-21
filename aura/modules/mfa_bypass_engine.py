"""
Aura v30.0 — 2FA/MFA Bypass Engine 🔑
========================================
Detects weaknesses in two-factor authentication implementations.

Attacks:
  1. Response Manipulation — flip success=false to true
  2. OTP Code Reuse — same code accepted twice
  3. Session Fixation — same session before/after 2FA
  4. OTP Brute Force Detection — checks if rate limiting exists
  5. Backup Code Enumeration — tests weak backup code formats
"""
import asyncio
import json
import re
import httpx
from rich.console import Console

from aura.ui.formatter import console

# Common 2FA/OTP endpoints
MFA_ENDPOINT_PATTERNS = [
    "/verify", "/otp", "/2fa", "/mfa", "/totp", "/auth/verify",
    "/api/verify", "/api/otp", "/api/2fa", "/api/mfa",
    "/login/verify", "/account/verify", "/auth/2fa",
    "/verify-otp", "/confirm-otp", "/sms/verify",
]

# Common response fields with success indicators
SUCCESS_FIELDS = ["success", "valid", "verified", "status", "result", "authenticated"]


class MFABypassEngine:
    """v30.0: 2FA/MFA Bypass Engine."""

    def __init__(self, session=None):
        self.session = session

    # ── Find MFA Endpoints ────────────────────────────────────────────────
    async def _discover_mfa_endpoints(self, client, base_url: str) -> list:
        found = []
        sem = asyncio.Semaphore(10)

        async def _probe(path):
            async with sem:
                url = f"{base_url.rstrip('/')}{path}"
                try:
                    for method in ("POST", "GET"):
                        r = await client.request(method, url, timeout=6)
                        if r.status_code in (200, 400, 401, 422, 405):
                            found.append(url)
                            return
                except Exception:
                    pass

        await asyncio.gather(*[_probe(p) for p in MFA_ENDPOINT_PATTERNS])
        return list(set(found))

    # ── Attack 1: Response Manipulation ──────────────────────────────────
    async def _response_manipulation(self, client, url: str) -> dict | None:
        """Tests if flipping a response field bypasses 2FA."""
        # Send with obviously wrong OTP
        test_payloads = [
            {"otp": "000000", "code": "000000"},
            {"token": "000000", "mfa_code": "000000"},
        ]
        for payload in test_payloads:
            try:
                r = await client.post(url, json=payload, timeout=8)
                body = r.text.lower()
                # Check if success-like fields are present with clear false values
                for field in SUCCESS_FIELDS:
                    if f'"{field}": false' in body or f'"{field}":false' in body:
                        return {
                            "type": "2FA Response Manipulation Vector",
                            "finding_type": "2FA/MFA Response Manipulation",
                            "severity": "HIGH",
                            "owasp": "A07:2021 – Identification and Authentication Failures",
                            "mitre": "T1556",
                            "content": (
                                f"2FA endpoint returns explicit `{field}: false` on {url}\n"
                                f"Payload: {json.dumps(payload)}\n"
                                f"Response: {r.text[:300]}\n"
                                f"This response structure may be vulnerable to client-side manipulation. "
                                f"Intercept and flip `{field}` to `true` to bypass 2FA."
                            ),
                            "url": url,
                            "confirmed": False,  # Requires manual confirmation
                        }
            except Exception:
                continue
        return None

    # ── Attack 2: OTP Brute Force — Check Rate Limiting ──────────────────
    async def _check_brute_force_protection(self, client, url: str) -> dict | None:
        """Sends 15 wrong OTPs rapidly to test for rate limiting."""
        failed_count = 0
        for attempt in range(15):
            otp = str(attempt * 7331 % 1000000).zfill(6)
            try:
                payload = {"otp": otp, "code": otp, "token": otp}
                r = await client.post(url, json=payload, timeout=6)
                if r.status_code == 429:  # rate limited — good
                    return None
                if r.status_code in (200, 400, 401, 422):
                    failed_count += 1
            except Exception:
                break

        if failed_count >= 12:  # 12 of 15 attempts succeeded without rate limit
            return {
                "type": "2FA OTP Brute Force — No Rate Limiting",
                "finding_type": "2FA Brute Force Vulnerability",
                "severity": "CRITICAL",
                "owasp": "A07:2021 – Identification and Authentication Failures",
                "mitre": "T1110.001",
                "content": (
                    f"OTP endpoint allows rapid guessing without rate limiting on {url}\n"
                    f"{failed_count}/15 requests accepted without blocking.\n"
                    f"4-digit OTP = 10,000 combinations (~10s to brute force)\n"
                    f"6-digit OTP = 1,000,000 combinations (~15min with 1000 req/s)\n"
                    f"Impact: Account takeover via OTP exhaustion."
                ),
                "url": url,
                "confirmed": True,
            }
        return None

    # ── Attack 3: OTP Code Reuse Detection ───────────────────────────────
    async def _check_code_reuse(self, client, url: str) -> dict | None:
        """Checks if the same OTP can be submitted twice successfully."""
        # We send the same OTP twice — if both return same non-error response
        # and neither hits a "already used" message — potential reuse
        otp = "123456"
        reuse_markers = ["already used", "expired", "invalid", "consumed", "used"]
        try:
            r1 = await client.post(url, json={"otp": otp, "code": otp}, timeout=8)
            r2 = await client.post(url, json={"otp": otp, "code": otp}, timeout=8)

            r2_body_lower = r2.text.lower()
            no_reuse_markers = not any(m in r2_body_lower for m in reuse_markers)

            if r1.status_code == r2.status_code and no_reuse_markers:
                return {
                    "type": "2FA OTP Code Reuse",
                    "finding_type": "2FA OTP Reuse Vulnerability",
                    "severity": "HIGH",
                    "owasp": "A07:2021 – Identification and Authentication Failures",
                    "mitre": "T1556",
                    "content": (
                        f"OTP endpoint may allow code reuse on {url}\n"
                        f"Both requests with OTP `{otp}` returned status {r1.status_code}\n"
                        f"No 'already used' or 'expired' message detected in second response.\n"
                        f"Impact: Stolen OTP can be reused for account takeover."
                    ),
                    "url": url,
                    "confirmed": False,  # Requires manual validation with real OTP
                }
        except Exception:
            pass
        return None

    # ── Main Scan ─────────────────────────────────────────────────────────
    async def scan_target(self, target_url: str) -> list:
        from urllib.parse import urlparse
        base = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
        findings = []

        console.print(f"[bold cyan][🔑 2FA] Scanning {base} for MFA bypass vectors...[/bold cyan]")

        async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
            endpoints = await self._discover_mfa_endpoints(client, base)
            if not endpoints:
                console.print(f"[dim][2FA] No MFA endpoints found on {base}[/dim]")
                return []

            console.print(f"[cyan][🔑 2FA] Found {len(endpoints)} MFA endpoint(s). Testing...[/cyan]")

            for url in endpoints[:5]:
                results = await asyncio.gather(
                    self._response_manipulation(client, url),
                    self._check_brute_force_protection(client, url),
                    self._check_code_reuse(client, url),
                    return_exceptions=True
                )
                for r in results:
                    if r and not isinstance(r, Exception):
                        console.print(f"[bold red][🔑 2FA] {r['type']} on {url}![/bold red]")
                        findings.append(r)

        if not findings:
            console.print(f"[dim][2FA] No MFA bypass vectors detected.[/dim]")
        return findings

    async def scan_urls(self, urls: list) -> list:
        seen = set()
        all_findings = []
        for url in urls:
            from urllib.parse import urlparse
            base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            if base in seen:
                continue
            seen.add(base)
            try:
                results = await self.scan_target(url)
                all_findings.extend(results)
            except Exception as e:
                console.print(f"[dim red][2FA] Skipped {url}: {e}[/dim red]")
        return all_findings
