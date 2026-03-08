"""
Aura v5.2: Secret Hunter Module (TruffleHog-style)
Scans JavaScript files, HTML, and config pages for exposed API keys,
tokens, and credentials using high-signal regex patterns.

v5.1 Upgrade: Precision False-Positive Elimination Engine
  - Layer 1: CDN/Safe Domain Blocklist
  - Layer 2: Shannon Entropy Validator (min 3.5 bits/char)
  - Layer 3: Context-Aware HTML Scanning (script tags + key= lines only)
  - Layer 4: Per-session de-duplication

v5.2 Upgrade (Phase 1): Active Secret Validation Engine
  - AWS Key: validated via STS GetCallerIdentity
  - GitHub Token: validated via api.github.com/user
  - Stripe Key: validated via api.stripe.com/v1/account
  - Google Key: validated via tokeninfo endpoint
  - OpenAI Key: validated via api.openai.com/v1/models

When a CONFIRMED secret is found → EXCEPTIONAL/CRITICAL finding with CVSS 9.8+
"""
import re
import math
import hmac
import hashlib
import base64
import asyncio
import urllib.parse
from datetime import datetime, timezone
from rich.console import Console
from rich.console import Console
from aura.core.storage import AuraStorage
from aura.core import state
from aura.modules.key_validator import KeyValidator

console = Console()
db_logger = AuraStorage()


# ─── Layer 1: CDN / Safe Domain Blocklist ─────────────────────────────────────
# Any match found inside a URL containing these strings is discarded.
CDN_BLOCKLIST = [
    "staticctf.", "ubiservices.cdn.", "static-dm.", "static-news.",
    "cloudfront.net", "akamaiedge.net", "fastly.net", "akamai.net",
    "googleapis.com", "gstatic.com", "gvt1.com",
    "bootstrapcdn.com", "jquery.com", "unpkg.com", "cdn.jsdelivr.net",
    "fbcdn.net", "cdninstagram.com", "twimg.com",
    "intigriti.com", "hackerone.com",
    "_next/static/", "static/chunks/", "static/css/",
    ".woff2", ".woff", ".ttf", ".svg", ".png", ".jpg", ".webp", ".ico",
]


class SecretHunter:
    """
    TruffleHog-style secret scanner for Aura v5.1.
    Now with 4-layer false-positive elimination engine.
    """

    # High-signal patterns — format-validated where possible
    SECRET_PATTERNS = {
        # AWS Access Key — strict: must start with AKIA
        "AWS Access Key":         (r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])", 9.8, True),
        # AWS Secret Key — must appear next to a key= or secret= label in context
        "AWS Secret Key":         (r'(?i)(?:aws[_\-.]?secret[_\-.]?(?:access[_\-.]?)?key)\s*[:=]\s*[\'"]([A-Za-z0-9/+=]{40})[\'"]', 9.8, True),
        # Google API Key — strict AIza prefix
        "Google API Key":         (r"(AIza[0-9A-Za-z\-_]{35})", 8.8, True),
        # Google OAuth Token — strict ya29. prefix
        "Google OAuth Token":     (r"(ya29\.[0-9A-Za-z\-_]{30,})", 8.8, True),
        # GitHub tokens — strict prefix validation
        "GitHub Token (Classic)": (r"(ghp_[0-9A-Za-z]{36})", 9.0, True),
        "GitHub OAuth":           (r"(gho_[0-9A-Za-z]{36})", 9.0, True),
        "GitHub App Token":       (r"(github_pat_[0-9A-Za-z_]{82})", 9.0, True),
        # Stripe — strict sk_live / pk_live prefix
        "Stripe Secret Key":      (r"(sk_live_[0-9a-zA-Z]{24,})", 9.5, True),
        "Stripe Publishable Key": (r"(pk_live_[0-9a-zA-Z]{24,})", 7.5, True),
        # SendGrid — strict SG. prefix + dot-separated structure
        "SendGrid API Key":       (r"(SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43})", 8.8, True),
        # Slack tokens — strict xox prefix
        "Slack Token":            (r"(xox[baprs]-[0-9A-Za-z\-]{10,})", 8.8, True),
        "Slack Webhook":          (r"(https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+)", 8.0, True),
        # JWT — strict 3-part base64url structure
        "JWT Token":              (r"(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})", 8.5, True),
        # Private keys — unmistakable header
        "Private RSA Key":        (r"(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)", 9.9, True),
        # OpenAI — strict sk- prefix + length
        "OpenAI API Key":         (r"(sk-[A-Za-z0-9]{48})", 9.0, True),
        # Database URLs with credentials embedded
        "Database URL":           (r'((?:mysql|postgresql|mongodb|redis)://[^@\s]+:[^@\s]+@[^\s"\']+)', 9.0, True),
        # Generic password in key=value context (high risk, needs context filter)
        "Generic Password":       (r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']', 7.0, False),
        # Bearer token beside Authorization header
        "Bearer Token":           (r'[Aa]uthorization["\s:]+Bearer\s+([A-Za-z0-9\-_\.]{20,})', 8.0, False),
    }

    # Extensions to target for deep scanning
    JS_EXTENSIONS = [".js", ".min.js", ".bundle.js", ".chunk.js"]

    def __init__(self, session=None):
        self.session = session
        self._seen_values = set()  # Layer 4: de-duplication

    # ─── Phase 1: Active Secret Validation Engine ────────────────────────────
    async def _validate_secret(self, secret_type: str, value: str) -> tuple[bool, str]:
        """
        Actively validates a discovered secret by probing the issuer's API.
        Delegates to the dedicated KeyValidator module for Auto-Exploitation.
        """
        return await KeyValidator.validate_secret(secret_type, value)


    # ─── Layer 2: Shannon Entropy ────────────────────────────────────────────
    @staticmethod
    def _entropy(s: str) -> float:
        """Returns Shannon entropy in bits/char. Real secrets > 3.5."""
        if not s or len(s) < 8:
            return 0.0
        freq = {c: s.count(c) / len(s) for c in set(s)}
        return -sum(p * math.log2(p) for p in freq.values())

    # ─── Layer 1: CDN Blocklist check ────────────────────────────────────────
    @staticmethod
    def _is_cdn_value(value: str, context_line: str) -> bool:
        """Returns True if the value or its surrounding context is from a CDN."""
        check = value + " " + context_line
        return any(bad in check for bad in CDN_BLOCKLIST)

    # ─── Layer 3: Context extractor ──────────────────────────────────────────
    @staticmethod
    def _extract_high_risk_content(html: str) -> str:
        """
        Extracts only high-risk content from raw HTML:
        1. Content inside <script>...</script> blocks
        2. Lines containing key/secret/token/password/credential/api keywords
        This dramatically reduces false positives from CDN URLs in <link> and <img> tags.
        """
        high_risk = []

        # Extract <script> block contents
        script_blocks = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE)
        high_risk.extend(script_blocks)

        # Extract lines that contain secret-related keywords
        for line in html.splitlines():
            lower = line.lower()
            if any(kw in lower for kw in ["key", "secret", "token", "password", "passwd", "credential", "api_key", "apikey", "bearer", "auth"]):
                # Skip lines that are clearly just HTML tags with src/href CDN links
                if not re.match(r'^\s*<(?:link|img|script|source)\s+', line.strip()):
                    high_risk.append(line)

        return "\n".join(high_risk)

    async def _scan_content(self, content: str, source_url: str, is_html: bool = False) -> list[dict]:
        """
        Scans content for secret patterns.
        If is_html=True, applies Layer 3 context extraction first.
        Phase 1: Validates each found secret live against the issuer API.
        """
        findings = []

        # Layer 3: For HTML pages, only scan high-risk content sections
        scan_target = self._extract_high_risk_content(content) if is_html else content

        for secret_type, pattern_info in self.SECRET_PATTERNS.items():
            pattern, cvss_score, prefix_validated = pattern_info
            matches = re.findall(pattern, scan_target)

            for match in matches:
                evidence = match if isinstance(match, str) else (match[0] if match else "")
                if not evidence or len(evidence) < 8:
                    continue

                # Layer 4: De-duplication
                if evidence in self._seen_values:
                    continue

                # Layer 1: CDN Blocklist
                ctx_start = scan_target.find(evidence)
                ctx_line = scan_target[max(0, ctx_start - 100): ctx_start + len(evidence) + 100]
                if self._is_cdn_value(evidence, ctx_line):
                    continue

                # Layer 2: Entropy check (skip for prefix-validated patterns)
                if not prefix_validated:
                    ent = self._entropy(evidence)
                    if ent < 3.5:
                        continue

                # All layers passed — attempt live validation (Phase 1)
                self._seen_values.add(evidence)
                is_confirmed, account_info = await self._validate_secret(secret_type, evidence)

                # Determine severity and badge based on confirmation
                if is_confirmed:
                    severity = "EXCEPTIONAL"
                    cvss_final = min(cvss_score + 0.2, 10.0)
                    confirmation_badge = f"[CONFIRMED LIVE] {account_info}"
                    console.print(f"[bold red blink][CONFIRMED SECRET] {secret_type} VERIFIED: {account_info}[/bold red blink]")
                else:
                    severity = "CRITICAL"
                    cvss_final = cvss_score
                    confirmation_badge = f"[UNCONFIRMED] Could not validate live: {account_info}"
                    console.print(f"[bold red][SECRET FOUND] {secret_type} (unconfirmed) in {source_url}[/bold red]")

                # Redact for safe display in console/logs
                if len(evidence) > 10:
                    display = evidence[:6] + "****" + evidence[-4:]
                else:
                    display = evidence[:3] + "***"

                findings.append({
                    "type": f"Exposed Secret: {secret_type}",
                    "severity": severity,
                    "cvss_score": cvss_final,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    "owasp": "A02:2021-Cryptographic Failures",
                    "mitre": "T1552 - Unsecured Credentials",
                    "content": (
                        f"{confirmation_badge}\n"
                        f"Exposed {secret_type} found at {source_url}\n"
                        f"Evidence: '{evidence}' | Entropy: {self._entropy(evidence):.2f} bits/char"
                    ),
                    "remediation_fix": (
                        f"1. Immediately REVOKE the exposed {secret_type} from the issuing platform's dashboard.\n"
                        "2. Rotate all related secrets and regenerate access credentials.\n"
                        "3. Remove the secret from source code and commit history.\n"
                        "4. Move to a secrets manager (AWS Secrets Manager, HashiCorp Vault).\n"
                        "5. Add pre-commit hooks (`git-secrets`, `truffleHog`) to prevent future leaks.\n"
                        "6. Audit access logs for the exposed key period to check for unauthorized use."
                    ),
                    "impact_desc": (
                        f"{'CONFIRMED LIVE' if is_confirmed else 'SUSPECTED'} exposure of {secret_type}. "
                        f"{'Validated against issuer API — key is active and usable.' if is_confirmed else 'Could not confirm live status — key may still be valid.'} "
                        f"Attackers can leverage this for data exfiltration, service impersonation, or financial abuse."
                    ),
                    "patch_priority": "IMMEDIATE",
                    "evidence_url": source_url,
                    "secret_type": secret_type,
                    "secret_value": evidence, # Store UNREDACTED secret for Bug Bounty submission
                    "confirmed": is_confirmed,
                    "account_info": account_info,
                })
        return findings

    async def hunt_in_page(self, page_content: str, page_url: str) -> list[dict]:
        """Scans a page's HTML content for secrets (with context-aware filtering + live validation)."""
        return await self._scan_content(page_content, page_url, is_html=True)

    async def _fetch_file(self, url: str) -> str | None:
        """Downloads a file and returns its text content."""
        try:
            res = await self.session.get(url, timeout=state.NETWORK_TIMEOUT)
            if res and res.status_code == 200:
                db_logger.log_operation(url, "SecretHunter_Extract", 200)
                return res.text
        except Exception:
            db_logger.log_operation(url, "SecretHunter_Extract", 0)
        return None

    async def hunt_js_files(self, discovered_urls: list[str]) -> list[dict]:
        """
        Downloads and scans all JS/config files discovered during crawling.
        JS files are NOT HTML, so they get full (non-context-filtered) scanning.
        """
        all_findings = []
        sensitive_targets = [
            url for url in discovered_urls
            if (any(url.endswith(ext) for ext in self.JS_EXTENSIONS)
                or any(s in url for s in [".env", "config", "docker-compose", ".json", "settings"]))
        ]

        if not sensitive_targets:
            console.print("[dim][🔑 Secret Hunter] No JS/config files to scan.[/dim]")
            return []

        console.print(f"[bold yellow][🔑 Secret Hunter] Scanning {len(sensitive_targets)} files for secrets...[/bold yellow]")

        for url in sensitive_targets:
            # Skip known CDN URLs entirely
            if any(cdn in url for cdn in CDN_BLOCKLIST):
                continue
            content = await self._fetch_file(url)
            if content:
                findings = await self._scan_content(content, url, is_html=False)
                if findings:
                    all_findings.extend(findings)
                    console.print(f"[bold red]  [!!!] {len(findings)} secret(s) in {url}[/bold red]")
                else:
                    console.print(f"[dim green]  [✓] {url} — clean[/dim green]")

        console.print(
            f"[bold {'red' if all_findings else 'green'}]"
            f"[🔑 Secret Hunter] Done: {len(all_findings)} high-confidence secret(s) found.[/bold {'red' if all_findings else 'green'}]"
        )
        return all_findings
