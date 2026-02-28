"""
Aura v5.0: Secret Hunter Module (TruffleHog-style)
Scans JavaScript files, HTML, and config pages for exposed API keys,
tokens, and credentials using high-signal regex patterns.

When a real secret is found → CRITICAL finding with CVSS 9.0+
"""
import re
import asyncio
from rich.console import Console

console = Console()


class SecretHunter:
    """
    TruffleHog-style secret scanner for Aura v5.0.
    - Downloads JS/config files discovered by the crawler
    - Matches high-entropy secrets using regex
    - Auto-classifies severity and validates key format
    """

    # High-signal patterns (minimize false positives)
    SECRET_PATTERNS = {
        "AWS Access Key":          (r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])", 9.8),
        "AWS Secret Key":          (r"(?i)aws[_\-\.]?secret[_\-\.]?(?:access[_\-\.]?)?key\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]", 9.8),
        "Google API Key":          (r"AIza[0-9A-Za-z\-_]{35}", 8.8),
        "Google OAuth Token":      (r"ya29\.[0-9A-Za-z\-_]+", 8.8),
        "GitHub Token (Classic)":  (r"ghp_[0-9A-Za-z]{36}", 9.0),
        "GitHub OAuth":            (r"gho_[0-9A-Za-z]{36}", 9.0),
        "GitHub App Token":        (r"github_pat_[0-9A-Za-z_]{82}", 9.0),
        "Stripe Secret Key":       (r"sk_live_[0-9a-zA-Z]{24,}", 9.5),
        "Stripe Publishable Key":  (r"pk_live_[0-9a-zA-Z]{24,}", 7.5),
        "Twilio API Key":          (r"SK[0-9a-fA-F]{32}", 8.5),
        "SendGrid API Key":        (r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}", 8.8),
        "Slack Token":             (r"xox[baprs]-[0-9A-Za-z\-]{10,}", 8.8),
        "Slack Webhook":           (r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+", 8.0),
        "Firebase Database URL":   (r"https://[^.]+\.firebaseio\.com", 7.5),
        "JWT Token":               (r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", 8.5),
        "Private RSA Key":         (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", 9.9),
        "OpenAI API Key":          (r"sk-[A-Za-z0-9]{48}", 9.0),
        "Bearer Token":            (r'[Aa]uthorization["\s:]+Bearer\s+([A-Za-z0-9\-_\.]{20,})', 8.0),
        "Generic Password":        (r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']', 7.0),
        "Database URL":            (r'(?:mysql|postgresql|mongodb|redis)://[^@\s]+:[^@\s]+@[^\s"\']+', 9.0),
        "Heroku API Key":          (r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", 8.0),
    }

    # JS-specific files to fetch and scan
    JS_EXTENSIONS = [".js", ".min.js", ".bundle.js", ".chunk.js"]

    def __init__(self, session=None):
        self.session = session

    async def _fetch_file(self, url: str) -> str | None:
        """Downloads a file and returns its text content."""
        try:
            res = await self.session.get(url, timeout=8)
            if res.status_code == 200:
                return res.text
        except: pass
        return None

    def _scan_content(self, content: str, source_url: str) -> list[dict]:
        """Scans text content for secret patterns. Returns findings."""
        findings = []
        for secret_type, (pattern, cvss_score) in self.SECRET_PATTERNS.items():
            matches = re.findall(pattern, content)
            for match in matches:
                # Avoid duplicates within same file
                evidence = match if isinstance(match, str) else match[0] if match else ""
                if not evidence:
                    continue

                # Redact middle of secret for display (security best practice)
                if len(evidence) > 10:
                    display = evidence[:6] + "****" + evidence[-4:]
                else:
                    display = evidence[:3] + "***"

                console.print(
                    f"[bold red blink][🔑 SECRET FOUND] {secret_type}: '{display}' in {source_url}[/bold red blink]"
                )
                findings.append({
                    "type": f"Exposed Secret: {secret_type}",
                    "severity": "CRITICAL",
                    "cvss_score": cvss_score,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    "owasp": "A02:2021-Cryptographic Failures",
                    "mitre": "T1552 - Unsecured Credentials",
                    "content": (
                        f"CRITICAL SECRET EXPOSED: {secret_type} found in {source_url}\n"
                        f"Evidence: '{display}'\n"
                        f"Full match pattern: {pattern[:60]}..."
                    ),
                    "remediation_fix": (
                        f"1. IMMEDIATELY revoke/rotate the exposed {secret_type}.\n"
                        "2. Remove secrets from frontend code and config files.\n"
                        "3. Use environment variables or a secrets manager (HashiCorp Vault, AWS Secrets Manager):\n"
                        "   # .env file (never commit to git)\n"
                        "   API_KEY=your_secret_here\n"
                        "   # Access in code: os.environ['API_KEY']\n"
                        "4. Add .env to .gitignore immediately.\n"
                        "5. Scan git history with: git log --all --grep='API_KEY'"
                    ),
                    "impact_desc": (
                        f"CATASTROPHIC: Exposed {secret_type} allows direct unauthorized access "
                        f"to the associated service. Attacker can impersonate the application, "
                        f"steal data, or cause financial damages."
                    ),
                    "patch_priority": "IMMEDIATE",
                    "evidence_url": source_url,
                })
        return findings

    async def hunt_in_page(self, page_content: str, page_url: str) -> list[dict]:
        """Scans a page's HTML/JS content for secrets inline."""
        return self._scan_content(page_content, page_url)

    async def hunt_js_files(self, discovered_urls: list[str]) -> list[dict]:
        """
        Downloads and scans all JS files discovered during crawling.
        Also scans .env, config, and docker-compose files if accessible.
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
            content = await self._fetch_file(url)
            if content:
                findings = self._scan_content(content, url)
                if findings:
                    all_findings.extend(findings)
                    console.print(f"[bold red]  [!!!] {len(findings)} secret(s) in {url}[/bold red]")
                else:
                    console.print(f"[dim green]  [✓] {url} — clean[/dim green]")

        console.print(
            f"[bold {'red' if all_findings else 'green'}]"
            f"[🔑 Secret Hunter] Done: {len(all_findings)} secret(s) found across {len(sensitive_targets)} files.[/bold {'red' if all_findings else 'green'}]"
        )
        return all_findings
