import re
import asyncio
import uuid
from typing import List, Dict, Any, Optional
from aura.core.stealth import StealthEngine, AuraSession
from aura.core import state
from aura.core.notifier import CommLink
from aura.core.engine_interface import IEngine
from aura.core.models import Finding, Severity
from rich.console import Console

from aura.ui.formatter import console

class BrokenLinkHijacker:
    """Phase 8: Scans for abandoned/broken social media links that can be hijacked."""
    SOCIAL_PLATFORMS = {
        "Twitter": {"pattern": r"https?://(?:www\.)?twitter\.com/([a-zA-Z0-9_]{1,15})", "404_sig": "This account doesn't exist"},
        "Instagram": {"pattern": r"https?://(?:www\.)?instagram\.com/([a-zA-Z0-9_\.]{1,30})", "404_sig": "Sorry, this page isn't available"},
        "LinkedIn Company": {"pattern": r"https?://(?:www\.)?linkedin\.com/company/([a-zA-Z0-9\-]+)", "404_sig": "Page not found"},
        "YouTube Channel": {"pattern": r"https?://(?:www\.)?youtube\.com/(?:channel/|c/|u/|user/|@)([a-zA-Z0-9_\-]+)", "404_sig": "This page isn't available"},
        "TikTok": {"pattern": r"https?://(?:www\.)?tiktok\.com/@([a-zA-Z0-9_\.]{1,24})", "404_sig": "Couldn't find this account"},
    }

    async def scan_for_broken_links(self, content, domain):
        """Identifies potentially hijackable broken social media links."""
        hijack_found = []
        for platform, data in self.SOCIAL_PLATFORMS.items():
            matches = re.findall(data["pattern"], content)
            for handle in set(matches):
                link = f"{platform.split()[0].lower()}.com/{handle}"
                if platform == "Twitter": link = f"https://twitter.com/{handle}"
                elif platform == "Instagram": link = f"https://instagram.com/{handle}"
                # In a real scan, we'd verify the 404 live
                # For Phase 8 logic, we'll mark suspicious ones for review
                hijack_found.append({
                    "type": "Broken Social Media Link (Potential Hijack)",
                    "severity": "LOW", # Usually Low, but can be High if it's a main corporate account
                    "content": f"POTENTIAL HIJACK: Found {platform} link to '{handle}' on {domain}. If this account is deleted/available, an attacker can hijack it to ruin brand reputation.",
                    "platform": platform,
                    "handle": handle,
                    "url": link,
                    "value": link # v14.1 Fix: Orchestrator expects 'value' for all secrets
                })
        return hijack_found

class BountyHunter(IEngine):
    """High-impact vulnerability scanner focused on monetization."""
    
    ENGINE_ID = "bounty_hunter"

    def __init__(self, persistence=None, telemetry=None, brain=None, stealth=None, **kwargs):
        self.persistence = persistence
        self.telemetry = telemetry
        self.brain = brain
        self.stealth = stealth or StealthEngine()
        self.session = AuraSession(self.stealth)
        self.hijacker = BrokenLinkHijacker()
        self._status = "initialized"

    async def run(self, target: str, **kwargs) -> List[Finding]:
        """Unified entry point for IEngine."""
        self._status = "running"
        findings = []
        
        secrets = await self.scan_for_secrets(target)
        
        for s in secrets:
            findings.append(Finding(
                content=s.get("content") or f"Discovered leaked secret/hijackable link at {s.get('location')}",
                finding_type=s.get("type", "Bounty Finding"),
                severity=Severity[s.get("severity", "HIGH")],
                target_value=target,
                meta={"engine": self.ENGINE_ID, "remediation": s.get("remediation", "Revoke exposed secret and rotate credentials."), "raw": s}
            ))
            
        self._status = "completed"
        return findings

    def get_status(self) -> Dict[str, Any]:
        return {"id": self.ENGINE_ID, "status": self._status}

    # Expanded RE_PATTERNS - 25+ secret types with CVSS scores and bounty estimates
    RE_PATTERNS = {
        # ── Cloud Providers ──────────────────────────────────────────────
        "AWS Access Key":         (r"AKIA[0-9A-Z]{16}",                                      9.8, "$1,500-$5,000"),
        "AWS Secret Key":         (r"(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])", 9.8, "$1,500-$5,000"),
        "AWS Session Token":      (r"FQoG[a-zA-Z0-9/+]{200,}",                               9.8, "$1,500-$5,000"),
        "Google API Key":         (r"AIza[0-9A-Za-z\-_]{35}",                                9.1, "$500-$3,000"),
        "Google OAuth Token":     (r"ya29\.[0-9A-Za-z\-_]+",                                 9.1, "$500-$3,000"),
        "GCP Service Account":    (r'"type":\s*"service_account"',                            9.8, "$1,000-$5,000"),
        "Azure Storage Key":      (r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}", 9.8, "$1,000-$3,000"),
        "Azure Client Secret":    (r'(?:client.?secret|AZURE_CLIENT_SECRET|clientSecret)[\s=:\"\'][0-9a-zA-Z\-_.~]{16,}', 7.5, "$500-$2,000"),

        # ── Payment & Finance ─────────────────────────────────────────────
        "Stripe Live Key":        (r"sk_live_[0-9a-zA-Z]{24}",                               9.8, "$1,000-$5,000"),
        "Stripe Publishable Key": (r"pk_live_[0-9a-zA-Z]{24}",                               6.5, "$200-$500"),
        "PayPal OAuth Token":     (r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}", 9.8, "$1,000-$5,000"),
        "Braintree Token":        (r"access_token\$sandbox\$[0-9a-z]{16}\$[0-9a-f]{32}",     7.5, "$300-$1,000"),
        "Square API Key":         (r"sq0atp-[0-9A-Za-z\-_]{22}",                             9.1, "$500-$2,000"),

        # ── Communication & Social ────────────────────────────────────────
        "Slack Webhook":          (r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+", 7.5, "$200-$1,000"),
        "Slack Token":            (r"xox[baprs]-[0-9a-zA-Z\-]{10,48}",                       8.0, "$300-$1,500"),
        "Twilio API Key":         (r"SK[0-9a-fA-F]{32}",                                     8.0, "$300-$1,000"),
        "Twilio Account SID":     (r"AC[a-z0-9]{32}",                                        7.5, "$200-$800"),
        "SendGrid API Key":       (r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}",           8.0, "$200-$1,000"),
        "Mailgun API Key":        (r"key-[0-9a-zA-Z]{32}",                                   7.5, "$200-$800"),
        "Discord Bot Token":      (r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}",              7.5, "$100-$500"),
        "Telegram Bot Token":     (r"\d{8,10}:[A-Za-z0-9_-]{35}",                           7.5, "$100-$500"),

        # ── DevOps & Version Control ──────────────────────────────────────
        "GitHub Token":           (r"ghp_[A-Za-z0-9]{36}",                                   9.1, "$500-$3,000"),
        "GitHub OAuth":           (r"gho_[A-Za-z0-9]{36}",                                   9.1, "$500-$3,000"),
        "GitHub App Token":       (r"(ghu|ghs)_[A-Za-z0-9]{36}",                            9.1, "$500-$3,000"),
        "GitLab Token":           (r"glpat-[A-Za-z0-9\-_]{20}",                             8.5, "$300-$2,000"),
        "NPM Token":              (r"npm_[A-Za-z0-9]{36}",                                   7.5, "$200-$1,000"),
        "Docker Hub Token":       (r"dckr_pat_[A-Za-z0-9_-]{27}",                           7.5, "$200-$800"),
        "Heroku API Key":         (r'(?:heroku|HEROKU_API_KEY)[\s=:\"\'][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', 8.0, "$300-$1,500"),

        # ── Databases & Infra ─────────────────────────────────────────────
        "Firebase URL":           (r"https://[a-zA-Z0-9-]+\.firebaseio\.com",                8.5, "$500-$2,000"),
        "MongoDB URI":            (r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s\"']+",             9.8, "$500-$3,000"),
        "PostgreSQL DSN":         (r"postgres(?:ql)?://[^:]+:[^@]+@[^\s\"']+",              9.8, "$500-$3,000"),
        "Redis URL":              (r"redis://:[^@]+@[^\s\"']+",                              8.0, "$200-$1,000"),

        # ── Security & Auth ───────────────────────────────────────────────
        "JWT Token":              (r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*", 8.5, "$300-$2,000"),
        "Private Key (RSA/EC)":   (r"-----BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY-----",     10.0, "$1,000-$10,000"),
        "Generic Bearer Token":   (r"[Bb]earer [A-Za-z0-9\-_=.]{20,}",                      7.5, "$200-$1,000"),
    }

    # Paths to scan — expanded from 5 to 20+
    SCAN_PATHS = [
        "/", "/.env", "/.env.local", "/.env.production", "/.env.backup",
        "/config.js", "/assets/app.js", "/static/app.js", "/js/app.js",
        "/wp-config.php.bak", "/config.php.bak", "/settings.py",
        "/application.properties", "/appsettings.json", "/credentials.json",
        "/serviceAccountKey.json", "/.git/config", "/Dockerfile",
        "/docker-compose.yml", "/firebase.json",
    ]

    # CVSS details per type
    CVSS_INFO = {
        "regex":   {"score": None, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
        "entropy": {"score": 7.5,  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    }

    def calculate_entropy(self, data):
        """Calculates Shannon entropy of a string."""
        import math
        if not data: return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def get_cvss_for_type(self, secret_type, method="regex"):
        """Returns CVSS score and vector for a given secret type."""
        for name, (pattern, cvss, bounty) in self.RE_PATTERNS.items():
            if name == secret_type:
                return cvss, self.CVSS_INFO["regex"]["vector"]
        return self.CVSS_INFO["entropy"]["score"], self.CVSS_INFO["entropy"]["vector"]

    def get_bounty_estimate(self, secret_type):
        """Returns estimated bounty range for a secret type."""
        for name, (pattern, cvss, bounty) in self.RE_PATTERNS.items():
            if name == secret_type:
                return bounty
        return "$100-$500"

    def get_platform_recommendation(self, secret_type):
        """Returns the best bug bounty platform for a given finding type."""
        high_value = ["AWS Access Key", "AWS Secret Key", "GCP Service Account", "Private Key (RSA/EC)",
                      "Stripe Live Key", "PayPal OAuth Token", "Azure Storage Key", "Google API Key",
                      "GitHub Token", "MongoDB URI", "PostgreSQL DSN"]
        medium_value = ["Slack Token", "JWT Token", "GitLab Token", "SendGrid API Key",
                        "Twilio API Key", "Firebase URL", "Heroku API Key"]

        if secret_type in high_value:
            return "HackerOne (H1) — Critical/High tier. Expected response: 1-3 days. Also report directly to vendor."
        elif secret_type in medium_value:
            return "Bugcrowd or Intigriti — Medium/High tier. Also consider direct vendor disclosure."
        else:
            return "YesWeHack or direct vendor email disclosure."

    def get_remediation(self, secret_type):
        """Returns concise remediation steps."""
        steps = [
            f"1. Immediately REVOKE the exposed {secret_type} from the issuing platform's dashboard.",
            "2. Rotate all related secrets and regenerate access credentials.",
            "3. Remove the secret from the source code/configuration file.",
            "4. Add the secret to a secrets manager (AWS Secrets Manager, HashiCorp Vault, or GitHub Encrypted Secrets).",
            "5. Add pre-commit hooks (e.g., `git-secrets` or `truffleHog`) to prevent future exposure.",
            "6. Audit access logs for the exposed key to determine if it was previously exploited.",
        ]
        return "\n".join(steps)

    async def validate_secret(self, secret_type, secret_value):
        """Live API validation — confirms if a found secret is active."""
        import httpx
        status = "UNVERIFIED"
        evidence = ""
        try:
            async with httpx.AsyncClient(timeout=state.NETWORK_TIMEOUT, verify=False) as client:
                st = secret_type.lower()

                if "aws access key" in st:
                    # Validate via STS GetCallerIdentity (no signing needed for error check)
                    r = await client.post(
                        "https://sts.amazonaws.com/",
                        params={"Action": "GetCallerIdentity", "Version": "2011-06-15"},
                        headers={"Authorization": f"AWS4-HMAC-SHA256 Credential={secret_value}"}
                    )
                    if r.status_code == 403:
                        status = "VALID (AuthFailure — key exists but needs secret key)"
                        evidence = r.text[:200]
                    elif "InvalidClientTokenId" in r.text:
                        status = "INVALID"
                    else:
                        status = "UNVERIFIED"

                elif "google api key" in st or "google oauth" in st:
                    r = await client.get(
                        f"https://www.googleapis.com/oauth2/v1/tokeninfo",
                        params={"access_token": secret_value}
                    )
                    if r.status_code == 200:
                        status = "VALID"
                        evidence = r.text[:300]
                    elif "invalid_token" in r.text.lower():
                        status = "INVALID"

                elif "github" in st:
                    r = await client.get(
                        "https://api.github.com/user",
                        headers={"Authorization": f"token {secret_value}", "User-Agent": "curl/7.64"}
                    )
                    if r.status_code == 200:
                        data = r.json()
                        status = "VALID"
                        evidence = f"User: {data.get('login')} | Repos: {data.get('public_repos')}"
                    elif r.status_code == 401:
                        status = "INVALID"

                elif "stripe" in st:
                    r = await client.get(
                        "https://api.stripe.com/v1/account",
                        auth=(secret_value, "")
                    )
                    if r.status_code == 200:
                        data = r.json()
                        status = "VALID"
                        evidence = f"Account: {data.get('id')} | Email: {data.get('email')}"
                    elif r.status_code == 401:
                        status = "INVALID"

                elif "sendgrid" in st:
                    r = await client.get(
                        "https://api.sendgrid.com/v3/user/account",
                        headers={"Authorization": f"Bearer {secret_value}"}
                    )
                    if r.status_code == 200:
                        status = "VALID"
                        evidence = r.text[:200]
                    elif r.status_code == 401:
                        status = "INVALID"

                elif "slack" in st:
                    r = await client.get(
                        f"https://slack.com/api/auth.test?token={secret_value}"
                    )
                    data = r.json()
                    if data.get("ok"):
                        status = "VALID"
                        evidence = f"Team: {data.get('team')} | User: {data.get('user')}"
                    else:
                        status = "INVALID"
                        
                elif "openai" in st:
                    r = await client.get(
                        "https://api.openai.com/v1/models",
                        headers={"Authorization": f"Bearer {secret_value}"}
                    )
                    if r.status_code == 200:
                        status = "VALID"
                        evidence = "Access to OpenAI API Confirmed (Models List Retrieve Success)"
                    elif r.status_code == 401:
                        status = "INVALID"
                        
                elif "discord webhook" in st:
                    r = await client.get(secret_value)
                    if r.status_code == 200:
                        data = r.json()
                        status = "VALID"
                        evidence = f"Webhook Name: {data.get('name')} | Guild ID: {data.get('guild_id')}"
                    elif r.status_code in [401, 404]:
                        status = "INVALID"
                        
                elif "twilio" in st:
                    # Twilio requires Account SID and Auth Token, but we only have one string natively. Let's try basic validation if it's formatted like a normal key.
                    # As a heuristic, if it starts with 'SK' it's an API Key, if 'AC' it's Account SID. We'll mark it as POTENTIALLY VALID for manual review to avoid false negatives.
                    status = "UNVERIFIED (High Confidence)"
                    evidence = f"Twilio Key Detected: {secret_value[:5]}..."
                    
                elif "google map" in st or "gmap" in st:
                    r = await client.get(
                        f"https://maps.googleapis.com/maps/api/staticmap?center=40.714728,-73.998672&zoom=12&size=400x400&key={secret_value}"
                    )
                    if r.status_code == 200:
                        status = "VALID"
                        evidence = "Google Maps API Key is ACTIVE and vulnerable to quota theft/billing exploits."
                    elif r.status_code in [400, 403]:
                        # 403 means it exists but is restricted.
                        status = "VALID (IP/Referer Restricted)"
                        evidence = "Requires origin manipulation to exploit."

        except Exception as e:
            status = "UNVERIFIED"
            evidence = str(e)[:100]

        return status, evidence

    async def scan_for_secrets(self, url):
        """Scans for leaked secrets using RegEx and high-entropy string detection (v3 - Expanded)."""
        if not url.startswith("http"):
            url = f"http://{url}"
        
        # v22.6 DNS Pre-flight Guard
        import urllib.parse as _urlp
        _h = _urlp.urlparse(url).netloc
        if state.is_dns_failed(_h):
            return []
            
        console.print(f"[bold yellow][*] Bounty Hunter v3: Scanning for secrets on {url}...[/bold yellow]")
        
        found_secrets = []
        seen = set()  # Deduplication: (secret_type, value_prefix)
        try:
            for path in self.SCAN_PATHS:
                full_url = f"{url.rstrip('/')}{path}"
                response = await session.get(full_url, timeout=state.NETWORK_TIMEOUT)
                
                if response and response.status_code == 200:
                    content = response.text
                    
                    # 1. RegEx Matching (35+ patterns)
                    for name, (pattern, cvss_score, bounty_est) in self.RE_PATTERNS.items():
                        matches = re.findall(pattern, content)
                        if matches:
                            for match in matches:
                                match_str = match if isinstance(match, str) else match[0]
                                if len(match_str) < 10:
                                    continue
                                dedup_key = (name, match_str[:16])
                                if dedup_key in seen:
                                    continue
                                seen.add(dedup_key)
                                # Live validation
                                val_status, val_evidence = await self.validate_secret(name, match_str)
                                secret_info = {
                                    "type": name, 
                                    "value": match_str,
                                    "location": full_url, 
                                    "method": "regex",
                                    "cvss_score": cvss_score,
                                    "bounty_estimate": bounty_est,
                                    "platform": self.get_platform_recommendation(name),
                                    "remediation": self.get_remediation(name),
                                    "validation_status": val_status,
                                    "validation_evidence": val_evidence,
                                }
                                found_secrets.append(secret_info)
                                
                                badge = "[bold green][VALID] VALID[/bold green]" if "VALID" in val_status else "[yellow][WARN] UNVERIFIED[/yellow]"
                                console.print(f"[bold red][!!!] BOUNTY (Regex): {name} found in {full_url}[/bold red] {badge}")
                                console.print(f"[bold red]      VALUE: {bounty_est}[/bold red]")
                                if val_evidence:
                                    console.print(f"      [dim cyan]Proof: {val_evidence}[/dim cyan]")

                    # 2. Broken Link Hijacking (Phase 8)
                    broken_links = await self.hijacker.scan_for_broken_links(content, url)
                    if broken_links:
                        for bl in broken_links:
                            found_secrets.append({
                                "type": bl["type"],
                                "content": bl["content"],
                                "severity": bl["severity"],
                                "location": full_url,
                                "method": "hijack-probe"
                            })
                            console.print(f"[bold magenta][[HIJACK]] POTENTIAL HIJACK: {bl['platform']} handle '{bl['handle']}' found on {url}[/bold magenta]")
                    
                    # 3. Context-Aware Entropy Detection (v4 — no false positives)
                    # Only flag high-entropy strings near variable keywords
                    CONTEXT_KEYWORDS = r'(?:key|token|secret|password|auth|api|credential|access|private)[\s=:\"\']'
                    context_candidates = re.findall(
                        CONTEXT_KEYWORDS + r'([A-Za-z0-9/\+=]{32,64})', content, re.IGNORECASE
                    )
                    for pk in context_candidates:
                        entropy = self.calculate_entropy(pk)
                        if entropy > 4.5:
                            if not any(pk in s["value"] for s in found_secrets):
                                dedup_key = ("High-Entropy String", pk[:16])
                                if dedup_key in seen:
                                    continue
                                seen.add(dedup_key)
                                secret_info = {
                                    "type": "High-Entropy String", "value": pk,
                                    "location": full_url, "method": "entropy",
                                    "score": round(entropy, 2),
                                    "cvss_score": 7.5,
                                    "bounty_estimate": "$100-$500",
                                    "platform": "Bugcrowd or direct vendor disclosure.",
                                    "remediation": self.get_remediation("High-Entropy String"),
                                    "validation_status": "UNVERIFIED",
                                    "validation_evidence": "",
                                }
                                console.print(f"[bold red][!!!] BOUNTY (Entropy): Possible secret (E:{round(entropy, 2)}) in {full_url}[/bold red]")
                                comm_link.send_telegram_alert(f"[WARN] High-Entropy Secret Detected!\nValue: `{pk[:8]}...`\nURL: `{full_url}`")
                                found_secrets.append(secret_info)
                                
        except Exception as e:
            console.print(f"[red][!] Secret scan error: {str(e)}[/red]")
            
        return found_secrets

    def estimate_value(self, finding_type):
        """Estimates the potential bounty value based on the finding type."""
        for name, (pattern, cvss, bounty) in self.RE_PATTERNS.items():
            if name == finding_type:
                # Return the max of the range
                try:
                    return int(bounty.split("-$")[1].replace(",", "").replace("$", ""))
                except:
                    return 500
        return 100


class DuplicateFinder:
    """
    Phase 8: Duplicate Detection Engine.
    Checks the Aura database for findings that were already reported recently,
    preventing wasted submissions and platform reputation damage.
    """

    def __init__(self, db_path=None):
        from aura.core.storage import AuraStorage
        self.db = AuraStorage(db_path)

    def check_recent_duplicates(self, target_filter: str = None, days: int = 7) -> list[dict]:
        """
        Checks the DB for findings on the same target within the last `days` days.
        Returns a list of duplicate findings with metadata.
        """
        from aura.core.reporter import AuraReporter
        try:
            pdf_reporter = AuraReporter(self.db.db_path)
            targets, _, _, _ = pdf_reporter._fetch_data(target_filter)
        except Exception:
            return []

        from datetime import datetime, timezone, timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        duplicates = []
        for t in targets:
            domain = t.get("value", "Target")
            for f in t.get("findings", []):
                f_type = f.get("finding_type", f.get("type", ""))
                f_url  = f.get("evidence_url", f.get("location", ""))

                # Try to parse the finding timestamp
                raw_ts = f.get("timestamp", f.get("created_at", ""))
                if raw_ts:
                    try:
                        # Handle both timezone-aware and naive timestamps
                        if isinstance(raw_ts, str):
                            ts = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
                        else:
                            ts = raw_ts
                        if ts.tzinfo is None:
                            ts = ts.replace(tzinfo=timezone.utc)
                        if ts >= cutoff:
                            days_ago = (datetime.now(timezone.utc) - ts).days
                            duplicates.append({
                                "type": f_type,
                                "domain": domain,
                                "url": f_url,
                                "days_ago": days_ago,
                            })
                    except Exception:
                        pass

        return duplicates

    def is_duplicate(self, finding_type: str, url: str, days: int = 7) -> bool:
        """Quick check: returns True if this exact finding was seen recently."""
        dupes = self.check_recent_duplicates()
        for d in dupes:
            if d["type"] == finding_type and d["url"] == url:
                return True
        return False
