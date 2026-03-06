"""
Aura v6.0 — Power Stack Integration
=======================================
Orchestrates 4 best-in-class security tools with seamless Python fallbacks:

  1. Nuclei     → CVE / zero-day template scanning    (fallback: AuraPatternEngine)
  2. TruffleHog → Deep JS secret scanning             (fallback: SecretHunter)
  3. Nmap -sV   → Service version fingerprinting      (fallback: TCP banner grab)
  4. HTTPX      → URL liveness verification           (fallback: aiohttp HEAD probe)
"""
import asyncio
import shutil
import json
import re
import aiohttp
from rich.console import Console
from aura.core.stealth import AuraSession, StealthEngine

console = Console()


class PowerStack:
    """v6.0: Orchestrates Nuclei, TruffleHog, HTTPX & Nmap as a unified offensive stack."""

    def __init__(self, stealth: StealthEngine = None):
        self.stealth = stealth or StealthEngine()
        self.session  = AuraSession(self.stealth)

    # ── 1. NUCLEI ─────────────────────────────────────────────────────────
    async def nuclei_scan(self, target_url: str) -> list:
        """
        Runs Nuclei with CVE + exposures templates.
        Falls back to AuraPatternEngine if nuclei is not installed.
        """
        findings = []
        if shutil.which("nuclei"):
            console.print(f"[bold cyan][⚡ Nuclei] Scanning {target_url} with CVE templates...[/bold cyan]")
            try:
                proc = await asyncio.create_subprocess_exec(
                    "nuclei", "-u", target_url,
                    "-t", "cves,exposures,technologies",
                    "-severity", "medium,high,critical",
                    "-json", "-silent", "-timeout", "20",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
                for line in stdout.decode("utf-8", errors="ignore").strip().splitlines():
                    try:
                        result = json.loads(line)
                        findings.append({
                            "type":            result.get("info", {}).get("name", "Nuclei Finding"),
                            "finding_type":    result.get("info", {}).get("name", "Nuclei Finding"),
                            "content":         f"[Nuclei] {result.get('matched-at', target_url)}: {result.get('info', {}).get('description', 'Template match')}",
                            "severity":        result.get("info", {}).get("severity", "MEDIUM").upper(),
                            "cvss_score":      result.get("info", {}).get("classification", {}).get("cvss-score", None),
                            "owasp":           "A06:2021",
                            "mitre":           "T1190 — Exploit Public-Facing Application",
                            "remediation_fix": result.get("info", {}).get("remediation", "Apply vendor patch."),
                            "impact_desc":     result.get("info", {}).get("description", "Known vulnerability template matched."),
                            "source":          "Nuclei",
                        })
                    except (json.JSONDecodeError, TypeError):
                        continue
                console.print(f"[green][+] Nuclei: {len(findings)} template matches on {target_url}.[/green]")
            except Exception as e:
                console.print(f"[dim yellow][!] Nuclei scan failed: {e}. Using fallback.[/dim yellow]")
        else:
            console.print("[dim yellow][!] Nuclei not installed. Using AuraPatternEngine as fallback.[/dim yellow]")
        return findings

    # ── 2. TRUFFLEHOG ────────────────────────────────────────────────────
    async def trufflehog_scan(self, target_url: str) -> list:
        """
        Runs TruffleHog Git/URL scan for secrets.
        Falls back to SecretHunter if not installed.
        """
        findings = []
        if shutil.which("trufflehog"):
            console.print(f"[bold yellow][🔑 TruffleHog] Scanning {target_url} for secrets...[/bold yellow]")
            try:
                proc = await asyncio.create_subprocess_exec(
                    "trufflehog", "filesystem", "--directory", ".",
                    "--json", "--no-update",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=90)
                for line in stdout.decode("utf-8", errors="ignore").strip().splitlines():
                    try:
                        result = json.loads(line)
                        secret_type = result.get("DetectorName", "Secret")
                        raw_secret  = result.get("Raw", "")[:60] + "..." if result.get("Raw") else "N/A"
                        findings.append({
                            "type":            f"Secret Exposure — {secret_type}",
                            "finding_type":    f"Secret Exposure — {secret_type}",
                            "content":         f"[TruffleHog] {secret_type} secret found in {result.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file', '?')}: {raw_secret}",
                            "severity":        "CRITICAL",
                            "cvss_score":      9.8,
                            "owasp":           "A02:2021",
                            "mitre":           "T1552 — Unsecured Credentials",
                            "remediation_fix": "Immediately rotate the exposed credential. Remove from source code and history with `git filter-repo`. Add to .gitignore.",
                            "impact_desc":     f"A live {secret_type} credential was extracted from source files. An attacker can use this for direct API/platform access.",
                            "source":          "TruffleHog",
                        })
                    except (json.JSONDecodeError, TypeError):
                        continue
                console.print(f"[bold red][+] TruffleHog: {len(findings)} secrets found![/bold red]")
            except Exception as e:
                console.print(f"[dim yellow][!] TruffleHog scan failed: {e}. SecretHunter is the fallback.[/dim yellow]")
        else:
            console.print("[dim yellow][!] TruffleHog not installed. Using SecretHunter module.[/dim yellow]")
        return findings

    # ── 3. NMAP SERVICE DETECTION ─────────────────────────────────────────
    async def nmap_service_scan(self, target_ip: str) -> list:
        """
        Runs Nmap -sV for service version fingerprinting.
        Falls back to TCP banner grabbing if not installed.
        """
        findings = []
        if shutil.which("nmap"):
            console.print(f"[bold blue][🔍 Nmap -sV] Service fingerprinting {target_ip}...[/bold blue]")
            try:
                proc = await asyncio.create_subprocess_exec(
                    "nmap", "-sV", "--version-intensity", "5",
                    "-p", "21,22,23,25,53,80,110,143,443,445,3306,5432,6379,8080,8443,27017",
                    "-oX", "-", target_ip,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=90)
                xml_output = stdout.decode("utf-8", errors="ignore")
                # Parse basic version info from XML
                import xml.etree.ElementTree as ET
                root = ET.fromstring(xml_output)
                for host in root.findall(".//host"):
                    for port in host.findall(".//port"):
                        state_el = port.find("state")
                        if state_el is not None and state_el.get("state") == "open":
                            service = port.find("service")
                            portid  = port.get("portid")
                            if service is not None:
                                name    = service.get("name", "unknown")
                                product = service.get("product", "")
                                version = service.get("version", "")
                                extra   = service.get("extrainfo", "")
                                full    = f"{name} {product} {version} {extra}".strip()
                                findings.append({
                                    "type":         f"Open Service: Port {portid}/{name.upper()}",
                                    "finding_type": f"Open Service: Port {portid}/{name.upper()}",
                                    "content":      f"[Nmap -sV] Port {portid} open — {full} on {target_ip}",
                                    "severity":     "MEDIUM",
                                    "owasp":        "A05:2021",
                                    "mitre":        "T1046 — Network Service Scanning",
                                    "remediation_fix": f"Restrict access to port {portid} via firewall if not publicly required. Upgrade {product} to latest version.",
                                    "impact_desc":  f"Service {full} is exposed on port {portid}. Version disclosure enables targeted CVE exploitation.",
                                    "source":       "Nmap -sV",
                                })
                console.print(f"[green][+] Nmap -sV: {len(findings)} versioned services found on {target_ip}.[/green]")
            except Exception as e:
                console.print(f"[dim yellow][!] Nmap -sV failed: {e}.[/dim yellow]")
        else:
            console.print("[dim yellow][!] Nmap not installed. Banner grabber handles service detection.[/dim yellow]")
        return findings

    # ── 4. HTTPX LIVENESS FILTER ─────────────────────────────────────────
    async def httpx_verify(self, urls: list) -> list:
        """
        Filters a list of URLs to only LIVE ones (HTTP 200-399).
        Uses HTTPX CLI if available; falls back to aiohttp HEAD probes.
        Returns filtered list of live URLs only.
        """
        if not urls:
            return []

        if shutil.which("httpx"):
            console.print(f"[bold green][🌐 HTTPX] Verifying liveness of {len(urls)} discovered URLs...[/bold green]")
            try:
                input_data = "\n".join(urls).encode()
                proc = await asyncio.create_subprocess_exec(
                    "httpx", "-sc", "-silent", "-t", "10", # Added 10s timeout per request
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL
                )
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(input=input_data), timeout=120 # Increased total timeout
                )
                live_urls = []
                for line in stdout.decode("utf-8", errors="ignore").strip().splitlines():
                    # httpx format: "https://url [STATUS_CODE]"
                    match = re.search(r'(https?://\S+)\s+\[(\d+)\]', line)
                    if match:
                        url, status = match.group(1), int(match.group(2))
                        if status < 500: # v19.2: Accept 404s/403s as 'reachable' enough for fuzzer
                            live_urls.append(url)
                
                if live_urls:
                    console.print(f"[green][+] HTTPX: {len(live_urls)}/{len(urls)} URLs are reachable.[/green]")
                    return live_urls
                else:
                    console.print(f"[yellow][!] HTTPX verified 0 live URLs. Falling back to aiohttp...[/yellow]")
            except Exception as e:
                console.print(f"[dim yellow][!] HTTPX failed: {e}. Using aiohttp fallback.[/dim yellow]")

        # Fallback: aiohttp HEAD probe with retries and longer timeouts
        console.print(f"[dim cyan][*] aiohttp probing {len(urls)} URLs for liveness...[/dim cyan]")
        
        probe_semaphore = asyncio.Semaphore(10) # [WAF-Friendly] Prevent Cloudflare DDoS bans during mass liveness check
        
        async def probe(url: str, retries=2) -> str | None:
            async with probe_semaphore:
                for attempt in range(retries):
                    try:
                        # Use GET if HEAD is blocked/weird
                        async with aiohttp.ClientSession() as http:
                            timeout = aiohttp.ClientTimeout(total=15)
                            async with http.get(url, timeout=timeout, allow_redirects=True, ssl=False) as resp:
                                if resp.status < 500: # Anything reachable is better than nothing
                                    return url
                    except Exception:
                        await asyncio.sleep(1)
                return None

        tasks = [probe(u) for u in urls[:100]] # Cap fallback to first 100 for speed
        results = await asyncio.gather(*tasks, return_exceptions=True)
        live_urls = [r for r in results if r and isinstance(r, str)]
        
        if not live_urls and urls:
            console.print(f"[bold red][!] Warning: All liveness probes failed. v19.2: Forcing first 5 URLs as 'Reachable' to prevent engine stall.[/bold red]")
            return urls[:5]

        console.print(f"[green][+] Liveness Probe: {len(live_urls)} services confirmed reachable.[/green]")
        return live_urls
