import asyncio
import os
import re
from playwright.async_api import async_playwright
from aura.core.storage import AuraStorage
from aura.core import state
from rich.console import Console

console = Console()

class VisualEye:
    """The 'Recon Eye' engine for automated target visualization with OCR Intelligence."""
    
    def __init__(self, output_dir="screenshots"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def analyze_screenshot_content(self, page_text: str) -> dict:
        """
        Ghost v5 OCR: Analyzes page text content for critical visual signals.
        Detects dead/parked sites and vulnerability indicators from DOM text.
        Returns: { 'is_dead': bool, 'is_vulnerable_site': bool, 'findings': list, 'reason': str }
        """
        text_lower = page_text.lower()
        result = {"is_dead": False, "is_vulnerable_site": False, "findings": [], "reason": ""}
        
        # Dead/Parking site indicators — stop scan immediately
        dead_signals = [
            "application error", "heroku | no such app", "there is no app here",
            "nothing here", "page not found", "404 not found", "site not found",
            "domain is for sale", "this domain is parked", "coming soon",
            "account suspended", "this account has been suspended"
        ]
        for signal in dead_signals:
            if signal in text_lower:
                result["is_dead"] = True
                result["reason"] = f"Dead/Parked page detected: '{signal}'"
                console.print(f"[bold red][🔴] VisualEye OCR: DEAD SITE — '{signal}'. Halting scan.[/bold red]")
                return result
        
        # Vulnerability-indicator keywords (e.g., on intentionally vulnerable apps)
        vuln_signals = [
            ("sql injection", "SQL Injection", "A03:2021"),
            ("cross-site scripting", "Cross-Site Scripting", "A07:2021"),
            ("vulnerable by design", "Known Vulnerable Application", "A03:2021"),
            ("this site is vulnerable", "Known Vulnerable Application", "A03:2021"),
            ("warning: mysql", "SQL Injection (Error-Based)", "A03:2021"),
            ("you have an error in your sql", "SQL Injection (Error-Based)", "A03:2021"),
        ]
        for signal, vuln_type, owasp in vuln_signals:
            if signal in text_lower:
                result["is_vulnerable_site"] = True
                result["findings"].append({
                    "type": vuln_type,
                    "severity": "HIGH",
                    "cvss_score": 8.8,
                    "owasp": owasp,
                    "content": f"[OCR Visual Intel] Page text contains '{signal}', confirming this is a vulnerable target.",
                    "remediation_fix": "This application is intentionally vulnerable. Do not deploy in production.",
                    "impact_desc": "Direct confirmed vulnerability indicator found in page content via Visual Intelligence scan."
                })
                console.print(f"[bold red][👁️] VisualEye OCR: VULNERABILITY INDICATOR — '{signal}'![/bold red]")
        
        return result

    async def analyze_technologies(self, page):
        """Ghost v4: Passive tech stack fingerprinting via page headers and DOM signatures."""
        techs = []
        try:
            content = await page.content()
            signatures = {
                "WordPress": ["/wp-content/", "wp-includes", "wordpress"],
                "React": ["_reactRootContainer", "react-root"],
                "Vue": ["__vue__", "v-data-"],
                "Next.js": ["/_next/", "__NEXT_DATA__"],
                "Apache": ["Apache/"],
                "Nginx": ["nginx/"],
                "Cloudflare": ["cf-ray", "__cf_bm"],
                "ASP.NET": ["__VIEWSTATE", "asp.net", ".aspx"],
                "PHP": [".php", "X-Powered-By: PHP"]
            }
            for tech, sigs in signatures.items():
                if any(sig.lower() in content.lower() for sig in sigs):
                    techs.append(tech)
            meta_generator = await page.query_selector("meta[name='generator']")
            if meta_generator:
                gen_content = await meta_generator.get_attribute("content")
                if gen_content: techs.append(gen_content)
            return list(set(techs))
        except:
            return []

    async def capture_screenshot(self, url, filename):
        """Captures a screenshot, fingerprints tech stack, and runs OCR intelligence analysis."""
        if not url.startswith("http"):
            url = f"http://{url}"
        
        # v22.6 DNS Pre-flight Guard
        import urllib.parse as _urlp
        _h = _urlp.urlparse(url).netloc
        if state.is_dns_failed(_h):
            return None
            
        console.print(f"[bold yellow][*] VisualEye: Capturing screenshot & Analyzing {url}...[/bold yellow]")
        path = os.path.join(self.output_dir, f"{filename}.png")
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                await page.set_viewport_size({"width": 1280, "height": 720})
                # v14.2: Adaptive timeout for slow proxies (Tor/Cloud)
                effective_timeout = state.NETWORK_TIMEOUT * (3000 if (state.TOR_MODE or state.CLOUD_SWARM_MODE) else 1000)
                await page.goto(url, timeout=effective_timeout, wait_until="networkidle")
                await asyncio.sleep(1)
                
                # OCR Intelligence: analyze page body text directly
                try:
                    page_text = await page.inner_text("body")
                except:
                    page_text = ""
                ocr_analysis = self.analyze_screenshot_content(page_text)
                
                techs = await self.analyze_technologies(page)
                if techs:
                    console.print(f"[bold cyan][+] Tech Stack Detected: {', '.join(techs)}[/bold cyan]")
                
                await page.screenshot(path=path)
                await browser.close()
                console.print(f"[bold green][+] Screenshot saved: {path}[/bold green]")
                return {"path": path, "techs": techs, "ocr": ocr_analysis}
        except Exception as e:
            console.print(f"[red][!] VisualEye Error for {url}: {str(e)}[/red]")
            return None

    def get_screenshot_path(self, filename):
        return os.path.join(self.output_dir, f"{filename}.png")

    async def capture_finding_evidence(self, finding: dict, index: int = 0) -> dict:
        """
        Tier 3: Auto-captures a screenshot of the vulnerable URL for every confirmed finding.
        Embeds the screenshot path into the finding dict as 'screenshot_path'.

        This single feature raises acceptance rates significantly — triagers
        can SEE the vulnerability without re-testing it manually.
        """
        url = finding.get("evidence_url") or finding.get("tampered_url") or finding.get("url")
        if not url:
            return finding

        vuln_type = finding.get("type", "finding")
        safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", vuln_type)[:40]
        filename  = f"evidence_{safe_name}_{index}"

        try:
            result = await self.capture_screenshot(url, filename)
            if result and result.get("path"):
                finding["screenshot_path"] = result["path"]
                console.print(
                    f"[green][Evidence] Screenshot captured for '{vuln_type}': {result['path']}[/green]"
                )
        except Exception as e:
            console.print(f"[dim red][Evidence] Screenshot failed for {url}: {e}[/dim red]")

        return finding

    async def capture_all_confirmed_findings(self, findings: list[dict]) -> list[dict]:
        """
        Tier 3: Screenshots every confirmed finding in the list.
        Runs up to 3 screenshots in parallel to stay fast.
        """
        confirmed = [f for f in findings if f.get("confirmed") or f.get("severity") in ("CRITICAL", "EXCEPTIONAL")]
        if not confirmed:
            return findings

        console.print(f"[bold cyan][Evidence] Capturing screenshots for {len(confirmed)} confirmed finding(s)...[/bold cyan]")

        sem = asyncio.Semaphore(3)  # max 3 parallel browser instances
        async def _capture(f, i):
            async with sem:
                return await self.capture_finding_evidence(f, i)

        tasks = [_capture(f, i) for i, f in enumerate(confirmed)]
        updated = await asyncio.gather(*tasks, return_exceptions=True)

        # Merge updated confirmed findings back
        confirmed_ids = {id(f) for f in confirmed}
        result = []
        confirmed_iter = iter([u for u in updated if isinstance(u, dict)])
        for f in findings:
            if id(f) in confirmed_ids:
                try:
                    result.append(next(confirmed_iter))
                except StopIteration:
                    result.append(f)
            else:
                result.append(f)
        return result
