import asyncio
import os
import re
from playwright.async_api import async_playwright
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
            
        console.print(f"[bold yellow][*] VisualEye: Capturing screenshot & Analyzing {url}...[/bold yellow]")
        path = os.path.join(self.output_dir, f"{filename}.png")
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                await page.set_viewport_size({"width": 1280, "height": 720})
                await page.goto(url, timeout=15000, wait_until="networkidle")
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
