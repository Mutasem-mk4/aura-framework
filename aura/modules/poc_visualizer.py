import asyncio
import os
from datetime import datetime
from rich.console import Console

console = Console()

class PoCVisualizer:
    """
    v26.0 The Verdict: Visual Exploitation Proof Generator.
    Uses Playwright to autonomously visit 1-click PoC links, trigger payloads,
    and capture undeniable screenshot evidence of successful attacks (e.g. XSS alerts).
    """
    
    def __init__(self):
        # Anchor screenshots to the project's reports folder
        _pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        self.evidence_dir = os.path.join(_pkg_root, "reports", "evidence")
        
        if not os.path.exists(self.evidence_dir):
            os.makedirs(self.evidence_dir)
            
    async def _capture_with_playwright(self, url: str, finding_type: str) -> str | None:
        """Core Playwright logic for visiting a URL and taking a screenshot."""
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            console.print("[dim red][PoC Visualizer] Playwright is not installed. Run: pip install playwright && playwright install[/dim red]")
            return None

        screenshot_path = None
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_type = finding_type.replace(" ", "_").replace("/", "_").lower()
        filename = f"evidence_{safe_type}_{timestamp}.png"
        filepath = os.path.join(self.evidence_dir, filename)

        try:
            async with async_playwright() as p:
                # Launch Chromium headlessly
                browser = await p.chromium.launch(headless=True)
                # Create a context that records videos if needed, but we start with screenshots
                context = await browser.new_context(
                    viewport={'width': 1280, 'height': 800},
                    ignore_https_errors=True
                )
                
                page = await context.new_page()
                alert_triggered = False
                
                # Setup dialog handler to catch XSS alerts automatically
                async def handle_dialog(dialog):
                    nonlocal alert_triggered
                    alert_triggered = True
                    console.print(f"[bold green][📸 PoC Visualizer] Alert intercepted: '{dialog.message}'[/bold green]")
                    # Screenshot exactly when the alert is visible.
                    # Note: Playwright automatically dismisses dialogs after handlers,
                    # but we can take a screenshot of the page right before dismissing.
                    await page.screenshot(path=filepath, full_page=False)
                    await dialog.accept()
                    
                page.on("dialog", handle_dialog)

                try:
                    # Navigate to the PoC Link
                    console.print(f"[dim cyan][📸 PoC Visualizer] Navigating to PoC URL: {url}[/dim cyan]")
                    await page.goto(url, timeout=15000, wait_until="networkidle")
                    
                    # Wait a moment for any DOM mutations or delayed scripts to execute
                    await asyncio.sleep(2)
                    
                    if alert_triggered and os.path.exists(filepath):
                        screenshot_path = filepath
                    else:
                        # If no alert triggered (e.g., Open Redirect, SSRF output, SQLi page),
                        # take a screenshot of the resulting page's visual state.
                        await page.screenshot(path=filepath, full_page=True)
                        screenshot_path = filepath
                        console.print(f"[bold green][📸 PoC Visualizer] Captured page state screenshot.[/bold green]")
                        
                except Exception as net_err:
                    # If navigation fails (e.g. server down, or infinite redirect), capture whatever is there
                    console.print(f"[dim yellow][📸 PoC Visualizer] Navigation interrupted ({net_err}). Snapping current state.[/dim yellow]")
                    await page.screenshot(path=filepath)
                    screenshot_path = filepath
                
                finally:
                    await browser.close()
                    
        except Exception as e:
            console.print(f"[bold red][PoC Visualizer] Fatal error capturing proof: {e}[/bold red]")
            
        return screenshot_path

    async def generate_visual_proof(self, poc_link: str, finding_type: str = "exploit") -> str | None:
        """
        Public method to generate proof. Wraps the capturing logic.
        """
        if not poc_link or not poc_link.startswith("http"):
            return None
            
        console.print(f"[bold magenta][*] Generating Visual Proof for {finding_type}...[/bold magenta]")
        return await self._capture_with_playwright(poc_link, finding_type)
