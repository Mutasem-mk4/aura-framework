import asyncio
import os
from playwright.async_api import async_playwright
from rich.console import Console

console = Console()

class VisualEye:
    """The 'Recon Eye' engine for automated target visualization."""
    
    def __init__(self, output_dir="screenshots"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    async def capture_screenshot(self, url, filename):
        """Captures a high-quality screenshot of a web target."""
        if not url.startswith("http"):
            url = f"http://{url}"
            
        console.print(f"[bold yellow][*] VisualEye: Capturing screenshot of {url}...[/bold yellow]")
        
        path = os.path.join(self.output_dir, f"{filename}.png")
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                # Set a realistic viewport
                await page.set_viewport_size({"width": 1280, "height": 720})
                
                # Go to URL with timeout
                await page.goto(url, timeout=15000, wait_until="networkidle")
                await asyncio.sleep(1) # Allow for dynamic content
                
                await page.screenshot(path=path)
                await browser.close()
                console.print(f"[bold green][+] Screenshot saved: {path}[/bold green]")
                return path
        except Exception as e:
            console.print(f"[red][!] VisualEye Error for {url}: {str(e)}[/red]")
            return None

    def get_screenshot_path(self, filename):
        return os.path.join(self.output_dir, f"{filename}.png")
