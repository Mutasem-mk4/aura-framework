import asyncio
import os
import json
from typing import List, Dict, Any, Optional
from playwright.async_api import async_playwright
from rich.console import Console
import httpx
import re

from aura.ui.formatter import console

class OMEGACrawler:
    """v51.0: Stateful Headless Browser Cluster for SPA Deep Mapping."""
    
    def __init__(self, proxy_url: str = "http://127.0.0.1:8081", concurrency: int = 3):
        self.proxy_url = proxy_url
        self.concurrency = concurrency
        self.visited_urls = set()
        self.discovery_queue = asyncio.Queue()
        self._browser = None
        self._playwright = None

    async def start(self):
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(headless=True)
        console.print(f"[bold cyan][🌀] OMEGA Crawler initialized (Proxy: {self.proxy_url})[/bold cyan]")

    async def crawl(self, base_url: str, depth: int = 2):
        """Crawl the application while routing all traffic through the Nexus Proxy."""
        self.visited_urls.add(base_url)
        await self.discovery_queue.put((base_url, 0))
        
        workers = []
        for _ in range(self.concurrency):
            workers.append(asyncio.create_task(self._worker()))
            
        await self.discovery_queue.join()
        for w in workers:
            w.cancel()
        
        console.print(f"[bold green][✓] OMEGA Crawl complete. {len(self.visited_urls)} nodes mapped.[/bold green]")

    async def _worker(self):
        while True:
            url, current_depth = await self.discovery_queue.get()
            try:
                # v3.0 Omega: Hybrid Perception check
                is_spa, evidence = await self.should_spawn_browser(url)
                if is_spa:
                    console.print(f"[bold magenta]| [🧠] HybridPerception: SPA Detected ({evidence}). Launching OMEGABrowser...[/bold magenta]")
                    await self._browse_page(url, current_depth)
                else:
                    console.print(f"[dim]| [👣] HybridPerception: Static/SSR Detected. Using Lightweight Scraper.[/dim]")
                    await self._static_scrape(url, current_depth)
            finally:
                self.discovery_queue.task_done()

    async def should_spawn_browser(self, url: str) -> tuple[bool, str]:
        """v3.0: Decision engine to prevent browser overhead on simple pages."""
        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                resp = await client.get(url)
                html = resp.text.lower()
                
                # SPA Indicators
                indicators = {
                    "React": ["react-root", "_reactroot", "react.development.js", "react.production.min.js"],
                    "Vue": ["vue.js", "vue.min.js", "data-v-", "app._vue"],
                    "Angular": ["ng-version", "ng-app", "ng-controller"],
                    "Svelte": ["svelte-", "svelte.js"],
                    "MountPoints": ["<div id=\"root\">", "<div id=\"app\">", "<div id=\"__next\">"]
                }
                
                for category, signs in indicators.items():
                    if any(sign.lower() in html for sign in signs):
                        return True, category
                        
                return False, ""
        except:
            return True, "Fallback (Error)" # If check fails, default to safe (browser)

    async def _static_scrape(self, url: str, depth: int):
        """Ultra-lightweight regex-based link extraction for non-SPA targets."""
        if depth > 2: return
        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                resp = await client.get(url)
                # Simple link extraction
                links = re.findall(r'href=["\'](/?[\w\-/.]+)["\']', resp.text)
                for href in set(links):
                    if href.startswith("/") and not href.startswith("//"):
                        full_url = url.split("?")[0].rstrip("/") + href
                        if full_url not in self.visited_urls:
                            self.visited_urls.add(full_url)
                            await self.discovery_queue.put((full_url, depth + 1))
        except: pass

    async def _browse_page(self, url: str, depth: int):
        if depth > 2: return # Hard limit for performance
        
        # Load Taint Hook
        hook_path = os.path.join(os.path.dirname(__file__), "taint_hook.js")
        with open(hook_path, "r") as f:
            hook_js = f.read()

        # Create a new context per page to isolate but use the same proxy
        context = await self._browser.new_context(
            proxy={"server": self.proxy_url},
            viewport={"width": 1280, "height": 720}
        )
        # Inject Taint Hook on every page creation
        await context.add_init_script(hook_js)
        
        page = await context.new_page()
        
        try:
            console.print(f"[dim]| [🕷️] Crawling: {url}[/dim]")
            await page.goto(url, wait_until="networkidle", timeout=30000)
            
            # 1. Trigger common interactions (buttons, links)
            # This handles SPA dynamic content triggering
            links = await page.query_selector_all("a")
            for link in links:
                href = await link.get_attribute("href")
                if href and href.startswith("/") and not href.startswith("//"):
                    full_url = url.split("?")[0].rstrip("/") + href
                    if full_url not in self.visited_urls:
                        self.visited_urls.add(full_url)
                        await self.discovery_queue.put((full_url, depth + 1))

            # 2. v40.0 OMEGA: Deep Semantic Interaction
            # Identify 'Sensitive' elements for state-changing discovery
            high_value_keywords = ["admin", "checkout", "payment", "transfer", "user", "settings", "profile", "config", "api"]
            actions = await page.query_selector_all("button, .btn, [role='button'], a")
            
            for action in actions:
                text = (await action.inner_text() or "").lower()
                cls = (await action.get_attribute("class") or "").lower()
                eid = (await action.get_attribute("id") or "").lower()
                
                if any(k in text or k in cls or k in eid for k in high_value_keywords):
                    try:
                        console.print(f"[bold magenta]| [🧬] DeepInteraction: Triggering high-value element ({text[:20]}...)[/bold magenta]")
                        await action.click(timeout=2000)
                        await asyncio.sleep(1) # Allow for state transition
                        # Check for new URLs after click
                        new_url = page.url
                        if new_url not in self.visited_urls:
                            self.visited_urls.add(new_url)
                            await self.discovery_queue.put((new_url, depth))
                    except: pass
                
        except Exception as e:
            console.print(f"[red][!] OMEGA Error on {url}: {e}[/red]")
        finally:
            await context.close()

    async def stop(self):
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()

if __name__ == "__main__":
    async def main():
        crawler = OMEGACrawler()
        await crawler.start()
        await crawler.crawl("https://example.com")
        await crawler.stop()
    
    asyncio.run(main())
