"""
Aura v2 — Authenticated API Crawler
Uses Playwright to browse a target website with real session cookies,
intercepts every API call made by the browser, and builds a complete
'Discovery Map' (discovery_map.json) of all authenticated endpoints.

This is the foundation for Phase 2: feeding the IDOR Engine with
real, session-aware API endpoints that anonymous scanners never see.
"""

import asyncio
import json
import os
import re
import urllib.parse
from pathlib import Path
from typing import Optional
from datetime import datetime

try:
    from playwright.async_api import async_playwright, BrowserContext, Page
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


# Patterns that indicate an API endpoint (vs. static assets)
API_URL_PATTERNS = re.compile(
    r'(/api/|/v\d+/|/rest/|/graphql|/gql|/service/|/ajax/|/xhr/|'
    r'\.json$|/user/|/account|/profile|/cart|/order|/address|/wish)',
    re.IGNORECASE
)

# Patterns to SKIP (noise/analytics/ads)
SKIP_PATTERNS = re.compile(
    r'(google-analytics|doubleclick|facebook|contentsquare|datadoghq'
    r'|cookielaw|hotjar|segment\.io|amplitude|mixpanel|gtag'
    r'\.(css|js|png|jpg|gif|svg|woff|ico|ttf)$)',
    re.IGNORECASE
)

# HTTP methods that change state (high IDOR/CSRF interest)
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class AuthenticatedCrawler:
    """
    Playwright-based authenticated API crawler for Aura v2.
    
    Usage:
        crawler = AuthenticatedCrawler(
            target_url="https://www.iciparisxl.nl",
            cookies_str="bm_ss=abc; PIM-SESSION-ID=xyz; ...",
            output_dir="./reports"
        )
        discovery_map = await crawler.crawl(pages_to_visit=["/", "/cart", "/account"])
    """
    
    def __init__(
        self,
        target_url: str,
        cookies_str: str,
        output_dir: str = "./reports",
        max_requests: int = 300,
        timeout_ms: int = 15000,
    ):
        # Normalize URL - add https:// if missing
        if not target_url.startswith("http"):
            target_url = "https://" + target_url
        self.target_url = target_url.rstrip("/")
        self.target_domain = urllib.parse.urlparse(self.target_url).netloc
        self.cookies_str = cookies_str
        self.output_dir = Path(output_dir)
        self.max_requests = max_requests
        self.timeout_ms = timeout_ms
        
        # Discovery state
        self.api_calls: list[dict] = []
        self.visited_pages: set[str] = set()
        self.discovered_ids: dict[str, list] = {}  # URL pattern -> [IDs found]
        
    def _parse_cookies(self, cookies_str: str, domain: str) -> list[dict]:
        """Parses a raw cookie string into Playwright cookie dictionaries."""
        cookies = []
        for chunk in cookies_str.split(";"):
            chunk = chunk.strip()
            if "=" in chunk:
                name, _, value = chunk.partition("=")
                cookies.append({
                    "name": name.strip(),
                    "value": value.strip(),
                    "domain": domain,
                    "path": "/",
                })
        return cookies

    def _is_api_call(self, url: str) -> bool:
        """Determines if a URL represents an API call worth capturing."""
        if SKIP_PATTERNS.search(url):
            return False
        # Always capture anything from OUR target domain (includes api.* subdomain)
        parsed = urllib.parse.urlparse(url)
        base_domain = self.target_domain.replace("www.", "")
        if base_domain in parsed.netloc:
            # Skip static assets but keep everything else
            if re.search(r'\.(css|js|png|jpg|gif|svg|woff|ico|ttf|woff2|map)$', url, re.IGNORECASE):
                return False
            return True
        # Also capture known API patterns from other domains
        return bool(API_URL_PATTERNS.search(url))

    def _extract_ids(self, url: str) -> list[dict]:
        """Extracts potential IDs from a URL (numeric IDs, UUIDs)."""
        ids_found = []
        uuid_re = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE)
        numeric_re = re.compile(r'/(\d{3,})')
        
        for uid in uuid_re.findall(url):
            ids_found.append({"type": "uuid", "value": uid})
        for nid in numeric_re.findall(url):
            ids_found.append({"type": "numeric", "value": nid})
        return ids_found
    
    async def _setup_context(self, playwright) -> BrowserContext:
        """Launches browser with real session cookies loaded."""
        browser = await playwright.chromium.launch(headless=True)
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            ignore_https_errors=True,
        )
        
        # Inject session cookies
        cookies = self._parse_cookies(self.cookies_str, self.target_domain)
        # Also inject for api subdomain
        api_domain = "api." + self.target_domain.replace("www.", "")
        api_cookies = [dict(c, domain=api_domain) for c in cookies]
        await context.add_cookies(cookies + api_cookies)
        
        return context, browser

    async def _intercept_requests(self, page: Page, source_page_url: str):
        """
        Attaches a route handler to capture all API calls made by the page.
        """
        async def handle_request(route):
            request = route.request
            url = request.url
            method = request.method
            
            if self._is_api_call(url) and len(self.api_calls) < self.max_requests:
                ids = self._extract_ids(url)
                call = {
                    "url": url,
                    "method": method,
                    "headers": dict(request.headers),
                    "post_data": request.post_data,
                    "source_page": source_page_url,
                    "ids_found": ids,
                    "is_mutating": method in MUTATING_METHODS,
                    "timestamp": datetime.utcnow().isoformat(),
                }
                
                # Avoid exact duplicates
                if not any(c["url"] == url and c["method"] == method 
                           for c in self.api_calls):
                    self.api_calls.append(call)
                    priority = "🔥 MUTATING" if method in MUTATING_METHODS else "📡 API"
                    id_info = f" [IDs: {len(ids)}]" if ids else ""
                    print(f"  {priority} [{method}] {url[:100]}{id_info}")
            
            await route.continue_()
        
        await page.route("**/*", handle_request)

    async def _visit_page(self, context: BrowserContext, path: str):
        """Visits a single page and captures all API calls made during loading."""
        url = self.target_url + path if path.startswith("/") else path
        if url in self.visited_pages:
            return
        self.visited_pages.add(url)
        
        page = await context.new_page()
        try:
            await self._intercept_requests(page, url)
            print(f"\n📄 Visiting: {url}")
            await page.goto(url, timeout=self.timeout_ms, wait_until="networkidle")
            
            # Scroll to trigger lazy-loaded content
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await asyncio.sleep(2)
            
            # Collect links on this page for further crawling
            links = await page.evaluate("""
                () => Array.from(document.querySelectorAll('a[href]'))
                    .map(a => a.href)
                    .filter(h => h.startsWith(window.location.origin))
                    .slice(0, 20)
            """)
            return links
        except Exception as e:
            print(f"  ⚠️ Failed to load {url}: {type(e).__name__}: {str(e)[:80]}")
            return []
        finally:
            await page.close()

    async def crawl(self, pages_to_visit: Optional[list[str]] = None) -> dict:
        """
        Main crawl loop. Visits all specified pages and captures API calls.
        Returns the full discovery map.
        """
        if not PLAYWRIGHT_AVAILABLE:
            return {"error": "Playwright not installed. Run: pip install playwright && playwright install chromium"}
        
        if pages_to_visit is None:
            pages_to_visit = ["/", "/cart", "/account", "/wishlist", "/myAccount"]
        
        print(f"\n{'='*60}")
        print(f"🕷️  AURA v2 — Authenticated Crawler")
        print(f"🎯 Target: {self.target_url}")
        print(f"📋 Pages to scan: {len(pages_to_visit)}")
        print(f"{'='*60}")
        
        async with async_playwright() as playwright:
            context, browser = await self._setup_context(playwright)
            
            try:
                # Phase 1: Visit all specified seed pages
                all_discovered_links = []
                for path in pages_to_visit:
                    links = await self._visit_page(context, path)
                    if links:
                        all_discovered_links.extend(links)
                
                # Phase 2: Follow discovered links (one level deep)
                extra_paths = []
                for link in set(all_discovered_links):
                    parsed = urllib.parse.urlparse(link)
                    path = parsed.path
                    # Only follow links that look like account/user pages
                    if any(kw in path.lower() for kw in 
                           ["address", "order", "profile", "account", "wish", "payment"]):
                        extra_paths.append(path)
                
                for path in extra_paths[:10]:  # Limit auto-follow to 10
                    await self._visit_page(context, path)
                    
            finally:
                await browser.close()
        
        # Build the discovery map
        discovery_map = self._build_discovery_map()
        self._save_discovery_map(discovery_map)
        self._print_summary(discovery_map)
        return discovery_map

    def _build_discovery_map(self) -> dict:
        """Organizes raw API calls into a structured discovery map."""
        mutating_endpoints = [c for c in self.api_calls if c["is_mutating"]]
        idor_candidates = [c for c in self.api_calls if c["ids_found"]]
        
        return {
            "meta": {
                "target": self.target_url,
                "scan_time": datetime.utcnow().isoformat(),
                "total_api_calls": len(self.api_calls),
                "mutating_endpoints": len(mutating_endpoints),
                "idor_candidates": len(idor_candidates),
                "pages_visited": len(self.visited_pages),
            },
            "idor_candidates": [
                {
                    "url": c["url"],
                    "method": c["method"],
                    "ids": c["ids_found"],
                    "source_page": c["source_page"],
                    "post_data": c["post_data"],
                }
                for c in idor_candidates
            ],
            "mutating_endpoints": [
                {
                    "url": c["url"],
                    "method": c["method"],
                    "source_page": c["source_page"],
                    "post_data": c["post_data"],
                    "headers": {k: v for k, v in c["headers"].items() 
                               if k.lower() not in ["cookie", "authorization"]},
                }
                for c in mutating_endpoints
            ],
            "all_api_calls": self.api_calls,
        }

    def _save_discovery_map(self, discovery_map: dict):
        """Saves the discovery map to a JSON file."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        target_slug = self.target_domain.replace(".", "_").replace("www_", "")
        output_path = self.output_dir / f"discovery_map_{target_slug}.json"
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(discovery_map, f, indent=2)
        
        print(f"\n💾 Discovery map saved: {output_path}")

    def _print_summary(self, discovery_map: dict):
        """Prints a human-readable summary of the crawl results."""
        meta = discovery_map["meta"]
        print(f"\n{'='*60}")
        print(f"✅ CRAWL COMPLETE")
        print(f"{'='*60}")
        print(f"  📊 Total API Calls Intercepted : {meta['total_api_calls']}")
        print(f"  🔥 Mutating Endpoints (POST/PATCH/DELETE) : {meta['mutating_endpoints']}")
        print(f"  🎯 IDOR Candidates (with IDs in URL) : {meta['idor_candidates']}")
        print(f"  📄 Pages Visited : {meta['pages_visited']}")
        
        if discovery_map["idor_candidates"]:
            print(f"\n🚨 TOP IDOR CANDIDATES:")
            for ep in discovery_map["idor_candidates"][:5]:
                ids_str = ", ".join([f"{i['type']}:{i['value'][:8]}..." 
                                    for i in ep["ids"]])
                print(f"  [{ep['method']}] {ep['url'][:80]}")
                print(f"       IDs: {ids_str}")
        print(f"{'='*60}\n")


async def run_crawler(target: str, cookies: str, output_dir: str = "./reports",
                      extra_pages: Optional[list] = None):
    """Convenience async runner function."""
    crawler = AuthenticatedCrawler(
        target_url=target,
        cookies_str=cookies,
        output_dir=output_dir,
    )
    
    seed_pages = ["/", "/cart", "/account", "/myAccount", 
                  "/myAccount/addresses", "/myAccount/orders"] 
    if extra_pages:
        seed_pages.extend(extra_pages)
    
    return await crawler.crawl(pages_to_visit=seed_pages)


# Direct CLI usage: python auth_crawler.py
if __name__ == "__main__":
    import sys
    from dotenv import load_dotenv
    load_dotenv()
    
    TARGET = sys.argv[1] if len(sys.argv) > 1 else "https://www.iciparisxl.nl"
    COOKIES = os.getenv("AUTH_TOKEN_ATTACKER", "")
    
    if not COOKIES:
        print("❌ ERROR: AUTH_TOKEN_ATTACKER not found in .env")
        sys.exit(1)
    
    asyncio.run(run_crawler(TARGET, COOKIES))
