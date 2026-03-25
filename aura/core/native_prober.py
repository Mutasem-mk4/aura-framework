import asyncio
import random
import time
import json
import logging
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
import httpx
from rich.console import Console
from aura.core.brain import AuraBrain
from aura.core.stealth import MorphicHeaderEngine
from aura.core.nexus_bridge import NexusBridge

from aura.ui.formatter import console
logger = logging.getLogger("aura")

class NativeProber:
    """
    v50.0 OMEGA: Custom High-Performance HTTP Probing Engine.
    Handles thousands of URLs with morphic headers and AI-driven behavior.
    """

    def __init__(self, concurrency: int = 100, timeout: int = 10):
        self.concurrency = concurrency
        self.timeout = timeout
        self.stealth = MorphicHeaderEngine()
        self.brain: Optional[AuraBrain] = None
        try:
            self.nexus = NexusBridge()
        except Exception:
            self.nexus = None

        # Load Brain if available
        try:
            self.brain = AuraBrain()
        except Exception:
            self.brain = None

        self.limits = httpx.Limits(max_keepalive_connections=20, max_connections=self.concurrency)
        self.client = httpx.AsyncClient(
            verify=False,
            timeout=self.timeout,
            limits=self.limits,
            follow_redirects=True
        )

    async def probe(self, url: str, stealth: bool = True, context: dict = None) -> Dict[str, Any]:
        """v51.0: AI-Heuristic Probing."""
        if not url.startswith("http"):
            url = "https://" + url
            
        headers = MorphicHeaderEngine.generate(url) if stealth else {"User-Agent": "Aura/50.0"}
        
        if self.brain and self.brain.enabled:
            ai_advice = await asyncio.to_thread(self.brain.suggest_waf_evasion, "Generic/Pre-flight")
            if ai_advice and "header" in ai_advice.lower():
                headers["X-Aura-Strategy"] = "AI-Heuristic"

        start_time = time.monotonic()
        try:
            resp = await self.client.get(url, headers=headers)
            elapsed = time.monotonic() - start_time
            
            result = {
                "url": str(resp.url),
                "status_code": resp.status_code,
                "reason": resp.reason_phrase,
                "elapsed": elapsed,
                "headers": dict(resp.headers),
                "tech": self._detect_tech(resp),
                "title": self._extract_title(resp.text),
                "server": resp.headers.get("Server", "Unknown"),
                "content_length": len(resp.content),
                "waf": self._check_waf(resp)
            }

            if self.brain and self.brain.enabled:
                if result["status_code"] in [403, 401, 429] or result["waf"]:
                    advice = await asyncio.to_thread(self.brain.reason, result)
                    result["ai_advice"] = advice
            
            return result
        except Exception as e:
            return {"url": url, "error": str(e), "status_code": 0}

    async def batch_probe(self, urls: List[str], stealth: bool = True) -> List[Dict[str, Any]]:
        """Optimized batch probing with Go (Nexus) acceleration."""
        if self.nexus and len(urls) > 5:
            console.print(f"[yellow][⚡] Nexus Core Active: Batch probing {len(urls)} targets at Go-native speeds...[/yellow]")
            try:
                go_results = self.nexus.probe_urls(urls, self.concurrency, self.timeout * 1000)
                if go_results is None:
                    raise Exception("Nexus results are None")
                results = []
                for r in go_results:
                    results.append({
                        "url": r["url"],
                        "status_code": r["status"],
                        "server": r["server"],
                        "title": r.get("title", "Unknown"),
                        "tech": [], # Tech detection not supported in Go core yet
                        "waf": None,
                        "ai_advice": None
                    })
                return results
            except Exception as e:
                console.print(f"[red][!] Nexus acceleration failed: {e}. Falling back to native async.[/red]")

        from rich.progress import Progress, SpinnerColumn, TextColumn
        results = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task(f"[cyan]Native Probing {len(urls)} targets...", total=len(urls))
            sem = asyncio.Semaphore(self.concurrency)
            
            async def limited_probe(u):
                async with sem:
                    res = await self.probe(u, stealth)
                    progress.advance(task)
                    return res
            
            gathered_results = await asyncio.gather(*[limited_probe(u) for u in urls])
            results = list(gathered_results)
        return results

    def _detect_tech(self, resp: httpx.Response) -> List[str]:
        tech = []
        body = resp.text.lower()
        headers = str(resp.headers).lower()
        indicators = {
            "WordPress": ["wp-content", "wp-includes"],
            "Laravel": ["laravel_session", "php"],
            "Django": ["csrftoken", "django"],
            "React": ["_next", "react-root"],
            "Vue": ["v-if", "vue"],
            "Cloudflare": ["__cfduid", "cf-ray", "cloudflare"],
            "nginx": ["nginx"],
            "IIS": ["microsoft-iis"],
        }
        for name, hints in indicators.items():
            if any(hint in body or hint in headers for hint in hints):
                tech.append(name)
        return tech

    def _extract_title(self, body: str) -> str:
        import re
        m = re.search(r'<title>(.*?)</title>', body, re.I | re.S)
        return m.group(1).strip() if m else "No Title"

    def _check_waf(self, resp: httpx.Response) -> Optional[str]:
        waf_headers = {
            "cf-ray": "Cloudflare",
            "x-akamai-transformed": "Akamai",
            "x-firewall-id": "Citrix",
        }
        for head, name in waf_headers.items():
            if head in resp.headers:
                return name
        return None

    async def close(self):
        await self.client.aclose()

if __name__ == "__main__":
    import sys
    from rich.panel import Panel
    async def main():
        if len(sys.argv) < 2:
            console.print("[red]Usage: python -m aura.core.native_prober <url1> ...[/red]")
            return
        urls = sys.argv[1:]
        prober = NativeProber()
        results = await prober.batch_probe(urls)
        console.print(Panel(json.dumps(results, indent=2), title="Batch Probe Complete"))
        await prober.close()
    asyncio.run(main())
