"""
Aura v25.0 OMEGA Professional+: Frontend Deconstructor 🌐
==========================================================
Reconstructs original developer source code and performs deep AST audits.
Bridges the gap between Black-Box scanning and Senior-level source review.
"""

import re
import os
import asyncio
from rich.console import Console
from urllib.parse import urljoin, urlparse

console = Console()

class FrontendDeconstructor:
    """
    OMEGA Professional+: Source Reconstruction & Logic Mining.
    Unpacks sourcemaps to 'data/reconstructed_source/' and mines for vulnerabilities.
    """
    def __init__(self, target: str = None, session=None):
        self.target = target
        import httpx
        self.session = session or httpx.AsyncClient(verify=False)
        self.hidden_endpoints = set()
        self.secrets = []
        self.reconstructed_dir = os.path.join(os.getcwd(), "data", "reconstructed_source")
        if not os.path.exists(self.reconstructed_dir):
            os.makedirs(self.reconstructed_dir)

    async def run(self):
        """v25.0: The Full Deconstruction Cycle."""
        all_findings = []
        if not self.target: return all_findings
        
        console.print(f"[bold cyan][🛰️ DECONSTRUCTOR] Initializing Source Reconstruction for {self.target}...[/bold cyan]")
        
        # v38.0: Recursive Discovery Initiation
        self.visited_scripts = set()
        await self._recursive_js_hunt(self.target)
            
        res = self.get_results()
        for sec in res["secrets"]:
            all_findings.append({
                "type": f"Exposed Secret: {sec['type']}",
                "severity": "HIGH",
                "url": sec["origin"],
                "content": f"Source Mining: Found {sec['type']} in reconstructed code.",
                "evidence": sec
            })
            
        for ep in res["endpoints"]:
            all_findings.append({
                "type": "Hidden API Endpoint",
                "severity": "INFO", 
                "url": self.target,
                "content": f"Architectural Discovery: Extracted route `{ep}` from deconstructed source."
            })
            
        return all_findings

    async def deconstruct(self, js_url: str, content: str = ""):
        """Attempts to find and parse .js.map for a given JS file."""
        map_url = js_url + ".map"
        try:
            if not content:
                resp = await self.session.get(js_url)
                if not resp or resp.status_code != 200: return
                content = resp.text

            # Check for sourcemap
            try:
                m_resp = await self.session.get(map_url)
                if m_resp and m_resp.status_code == 200:
                    try:
                        map_data = m_resp.json()
                        console.print(f"[bold green][✓] Sourcemap Found: {m_resp.url}[/bold green]")
                        await self._parse_map(map_data, js_url)
                    except Exception as e:
                        console.print(f"[dim red][!] Sourcemap parsing failed for {map_url}: Non-JSON or Corrupt. Falling back to raw mining...[/dim red]")
                        await self._mine_raw_js(content, js_url)
                else:
                    await self._mine_raw_js(content, js_url)
            except:
                await self._mine_raw_js(content, js_url)
        except: pass

    async def _recursive_js_hunt(self, url: str, depth: int = 0):
        """v38.0: Recursive JS bundle hunter."""
        if depth > 2 or url in self.visited_scripts: return
        self.visited_scripts.add(url)
        
        try:
            resp = await self.session.get(url)
            if not resp or resp.status_code != 200: return
            
            c_type = resp.headers.get("content-type", "").lower()
            if "html" in c_type:
                import bs4
                soup = bs4.BeautifulSoup(resp.text, 'html.parser')
                for s in soup.find_all('script', src=True):
                    src = urljoin(url, s['src'])
                    await self._recursive_js_hunt(src, depth + 1)
            elif "javascript" in c_type or url.endswith(".js"):
                await self.deconstruct(url, content=resp.text)
                # Parse for more bundles
                nested = re.findall(r'["\']([\w/.-]+\.js)["\']', resp.text)
                for n in nested:
                    if "/" in n or ".bundle" in n:
                        n_url = urljoin(url, n)
                        await self._recursive_js_hunt(n_url, depth + 1)
        except: pass

    async def _mine_raw_js(self, js_code: str, js_url: str):
        """Mines raw JS for endpoints when sourcemaps are missing."""
        self._mine_text(js_code, js_url)
        await self.run_ast_analysis(js_code, js_url)

    async def _parse_map(self, map_data: dict, origin_url: str):
        sources = map_data.get("sources", [])
        content = map_data.get("sourcesContent", [])
        
        target_slug = urlparse(origin_url).netloc.replace(".", "_")
        domain_dir = os.path.join(self.reconstructed_dir, target_slug)
        
        for i, source_path in enumerate(sources):
            if i < len(content) and content[i]:
                # 1. Clean and normalize the path
                clean_path = source_path.replace("webpack:///", "").replace("../", "").lstrip("./")
                full_local_path = os.path.join(domain_dir, clean_path)
                
                # 2. Save original source code
                try:
                    os.makedirs(os.path.dirname(full_local_path), exist_ok=True)
                    with open(full_local_path, "w", encoding="utf-8") as f:
                        f.write(content[i])
                except: pass
                
                # 3. Deep Mining
                self._mine_text(content[i], source_path)
                await self.run_ast_analysis(content[i], source_path)


    async def run_ast_analysis(self, js_code: str, origin: str):
        """v25.0: White-Box Semantic AST Mining on deconstructed code."""
        try:
            from aura.modules.semantic_ast_engine import SemanticASTAnalyzer
            analyzer = SemanticASTAnalyzer(strict_mode=True)
            findings = await analyzer.analyze(js_code, source=origin)
            
            for f in findings:
                self.secrets.append({
                    "type": f"Logic Flaw ({f.vuln_type.value})",
                    "value": f.code_snippet,
                    "origin": f"{origin}:{f.line}"
                })
        except: pass

    def _mine_text(self, text: str, origin: str):
        """Uses professional-tier regex to find hidden API routes and high-value secrets."""
        # 1. Advanced Endpoint Mining
        endpoint_patterns = [
            r'["\'](/api/[\w/.-]+)["\']',
            r'["\'](/v\d/[\w/.-]+)["\']',
            r'["\'](/internal/[\w/.-]+)["\']',
            r'["\'](/admin/[\w/.-]+)["\']',
            r'["\'](/rest/[\w/.-]+)["\']', # Common in SPAs
            r'["\'](/graphql)["\']',
            # v38.0: SPA Routing Patterns (Angular/React)
            r'path\s*:\s*["\']([\w/.-]+)["\']',
            r'redirectTo\s*:\s*["\']([\w/.-]+)["\']'
        ]
        for pattern in endpoint_patterns:
            matches = re.findall(pattern, text)
            for ep in matches:
                # Normalize path to bypass basic WAF blocking (e.g., removing ../ or parsing %2e)
                import urllib.parse
                ep = ep.replace("%2e", ".").replace("%2E", ".")
                clean_ep = urllib.parse.urljoin(origin, ep)
                self.hidden_endpoints.add(clean_ep)
            
        # 2. Professional Secret Mining (Zero-Noise)
        secret_patterns = {
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "Firebase URL": r"https://.*\.firebaseio\.com",
            "Slack Webhook": r"https://hooks\.slack\.com/services/T\w+/B\w+/\w+",
            "Google API Key": r"AIza[0-9A-Za-z\-_]+",
            "Github Token": r"ghp_[a-zA-Z0-9]{36}"
        }
        for name, pattern in secret_patterns.items():
            matches = re.findall(pattern, text)
            for m in matches:
                if m not in [s["value"] for s in self.secrets]:
                    self.secrets.append({"type": name, "value": m, "origin": origin})

    def get_results(self):
        return {
            "endpoints": list(self.hidden_endpoints),
            "secrets": self.secrets
        }
