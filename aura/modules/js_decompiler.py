import re
import asyncio
from typing import List, Dict, Set
from urllib.parse import urlparse, urljoin
from rich.console import Console

console = Console()

class JSDecompiler:
    """
    v33.0: JS Decompiler & Webpack Unpacker
    Hunts through minified JavaScript chunks (React/Angular/Vue build files)
    to surgically extract hidden backend endpoints, API routes, and hardcoded keys.
    """
    def __init__(self, session):
        self.session = session
        # Regex to find endpoint-like strings in JS
        self.endpoint_pattern = re.compile(
            r'["\'](?:/v[1-9]/api/|/api/|/rest/|/graphql|/internal/|/admin/|/users/|/auth/)(?:[a-zA-Z0-9_\-\./]+)["\']'
        )
        self.url_pattern = re.compile(
            r'["\'](?:https?://)(?:[a-zA-Z0-9_\-\.]+)(?::\d+)?(?:/[a-zA-Z0-9_\-\.\?/=&]+)["\']'
        )
        # Regex for common API Keys/Secrets (AWS, Stripe, Google, etc.)
        self.secret_pattern = re.compile(
            r'(?i)(?:api_key|apikey|secret|token|password|bearer)[^a-zA-Z0-9]{1,3}(["\'][a-zA-Z0-9_\-\.=]{15,40}["\'])'
        )
        
    async def extract_from_js(self, target_url: str, js_urls: List[str]) -> Dict[str, set]:
        """
        Downloads supplied JS files and decompiles them to find hidden paths and secrets.
        """
        results = {
            "endpoints": set(),
            "secrets": set()
        }
        
        if not js_urls:
            return results
            
        console.print(f"[bold cyan][*] v33.0 JS Decompiler: Unpacking {len(js_urls)} minified Webpack chunks...[/bold cyan]")
        
        tasks = []
        # Concurrently fetch and parse JS
        for url in js_urls:
             # Make sure URL is absolute
             if not url.startswith("http"):
                 url = urljoin(target_url, url)
             tasks.append(self._decompile_chunk(url))
             
        parsed_chunks = await asyncio.gather(*tasks)
        
        for endpoints, secrets in parsed_chunks:
            results["endpoints"].update(endpoints)
            results["secrets"].update(secrets)
            
        if results["endpoints"]:
            console.print(f"[bold green][+] JS Decompiler: Extracted {len(results['endpoints'])} hidden endpoints from source maps![/bold green]")
        if results["secrets"]:
            console.print(f"[bold red][💥] JS Decompiler: Extracted {len(results['secrets'])} hardcoded secrets/tokens![/bold red]")
            
        return results

    async def _decompile_chunk(self, js_url: str) -> tuple:
        """Fetches a single JS file and applies heuristic extraction."""
        endpoints = set()
        secrets = set()
        try:
            resp = await self.session.get(js_url, timeout=10)
            if not resp or resp.status_code != 200:
                return endpoints, secrets
                
            content = resp.text
            
            # Find relative API paths
            for match in self.endpoint_pattern.finditer(content):
                val = match.group(0).strip('"\'')
                endpoints.add(val)
                
            # Find absolute URLs
            for match in self.url_pattern.finditer(content):
                val = match.group(0).strip('"\'')
                if val.endswith(('.js', '.css', '.png', '.jpg', '.svg', '.woff', '.woff2')):
                    continue
                endpoints.add(val)
                
            # Find Secrets
            for match in self.secret_pattern.finditer(content):
                val = match.group(0)
                # Filter out obvious false positives like "token":"null"
                if "null" in val.lower() or "undefined" in val.lower():
                    continue
                secrets.add((js_url, val))

        except Exception as e:
            pass
            
        return endpoints, secrets
