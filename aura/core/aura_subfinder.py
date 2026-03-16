import asyncio
import aiohttp
import json
import logging
import socket
import re
from typing import List, Set, Dict, Any
from urllib.parse import urlparse
from rich.console import Console

import dns.resolver
import dns.asyncresolver

console = Console()
logger = logging.getLogger("aura")

class NativeSubfinder:
    """
    v50.0 OMEGA: Native Subdomain Discovery Engine.
    Replaces Subfinder CLI with asynchronous OSINT aggregation and high-speed resolution.
    """
    
    SUBDOMAIN_HINTS = [
        "www", "dev", "staging", "api", "prod", "test", "admin", "mail", "app", "portal",
        "vpn", "remote", "secure", "auth", "login", "m", "mobile", "cdn", "beta", "old",
        "v2", "v3", "static", "assets", "img", "blog", "news", "forum", "help", "support",
        "docs", "git", "gitlab", "jenkins", "jira", "confluence", "status", "monitor",
        "internal", "corp", "office", "hr", "payroll", "intranet", "extranet", "partner",
        "vendor", "client", "customer", "db", "database", "sql", "redis", "cache", "lb",
        "proxy", "nginx", "k8s", "docker", "registry", "ci", "cd", "build", "release",
        "download", "upload", "search", "video", "photos", "storage", "bucket", "s3",
        "cloud", "aws", "azure", "gcp", "web", "app1", "app2", "idp", "sso", "identity"
    ]

    def __init__(self, concurrency: int = 100):
        self.concurrency = concurrency
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.nameservers = ['8.8.8.8', '1.1.1.1', '8.8.4.4']
        self.resolver.timeout = 2
        self.resolver.lifetime = 2

    async def discover(self, domain: str) -> List[str]:
        """Orchestrates passive discovery and validation."""
        console.print(f"[cyan][🌐 Subfinder] Starting native discovery for {domain}...[/cyan]")
        
        # 1. Passive Aggregation
        subdomains = await self.aggregate_osint(domain)
        
        # 2. Add local hints
        for hint in self.SUBDOMAIN_HINTS:
            subdomains.add(f"{hint}.{domain}")
            
        # Ensure base domain is in candidates
        subdomains.add(domain)
        subdomains.add(f"www.{domain}")
            
        console.print(f"[yellow][↻] OSINT Aggregated: {len(subdomains)} candidates. Resolving...[/yellow]")
        
        # 3. Active Resolution & Validation
        live_subdomains = await self.resolve_batch(list(subdomains))
        
        console.print(f"[bold green][+] Discovery Complete: {len(live_subdomains)} LIVE subdomains found.[/bold green]")
        return live_subdomains

    async def aggregate_osint(self, domain: str) -> Set[str]:
        """Fetches subdomains from multiple passive sources."""
        subdomains = set()
        
        sources = [
            self._fetch_crtsh(domain),
            self._fetch_otx(domain),
            self._fetch_hackertarget(domain),
            self._fetch_anubis(domain)
        ]
        
        results = await asyncio.gather(*sources)
        for res in results:
            subdomains.update(res)
            
        return {s.lower() for s in subdomains if s.endswith(domain)}

    async def _fetch_crtsh(self, domain: str) -> Set[str]:
        subdomains = set()
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=20) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for item in data:
                            name = item.get('name_value', '')
                            for sub in name.split('\n'):
                                sub = sub.strip().lstrip('*.')
                                subdomains.add(sub)
        except Exception: pass
        return subdomains

    async def _fetch_otx(self, domain: str) -> Set[str]:
        subdomains = set()
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=15) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for active in data.get('passive_dns', []):
                            sub = active.get('hostname', '')
                            subdomains.add(sub)
        except Exception: pass
        return subdomains

    async def _fetch_anubis(self, domain: str) -> Set[str]:
        subdomains = set()
        url = f"https://jldc.me/anubis/subdomains/{domain}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=15) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for sub in data:
                            subdomains.add(sub)
        except Exception: pass
        return subdomains

    async def _fetch_hackertarget(self, domain: str) -> Set[str]:
        subdomains = set()
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=15) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        for line in text.splitlines():
                            if ',' in line:
                                sub = line.split(',')[0]
                                subdomains.add(sub)
        except Exception: pass
        return subdomains

    async def resolve_batch(self, subdomains: List[str]) -> List[str]:
        """Batch resolves subdomains with concurrency limits."""
        sem = asyncio.Semaphore(self.concurrency)
        found = []

        async def resolve(sub):
            async with sem:
                try:
                    # Check A record
                    answers = await self.resolver.resolve(sub, 'A')
                    if answers:
                        found.append(sub)
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, Exception):
                    pass

        await asyncio.gather(*[resolve(sub) for sub in subdomains])
        return sorted(list(set(found)))

if __name__ == "__main__":
    import sys
    async def main():
        domain = sys.argv[1] if len(sys.argv) > 1 else "google.com"
        finder = NativeSubfinder()
        results = await finder.discover(domain)
        print(json.dumps(results, indent=2))
    
    asyncio.run(main())
