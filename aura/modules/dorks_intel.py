import asyncio
import httpx
import random
from bs4 import BeautifulSoup
from rich.console import Console

console = Console()

class DorksIntel:
    """
    v20.0 Bug Bounty Dorks Intelligence 🕵️‍♂️
    Scrapes Google/GitHub dork results to find leaked secrets, credentials,
    and exposed administrative panels specific to the target domain.
    """
    
    def __init__(self):
        # We scrape GitHub search without auth to avoid token bans, but with aggressive rotating UAs
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
        ]
        
        # High impact dorks from BugBountyDorks repo
        self.github_dorks = [
            '"{domain}" "jdbc:mysql"',
            '"{domain}" "Authorization: Bearer"',
            '"{domain}" filename:wp-config.php',
            '"{domain}" "AWS_ACCESS_KEY_ID"',
            '"{domain}" extension:pem private',
            '"{domain}" "mongodb+srv://"',
            '"{domain}" filename:.env DB_PASSWORD',
            '"{domain}" "api_key="',
            '"{domain}" "x-oxent-apikey"',
            '"{domain}" "Stripe API keys"',
        ]

    async def _search_github(self, domain: str, dork: str) -> list:
        """Scrapes GitHub search for a specific dork."""
        query = dork.replace("{domain}", domain)
        url = f"https://github.com/search?q={query}&type=code"
        headers = {"User-Agent": random.choice(self.user_agents)}
        
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
                res = await client.get(url, headers=headers)
                await asyncio.sleep(random.uniform(1.5, 3.5)) # Avoid instant rate limit
                
                if res.status_code == 200:
                    soup = BeautifulSoup(res.text, 'html.parser')
                    # Look for code snippet blocks
                    results = []
                    snippets = soup.find_all('div', class_='code-list')
                    for snippet in snippets:
                        text = snippet.get_text(strip=True)[:200]
                        if text:
                            results.append(text)
                    return results
        except Exception:
            pass
        return []

    async def run_dorks(self, target_domain: str):
        """
        Executes a targeted Dorks sweep against the domain.
        Returns a list of potential secret leaks.
        """
        console.print(f"\n[bold magenta][🕵️‍♂️] DORKS INTELLIGENCE: Searching GitHub for leaked secrets related to {target_domain}...[/bold magenta]")
        
        findings = []
        tasks = []
        
        # We only run the top 5 deadliest dorks to avoid IP ban during fast scans
        for dork in random.sample(self.github_dorks, min(5, len(self.github_dorks))):
            tasks.append(self._search_github(target_domain, dork))
            
        results = await asyncio.gather(*tasks)
        
        for i, res_list in enumerate(results):
            if res_list:
                console.print(f"[bold red][🔥] MASSIVE INTEL LEAK: Found code match for Dork: {self.github_dorks[i].replace('{domain}', target_domain)}[/bold red]")
                for snippet in res_list:
                    findings.append({
                        "type": "Code/Secret Leakage (OSINT)",
                        "severity": "HIGH",
                        "content": f"GitHub Search Leak via Dork '{self.github_dorks[i]}':\nSnippet: {snippet}",
                        "cvss_score": 8.5,
                        "owasp": "A01:2021-Broken Access Control",
                        "impact_desc": "Hardcoded or leaked secrets found on public GitHub repositories.",
                        "remediation_fix": "Immediately rotate leaked keys, remove files from public repos, and purge commit history."
                    })
        
        if not findings:
            console.print(f"[dim green][✔] No public GitHub leaks found for {target_domain}.[/dim green]")
            
        return findings
