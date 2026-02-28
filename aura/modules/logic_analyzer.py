import asyncio
import urllib.parse
from rich.console import Console

console = Console()

class LogicAnalyzer:
    """
    Phase 21: Extends Aura to test for Business Logic and Access Control flaws.
    Focuses on Insecure Direct Object Reference (IDOR), Parameter Pollution, and Privilege Escalation.
    """
    
    def __init__(self, brain_instance=None):
        self.brain = brain_instance
        self.findings = []
        
    async def analyze_target(self, url, page):
        """Analyze a page for potential business logic or IDOR vulnerabilities."""
        console.print(f"[cyan][⚙] LogicAnalyzer v2: Inspecting {url} for Semantic Business Logic flaws...[/cyan]")
        self.findings = []
        
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        # Phase 27: Extraction of all IDs from the DOM (Cross-Object Mapping)
        discovered_ids = await page.evaluate("""
            () => {
                const ids = [];
                const body = document.body.innerText;
                const matches = body.match(/(user|id|account|order|file|doc)_([a-zA-Z0-9_-]+)/gi);
                return matches ? matches : [];
            }
        """)
        if discovered_ids:
            console.print(f"[dim][🧪] LogicAnalyzer: Discovered {len(discovered_ids)} potential object IDs in DOM.[/dim]")

        if query_params:
            await self._test_idor_v2(url, page, parsed_url, query_params, discovered_ids)
            await self._test_parameter_pollution(url, page, parsed_url, query_params)
            await self._test_mass_assignment(url, page, query_params)
            
        return self.findings

    async def _test_idor_v2(self, original_url, page, parsed_url, query_params, discovered_ids):
        """Ghost v6: Advanced IDOR matching using semantic analysis and discovered tokens."""
        for param, values in query_params.items():
            val = values[0]
            # Use Brain to see if this parameter is a sensitive object reference
            is_sensitive = self.brain.analyze_parameter_semantics({param: val})
            
            if is_sensitive or any(x in param.lower() for x in ['id', 'uid', 'user', 'acc']):
                # Strategy A: Increment/Decrement (Numeric)
                if val.isdigit():
                    for delta in [-1, 1]:
                        test_val = str(max(0, int(val) + delta))
                        await self._probe_idor_link(param, val, test_val, parsed_url, page)
                
                # Strategy B: Cross-Token Substitution (if we found other IDs in the page)
                for discovered_id in discovered_ids:
                    if discovered_id != val:
                        await self._probe_idor_link(param, val, discovered_id, parsed_url, page)

    async def _probe_idor_link(self, param, original_val, test_val, parsed_url, page):
        test_query = parsed_url.query.replace(f"{param}={original_val}", f"{param}={test_val}")
        test_url = parsed_url._replace(query=test_query).geturl()
        try:
            await page.goto(test_url, wait_until="networkidle", timeout=5000)
            content = await page.content()
            # If 200 OK and content is 'Meaningfully Different' but not an error
            if "unauthorized" not in content.lower() and original_val not in content:
                self.findings.append({
                    "type": "Logic: IDOR Escalation",
                    "severity": "HIGH",
                    "content": f"LOGIC HIT: Successfully accessed {test_url} which appears to be a different object record."
                })
        except: pass

    async def _test_mass_assignment(self, url, page, query_params):
        """Tests for Mass Assignment by injecting administrative parameters."""
        admin_params = ["role=admin", "is_admin=true", "admin=1", "privilege=root"]
        for p in admin_params:
            test_url = f"{url}&{p}" if "?" in url else f"{url}?{p}"
            try:
                res = await page.goto(test_url, wait_until="networkidle", timeout=5000)
                # If we see 'admin' or 'dashboard' or 'settings' in page now, it might have worked
                content = await page.content()
                if any(kw in content.lower() for kw in ["admin dashboard", "root access", "superuser"]):
                     self.findings.append({
                        "type": "Logic: Mass Assignment",
                        "severity": "CRITICAL",
                        "content": f"LOGIC HIT: Parameter injection '{p}' resulted in escalated UI elements on {url}."
                    })
            except: pass

    async def _test_parameter_pollution(self, original_url, page, parsed_url, query_params):
        """Tests HTTP Parameter Pollution (HPP) by duplicating parameters."""
        for param, values in query_params.items():
             test_query = parsed_url.query + f"&{param}=aura_hpp_test"
             test_url = parsed_url._replace(query=test_query).geturl()
             
             console.print(f"[dim][🧪] LogicAnalyzer: Testing HTTP Parameter Pollution (HPP) on '{param}'[/dim]")
             
             try:
                 await page.goto(test_url, wait_until="networkidle")
                 content = await page.content()
                 
                 # If the injected value is reflected or causes an error, it might be vulnerable to HPP
                 if "aura_hpp_test" in content or "duplicate parameter" in content.lower():
                      self.findings.append({
                          "type": "HTTP Parameter Pollution (HPP)",
                          "confidence": "Medium",
                          "content": f"LOGIC FLAW: Parameter '{param}' appears vulnerable to HTTP Parameter Pollution on {test_url}."
                      })
                      console.print(f"[yellow][?] Logic Monitor: HPP anomaly detected on {param}.[/yellow]")
             except Exception as e:
                 console.print(f"[dim red][!] HPP Check Error: {e}[/dim red]")
