import asyncio
import re
import urllib.parse
from rich.console import Console

console = Console()

class AILogicEngine:
    """
    Aura v15: Autonomous Business Logic & IDOR Hunter.
    Analyzes parameters and injects logical anomalies (negative values, arrays, ID increments).
    """
    def __init__(self, session):
        self.session = session
        self.vulnerabilities = []
        
        # Heuristics for parameters that are likely to be vulnerable to IDOR or Logic flaws
        self.idor_params = ["id", "user_id", "account_id", "doc_id", "profile_id", "uuid", "order_id"]
        self.logic_params = ["amount", "price", "qty", "quantity", "discount", "fee", "balance", "total"]

    def _parse_url_params(self, url: str) -> dict:
        """Extracts parameters from a URL."""
        parsed = urllib.parse.urlparse(url)
        return urllib.parse.parse_qs(parsed.query)

    def _build_url(self, base_url: str, params: dict) -> str:
        """Reconstructs a URL with modified parameters."""
        parsed = urllib.parse.urlparse(base_url)
        # Flatten parse_qs output back to a normal query string
        flat_params = []
        for k, v in params.items():
            if isinstance(v, list):
                for item in v:
                    flat_params.append(f"{k}={item}")
            else:
                flat_params.append(f"{k}={v}")
                
        new_query = "&".join(flat_params)
        return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

    async def hunt_idor(self, base_url: str, params: dict, original_response_len: int):
        """Attempts to increment/decrement numeric IDs to access unauthorized data."""
        for param, values in params.items():
            if any(key in param.lower() for key in self.idor_params):
                for val in values:
                    if val.isdigit():
                        original_id = int(val)
                        # Test ID + 1 and ID - 1
                        for test_id in [original_id + 1, original_id - 1]:
                            if test_id <= 0: continue
                            
                            test_params = params.copy()
                            test_params[param] = [str(test_id)]
                            target_url = self._build_url(base_url, test_params)
                            
                            console.print(f"[cyan][🧠 Logic] Testing IDOR on {param}: {original_id} -> {test_id}[/cyan]")
                            try:
                                resp = await self.session.request("GET", target_url, timeout=10)
                                if resp and resp.status_code in [200, 201]:
                                    # If the response length is significantly different, we might have hit a valid, different record
                                    if abs(len(resp.text) - original_response_len) > 50:
                                         console.print(f"[bold red][VULNERABILITY] Potential IDOR detected at {target_url}[/bold red]")
                                         self.vulnerabilities.append({
                                             "type": "Broken Access Control (IDOR)",
                                             "url": target_url,
                                             "severity": "High",
                                             "method": "Auto-Incremented ID"
                                         })
                            except: pass

    async def hunt_business_logic(self, base_url: str, params: dict):
        """Injects negative values, zeros, and massive numbers into financial parameters."""
        for param, values in params.items():
            if any(key in param.lower() for key in self.logic_params):
                logic_payloads = ["-1", "-100", "0", "0.00", "999999999", "NaN", "[]"]
                
                for payload in logic_payloads:
                    test_params = params.copy()
                    
                    if payload == "[]":
                        # Parameter Pollution / Array Injection: amount[]=1
                        test_params[f"{param}[]"] = values
                        del test_params[param]
                        target_url = self._build_url(base_url, test_params)
                    else:
                        test_params[param] = [payload]
                        target_url = self._build_url(base_url, test_params)
                        
                    console.print(f"[cyan][🧠 Logic] Testing Business Logic on {param} with payload: {payload}[/cyan]")
                    try:
                         resp = await self.session.request("GET", target_url, timeout=10)
                         # If the server accepts a negative price or array without a 400/500 error, it's highly suspicious
                         if resp and resp.status_code == 200:
                             console.print(f"[bold red][VULNERABILITY] Potential Business Logic Flaw at {target_url}[/bold red]")
                             self.vulnerabilities.append({
                                 "type": "Business Logic Error / Parameter Pollution",
                                 "url": target_url,
                                 "severity": "High",
                                 "method": f"Injected '{payload}' into '{param}'"
                             })
                    except: pass

    async def analyze(self, urls: list[str]):
        """Main entry point for the Logic Engine."""
        console.print("\n[bold magenta][🧠 AI LOGIC] Activating Autonomous Business Logic & IDOR Hunter...[/bold magenta]")
        
        # Filter URLs that actually have parameters
        parameterized_urls = [url for url in urls if "?" in url]
        
        if not parameterized_urls:
            console.print("[yellow][🧠 Logic] No parameterized URLs found to analyze.[/yellow]")
            return self.vulnerabilities
            
        for url in parameterized_urls:
            params = self._parse_url_params(url)
            if not params: continue
            
            # Get baseline response
            try:
                resp = await self.session.request("GET", url, timeout=10)
                if not resp or resp.status_code >= 400: continue
                baseline_len = len(resp.text)
            except: continue
            
            # Run heuristic hunts concurrently for speed
            await asyncio.gather(
                self.hunt_idor(url, params, baseline_len),
                self.hunt_business_logic(url, params)
            )
            
        console.print(f"[bold green][✔ LOGIC] Analysis complete. Found {len(self.vulnerabilities)} logical vulnerabilities.[/bold green]")
        return self.vulnerabilities

