import asyncio
import urllib.parse
from rich.console import Console
from aura.core.stealth import AuraSession, StealthEngine
from aura.core import state

from aura.ui.formatter import console

class CorsHunter:
    """
    v21.0 Universal Bounty Maximizer: CORS Misconfiguration Engine.
    Hunts for high-payout Access-Control-Allow-Origin misconfigurations that return
    Credentials: true alongside reflected or null origins.
    """
    
    # Priority paths likely to contain authenticated user data (High impact for CORS)
    SENSITIVE_API_PATHS = [
        "/api/v1/user", "/api/v1/profile", "/api/v2/me", "/graphql", 
        "/user/config", "/account/settings", "/auth/session", "/api/users/me"
    ]
    
    def __init__(self, session=None):
        """Accepts an AuraSession object (from stealth engine) to make requests."""
        self.session = session
        
    async def scan_endpoint(self, url: str) -> list:
        """
        Actively probes an endpoint for CORS misconfigurations.
        Returns a list of finding dictionaries if vulnerable.
        """
        findings = []
        if not self.session:
            return findings
        
        # v22.5 normalize URL before probe
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        
        # Fast-fail if host is known dead
        from urllib.parse import urlparse as _up
        _h = _up(url).netloc
        if state.is_dns_failed(_h):
            return findings
        
        console.print(f"[cyan][⚙] CORS Hunter: Probing {url} for Access-Control misconfigurations...[/cyan]")
        
        parsed = urllib.parse.urlparse(url)
        base_domain = parsed.netloc
        
        # We test 3 common bypass techniques
        # 1. Arbitrary Origin reflection
        # 2. Null Origin trust
        # 3. Post-domain prefix bypass (e.g. target.com.evil.com)
        
        test_cases = [
            ("Arbitrary Origin Reflection", "https://evil-cors-hunter.com"),
            ("Null Origin Trust", "null"),
            ("Prefix Bypass", f"https://{base_domain}.evil.com")
        ]
        
        for case_name, spoofed_origin in test_cases:
            try:
                headers = {
                    "Origin": spoofed_origin,
                    "Access-Control-Request-Method": "GET"
                }
                
                res = await self.session.get(url, headers=headers, timeout=state.NETWORK_TIMEOUT, allow_redirects=False)
                if not res:
                    continue
                    
                allow_origin = res.headers.get("Access-Control-Allow-Origin", "")
                allow_creds = res.headers.get("Access-Control-Allow-Credentials", "").lower()
                
                # A critical CORS vulnerability exists if the server reflects the malicious origin
                # AND it explicitly allows credentials (cookies/auth headers) to be sent across origins.
                
                if allow_origin == spoofed_origin and allow_creds == "true":
                    content = (
                        f"CRITICAL CORS MISCONFIGURATION ({case_name}):\n"
                        f"Target allowed malicious Origin: '{spoofed_origin}'\n"
                        f"AND returned 'Access-Control-Allow-Credentials: true'.\n"
                        f"This allows cross-origin attackers to steal authenticated user data via XHR/Fetch."
                    )
                    
                    finding = {
                        "type": "CORS Misconfiguration (Auth Theft)",
                        "severity": "HIGH",
                        "cvss_score": 8.1,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                        "owasp": "A05:2021-Security Misconfiguration",
                        "mitre": "T1190 - Exploit Public-Facing Application",
                        "content": content,
                        "remediation_fix": "Never dynamically reflect the 'Origin' header into 'Access-Control-Allow-Origin'. Hardcode a strict whitelist of trusted domains. Never trust the 'null' origin.",
                        "impact_desc": "Session riding and complete authenticated data exfiltration. Attackers can read private API responses on behalf of the victim.",
                        "patch_priority": "HIGH"
                    }
                    console.print(f"[bold red][!!!] ZENITH HIT: Deterministic CORS Bypass ({case_name}) found on {url}![/bold red]")
                    findings.append(finding)
                    break # If one payload works, no need to test the others on the exact same endpoint
                    
            except Exception as e:
                pass
                
        return findings

    async def scan_domain(self, target_url: str, discovered_urls: list) -> list:
        """
        Phase 6 Bootstrapper: Scans the root target and a subset of discovered API endpoints.
        """
        all_findings = []
        
        # v22.5 Global DNS Circuit Breaker: skip dead targets immediately
        from urllib.parse import urlparse as _up
        # Normalize target_url to have scheme for urlparse to work
        _norm = target_url if target_url.startswith(("http://","https://")) else "https://" + target_url
        _host = _up(_norm).netloc
        if state.is_dns_failed(_host):
            return all_findings
        
        urls_to_test = [target_url]
        
        # Find likely API endpoints from the discovered links to test
        for u in discovered_urls:
            if any(x in u.lower() for x in ["/api", "/graphql", "/v1", "/v2", "/user"]):
                if u not in urls_to_test:
                    urls_to_test.append(u)
                    
        # Also explicitly add known sensitive endpoints to test
        base_clean = target_url.rstrip("/")
        for path in self.SENSITIVE_API_PATHS:
            test_url = f"{base_clean}{path}"
            if test_url not in urls_to_test:
                urls_to_test.append(test_url)
                
        # Limit to max 15 requests to preserve stealth
        urls_to_test = urls_to_test[:15]
        
        if urls_to_test:
            console.print(f"[cyan][*] Phase 6 Bounty Maximizer: Auditing {len(urls_to_test)} endpoints for CORS bypasses...[/cyan]")
            
        # Run tests concurrently
        tasks = [self.scan_endpoint(u) for u in urls_to_test]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for r in results:
            if isinstance(r, list) and r:
                all_findings.extend(r)
                
        return all_findings
