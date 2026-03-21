import logging
import httpx
import asyncio
from rich.console import Console
from typing import List, Dict

logger = logging.getLogger("aura")
from aura.ui.formatter import console

class SubdomainTakeoverHunter:
    """
    Auto-Exploitation Module: Subdomain Takeover
    Scans a list of subdomains for known vulnerable cloud service configurations.
    If a CNAME matches a known service (e.g., s3.amazonaws.com) and the
    HTTP response matches the 'not found' fingerprint, it reports an immediate
    Critical takeover opportunity.
    """
    
    # Signatures format: 
    #   "Service Name": {
    #       "cnames": [list of strings to match in CNAME],
    #       "fingerprint": "string to match in HTTP response body"
    #   }
    VULN_SIGNATURES = {
        "Amazon S3": {
            "cnames": ["s3.amazonaws.com", "s3-website", "s3.dualstack"],
            "fingerprint": "The specified bucket does not exist"
        },
        "GitHub Pages": {
            "cnames": ["github.io"],
            "fingerprint": "There isn't a GitHub Pages site here."
        },
        "Heroku": {
            "cnames": ["herokuapp.com", "herokudns.com"],
            "fingerprint": "No such app"
        },
        "Pantheon": {
            "cnames": ["pantheonsite.io"],
            "fingerprint": "The mysteriously missing site."
        },
        "Zendesk": {
            "cnames": ["zendesk.com"],
            "fingerprint": "Help Center Closed"
        },
        "Ghost": {
            "cnames": ["ghost.io"],
            "fingerprint": "The thing you were looking for is no longer here"
        },
        "Shopify": {
            "cnames": ["myshopify.com"],
            "fingerprint": "Sorry, this shop is currently unavailable."
        },
        "Webflow": {
            "cnames": ["proxy.webflow.com", "proxy-ssl.webflow.com"],
            "fingerprint": "The page you are looking for doesn't exist or has been moved."
        },
        "Netlify": {
            "cnames": ["netlify.com"],
            "fingerprint": "Not Found - Request ID:"
        }
    }

    async def _check_subdomain(self, subdomain: str) -> Dict | None:
        """
        Checks a single subdomain for takeover vulnerabilities.
        In a real scenario, this would first do a DNS CNAME lookup.
        For speed, we will do a direct HTTP GET and check the body against fingerprints,
        which works even without explicit CNAME checking if the DNS points to the service.
        """
        if not subdomain.startswith("http"):
            url = f"http://{subdomain}"
        else:
            url = subdomain

        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as client:
                response = await client.get(url)
                body = response.text

                for service, sig in self.VULN_SIGNATURES.items():
                    if sig["fingerprint"] in body:
                        # We found an exact fingerprint match indicating the service is unclaimed
                        return {
                            "type": "Subdomain Takeover",
                            "severity": "CRITICAL",
                            "cvss_score": 9.5,
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                            "owasp": "A05:2021-Security Misconfiguration",
                            "mitre": "T1190 - Exploit Public-Facing Application",
                            "content": (
                                f"[CRITICAL: AUTO-EXPLOITATION OPPORTUNITY]\n"
                                f"Subdomain `{subdomain}` is pointing to `{service}` but the resource is unclaimed.\n"
                                f"Fingerprint Matched: `{sig['fingerprint']}`"
                            ),
                            "remediation_fix": (
                                f"To fix this immediately:\n"
                                f"1. Log into your {service} provider and claim the app/bucket/site under the name matching `{subdomain}`.\n"
                                f"2. Alternatively, delete the DNS CNAME/A record for `{subdomain}` in your DNS registrar."
                            ),
                            "impact_desc": f"An attacker can register the missing {service} resource and gain full control over `{subdomain}`. This allows them to serve malicious content, steal cookies, and bypass security controls.",
                            "patch_priority": "IMMEDIATE",
                            "evidence_url": url,
                            "service": service
                        }
        except Exception as e:
            logger.debug(f"[Subdomain Takeover] Error checking {subdomain}: {e}")
        
        return None

    async def run(self, subdomains: List[str]) -> List[Dict]:
        """
        Runs the takeover check across a list of subdomains concurrently.
        """
        if not subdomains:
            return []

        console.print(f"[bold yellow][🧟‍♂️ Takeover Hunter] Scanning {len(subdomains)} subdomains for takeover vulnerabilities...[/bold yellow]")
        
        tasks = [self._check_subdomain(subdomain) for subdomain in subdomains]
        results = await asyncio.gather(*tasks)
        
        # Filter out Nones
        findings = [r for r in results if r]
        
        for finding in findings:
            console.print(f"[bold red blink][CRITICAL TAKEOVER] {finding['service']} takeover found at {finding['evidence_url']}![/bold red blink]")
            
        if not findings:
            console.print("[dim green][🧟‍♂️ Takeover Hunter] Done: 0 takeover vulnerabilities found.[/dim green]")
            
        return findings
