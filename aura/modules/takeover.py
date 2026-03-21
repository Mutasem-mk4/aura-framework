import requests
from rich.console import Console
from aura.core.stealth import StealthEngine, AuraSession
from aura.core import state

from aura.ui.formatter import console
stealth = StealthEngine()
session = AuraSession(stealth)

class TakeoverFinder:
    """Engine for detecting Subdomain Takeover vulnerabilities."""
    
    # Signatures for common services (dangling DNS) - v15.0 Global Bounty Maximizer
    TAKEOVER_SIGS = {
        "GitHub Pages": {"fingerprint": "There isn't a GitHub Pages site here", "service": "GitHub"},
        "Heroku": {"fingerprint": "no such app", "service": "Heroku"},
        "Amazon S3": {"fingerprint": "NoSuchBucket", "service": "AWS S3"},
        "Amazon S3 (Global)": {"fingerprint": "The specified bucket does not exist", "service": "AWS S3"},
        "Shopify": {"fingerprint": "Sorry, this shop is currently unavailable", "service": "Shopify"},
        "Tumblr": {"fingerprint": "Whatever you were looking for doesn't currently exist at this address", "service": "Tumblr"},
        "Ghost.io": {"fingerprint": "The thing you were looking for is no longer here", "service": "Ghost.io"},
        "WP Engine": {"fingerprint": "The site you were looking for couldn't be found", "service": "WP Engine"},
        "Pantheon": {"fingerprint": "The plain text response from Pantheon", "service": "Pantheon"},
        "Pantheon (404)": {"fingerprint": "404 error unknown site!", "service": "Pantheon"},
        "Bitbucket": {"fingerprint": "Repository not found", "service": "Bitbucket"},
        "Zendesk": {"fingerprint": "Help Center Closed", "service": "Zendesk"},
        "Smartling": {"fingerprint": "Domain is not configured", "service": "Smartling"},
        "Acquia": {"fingerprint": "If you are an Acquia Cloud customer and expect to see your site at this address", "service": "Acquia"},
        "Fastly": {"fingerprint": "Fastly error: unknown domain", "service": "Fastly"},
        "Agile CRM": {"fingerprint": "Sorry, this page is no longer available.", "service": "Agile CRM"},
        "Campaign Monitor": {"fingerprint": "Trying to access your account?", "service": "Campaign Monitor"},
        "Cargo Collective": {"fingerprint": "If you're moving your domain away from Cargo you must make this configuration through your registrar", "service": "Cargo"},
        "Fly.io": {"fingerprint": "404 Not Found", "service": "Fly.io"},
        "Hatena Blog": {"fingerprint": "404 Blog is not found", "service": "Hatena"},
        "Kinsta": {"fingerprint": "No Site For Domain", "service": "Kinsta"},
        "Launchaco": {"fingerprint": "It looks like you may have taken a wrong turn somewhere", "service": "Launchaco"},
        "Readme.io": {"fingerprint": "Project doesnt exist... yet!", "service": "Readme.io"},
        "Strikingly": {"fingerprint": "But if you're looking to build your own website,", "service": "Strikingly"},
        "Surge.sh": {"fingerprint": "project not found", "service": "Surge"},
        "Webflow": {"fingerprint": "The page you are looking for doesn't exist or has been moved", "service": "Webflow"},
        "Worksites": {"fingerprint": "Hello! Sorry, but the website you&rsquo;re looking for doesn&rsquo;t exist.", "service": "Worksites"},
        "Azure": {"fingerprint": "404 Web Site not found", "service": "Azure Cloud"}
    }

    @staticmethod
    async def _resolve_cname(domain: str) -> str | None:
        """
        Phase 2: Resolves the CNAME record of a domain to find dangling DNS.
        Returns the CNAME target string or None.
        """
        import asyncio
        import socket
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, socket.getaddrinfo, domain, None)
            return result[0][4][0] if result else None
        except Exception:
            return None  # DNS NXDOMAIN = fully dangling

    async def check_takeover(self, domain):
        """
        Phase 2: Checks a subdomain for potential takeover fingerprints.
        If fingerprint is found AND DNS confirms the CNAME is dangling (NXDOMAIN),
        the finding is elevated to EXCEPTIONAL severity.
        """
        if not domain.startswith("http"):
            url = f"http://{domain}"
        else:
            url = domain

        console.print(f"[bold yellow][*] TakeoverFinder: Checking {domain} for DNS takeover...[/bold yellow]")

        try:
            response = await session.get(url, timeout=state.NETWORK_TIMEOUT)
            content = response.text

            for service, data in self.TAKEOVER_SIGS.items():
                if data["fingerprint"] in content:
                    # Phase 2: Attempt live DNS confirmation
                    dns_result = await self._resolve_cname(domain)
                    dns_confirmed = (dns_result is None)  # NXDOMAIN = fully dangling

                    if dns_confirmed:
                        severity = "EXCEPTIONAL"
                        cvss = 9.3
                        console.print(f"[bold red blink][CONFIRMED TAKEOVER] {domain} DNS is DANGLING - {service} takeover is exploitable![/bold red blink]")
                    else:
                        severity = "HIGH"
                        cvss = 8.1
                        console.print(f"[bold red][TAKEOVER DETECTED] {domain} vulnerable to {service} (DNS resolves but fingerprint present)[/bold red]")

                    return {
                        "type": f"Subdomain Takeover: {service}",
                        "severity": severity,
                        "cvss_score": cvss,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
                        "owasp": "A05:2021-Security Misconfiguration",
                        "mitre": "T1584.001 - Compromise Infrastructure: Domains",
                        "content": (
                            f"{'[CONFIRMED - DNS DANGLING]' if dns_confirmed else '[DETECTED - DNS still resolves]'} "
                            f"Subdomain `{domain}` points to a deleted/unclaimed {service} resource.\n"
                            f"DNS resolution: {'NXDOMAIN (fully claimable)' if dns_confirmed else str(dns_result)}\n"
                            f"Fingerprint matched: '{data['fingerprint'][:60]}'"
                        ),
                        "remediation_fix": (
                            f"1. Either REMOVE the CNAME record for `{domain}` from DNS if the {service} service is no longer used.\n"
                            f"2. OR recreate the {service} resource to prevent anyone from claiming it.\n"
                            "3. Audit all CNAME records pointing to third-party services regularly.\n"
                            "4. Use a tool like `subjack` or `can-i-take-over-xyz` in CI/CD pipelines."
                        ),
                        "impact_desc": (
                            f"An attacker can claim the `{service}` resource that `{domain}` points to, "
                            f"then serve arbitrary content from the company's subdomain. This enables "
                            f"phishing attacks under a trusted domain, cookie theft, and XSS against users."
                        ),
                        "patch_priority": "IMMEDIATE" if dns_confirmed else "HIGH",
                        "evidence_url": url,
                        "vulnerable": True,
                        "service": service,
                        "dns_confirmed": dns_confirmed,
                        "bounty_estimate": 2500 if dns_confirmed else 1500,
                    }
        except Exception:
            pass

        return None
