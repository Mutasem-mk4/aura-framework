import requests
from rich.console import Console
from aura.core.stealth import StealthEngine, AuraSession

console = Console()
stealth = StealthEngine()
session = AuraSession(stealth)

class TakeoverFinder:
    """Engine for detecting Subdomain Takeover vulnerabilities."""
    
    # Signatures for common services (dangling DNS)
    TAKEOVER_SIGS = {
        "GitHub Pages": {"fingerprint": "There isn't a GitHub Pages site here", "service": "GitHub"},
        "Heroku": {"fingerprint": "no such app", "service": "Heroku"},
        "Amazon S3": {"fingerprint": "NoSuchBucket", "service": "AWS S3"},
        "Shopify": {"fingerprint": "Sorry, this shop is currently unavailable", "service": "Shopify"},
        "Tumblr": {"fingerprint": "Whatever you were looking for is not here", "service": "Tumblr"},
        "Ghost.io": {"fingerprint": "The thing you were looking for is no longer here", "service": "Ghost.io"}
    }

    def check_takeover(self, domain):
        """Checks a subdomain for potential takeover fingerprints."""
        if not domain.startswith("http"):
            url = f"http://{domain}"
        else:
            url = domain
            
        console.print(f"[bold yellow][*] TakeoverFinder: Checking {domain} for DNS takeover...[/bold yellow]")
        
        try:
            response = session.get(url, timeout=5)
            content = response.text
            
            for service, data in self.TAKEOVER_SIGS.items():
                if data["fingerprint"] in content:
                    console.print(f"[bold red][!!!] TAKEOVER DETECTED: {domain} is vulnerable to {service} takeover![/bold red]")
                    return {
                        "vulnerable": True,
                        "service": service,
                        "url": url,
                        "bounty_estimate": 1500
                    }
        except Exception as e:
            pass
            
        return None
