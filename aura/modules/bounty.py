import re
import requests
from rich.console import Console

console = Console()

class BountyHunter:
    """High-impact vulnerability scanner focused on monetization."""
    
    # Common RegEx patterns for secrets
    RE_PATTERNS = {
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "AWS Secret Key": r"['\"]([0-9a-zA-Z/+]{40})['\"]",
        "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
        "Firebase URL": r"https://[a-zA-Z0-9-]+\.firebaseio\.com",
        "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
        "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}"
    }

    def scan_for_secrets(self, url):
        """Scans a web target for leaked secrets in the source code or common config files."""
        if not url.startswith("http"):
            url = f"http://{url}"
            
        console.print(f"[bold yellow][*] Bounty Hunter: Scanning for secrets on {url}...[/bold yellow]")
        
        found_secrets = []
        try:
            # We fetch common sensitive files first
            paths_to_check = ["/", "/.env", "/config.js", "/assets/app.js", "/wp-config.php.bak"]
            
            for path in paths_to_check:
                full_url = f"{url.rstrip('/')}{path}"
                response = requests.get(full_url, timeout=5, verify=False)
                
                if response.status_code == 200:
                    for name, pattern in self.RE_PATTERNS.items():
                        matches = re.findall(pattern, response.text)
                        if matches:
                            for match in matches:
                                secret_info = {"type": name, "value": match, "location": full_url}
                                console.print(f"[bold red][!!!] BOUNTY DETECTED: {name} found in {full_url}[/bold red]")
                                found_secrets.append(secret_info)
                                
        except Exception as e:
            console.print(f"[red][!] Secret scan error: {str(e)}[/red]")
            
        return found_secrets

    def estimate_value(self, finding_type):
        """Estimates the potential bounty value based on the finding type."""
        values = {
            "AWS Access Key": 1500,
            "AWS Secret Key": 1500,
            "Stripe API Key": 1000,
            "Firebase URL": 500,
            "Slack Webhook": 300,
            "Google API Key": 500
        }
        return values.get(finding_type, 100)
