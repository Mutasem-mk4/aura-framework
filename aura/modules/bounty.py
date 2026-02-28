from aura.core.stealth import StealthEngine, AuraSession
from aura.core.notifier import CommLink
from rich.console import Console
import re

console = Console()
stealth = StealthEngine()
session = AuraSession(stealth)
comm_link = CommLink()

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

    def calculate_entropy(self, data):
        """Calculates Shannon entropy of a string."""
        import math
        if not data: return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    async def scan_for_secrets(self, url):
        """Scans for leaked secrets using RegEx and high-entropy string detection (v2)."""
        if not url.startswith("http"):
            url = f"http://{url}"
            
        console.print(f"[bold yellow][*] Bounty Hunter v2: Scanning for secrets on {url}...[/bold yellow]")
        
        found_secrets = []
        try:
            paths_to_check = ["/", "/.env", "/config.js", "/assets/app.js", "/wp-config.php.bak"]
            
            for path in paths_to_check:
                full_url = f"{url.rstrip('/')}{path}"
                response = await session.get(full_url, timeout=5)
                
                if response.status_code == 200:
                    content = response.text
                    
                    # 1. RegEx Matching
                    for name, pattern in self.RE_PATTERNS.items():
                        matches = re.findall(pattern, content)
                        if matches:
                            for match in matches:
                                secret_info = {"type": name, "value": match, "location": full_url, "method": "regex"}
                                console.print(f"[bold red][!!!] BOUNTY (Regex): {name} found in {full_url}[/bold red]")
                                comm_link.send_telegram_alert(f"Critical Secret Exposed!\nType: `{name}`\nURL: `{full_url}`")
                                found_secrets.append(secret_info)
                    
                    # 2. Entropy-based Detection (for unknown API keys/secrets)
                    # Find words of length 32-64 that might be keys
                    potential_keys = re.findall(r"[A-Za-z0-9/\+=]{32,64}", content)
                    for pk in potential_keys:
                        entropy = self.calculate_entropy(pk)
                        # Threshold for high-entropy (typical for keys)
                        if entropy > 4.5:
                            # Avoid duplicates from regex
                            if not any(pk in s["value"] for s in found_secrets):
                                secret_info = {"type": "High-Entropy String", "value": pk, "location": full_url, "method": "entropy", "score": round(entropy, 2)}
                                console.print(f"[bold red][!!!] BOUNTY (Entropy): Possible secret (E:{round(entropy, 2)}) in {full_url}[/bold red]")
                                comm_link.send_telegram_alert(f"Potential Secret Detected (High Entropy)!\nValue: `{pk[:8]}...`\nURL: `{full_url}`")
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
