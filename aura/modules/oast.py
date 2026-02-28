import requests
import time
from rich.console import Console

console = Console()

class OastCatcher:
    """Phase 26: Out-of-Band (OAST) Integration for Blind Exploitation"""
    def __init__(self):
        self.session = requests.Session()
        self.uuid = None
        self.oast_url = None
        
    def setup(self):
        """Initializes the OAST endpoint by generating a unique Webhook.site URL."""
        console.print("[magenta][*] Phase 26: Initializing God Mode OAST Server (Blind Exploitation)...[/magenta]")
        try:
            res = self.session.post("https://webhook.site/token", json={}, headers={"Accept": "application/json"}, timeout=5)
            if res.status_code in [200, 201]:
                self.uuid = res.json().get("uuid")
                # Strip out https:// to make it a raw domain for versatility, but here we keep full URL.
                self.oast_url = f"https://webhook.site/{self.uuid}"
                console.print(f"[bold magenta][👁️] OAST Server Active: {self.oast_url}[/bold magenta]")
                return self.oast_url
        except Exception as e:
            console.print(f"[dim red][!] OAST API Error: {e}. Blind checks will be degraded.[/dim red]")
        return None

    def poll(self):
        """Polls the OAST server for out-of-band interactions (RCE/SSRF confirmations)."""
        if not self.uuid: return []
        try:
            res = self.session.get(f"https://webhook.site/token/{self.uuid}/requests", headers={"Accept": "application/json"}, timeout=5).json()
            interactions = []
            if "data" in res:
                for req in res["data"]:
                    interactions.append({
                        "ip": req.get("ip"),
                        "method": req.get("method"),
                        "url": req.get("url"),
                        "user_agent": req.get("user_agent"),
                        "content": req.get("content", "")[:200]
                    })
            return interactions
        except Exception as e:
            console.print(f"[dim red]OAST Polling error: {e}[/dim red]")
            return []
