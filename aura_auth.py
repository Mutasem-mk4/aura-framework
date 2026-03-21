import json
import os
import asyncio
import httpx
from typing import Dict, Optional
from aura.ui.formatter import console

AUTH_STORE_PATH = "auth_store.json"

class AuthVault:
    """Manages persistent session tokens (JWT/Cookies) for diverse targets."""
    
    def __init__(self, store_path: str = AUTH_STORE_PATH):
        self.store_path = store_path
        self.data = self._load()

    def _load(self) -> Dict:
        if os.path.exists(self.store_path):
            with open(self.store_path, "r") as f:
                return json.load(f)
        return {}

    def save(self):
        with open(self.store_path, "w") as f:
            json.dump(self.data, f, indent=4)

    def set_session(self, domain: str, headers: Dict):
        self.data[domain] = headers
        self.save()
        console.print(f"  [bold green][+][/bold green] Session saved for [cyan]{domain}[/cyan]")

    def get_session(self, domain: str) -> Optional[Dict]:
        return self.data.get(domain)

class AuraAuthClient:
    """An httpx wrapper that automatically injects stored authentication."""
    
    def __init__(self, vault: AuthVault):
        self.vault = vault

    async def request(self, method: str, url: str, **kwargs):
        # Determine the domain
        from urllib.parse import urlparse
        domain = urlparse(url).netloc
        
        # Inject headers if available
        auth_headers = self.vault.get_session(domain)
        if auth_headers:
            if 'headers' not in kwargs:
                kwargs['headers'] = {}
            kwargs['headers'].update(auth_headers)
            
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            return await client.request(method, url, **kwargs)

# Global singleton
vault = AuthVault()
client = AuraAuthClient(vault)

if __name__ == "__main__":
    console.print("[bold blue]Aura Auth Engine Initialized.[/bold blue]")
    console.print(f"[*] Storage: {AUTH_STORE_PATH}")
