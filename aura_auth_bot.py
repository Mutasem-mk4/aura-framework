import asyncio
import httpx
import json
from aura_auth import vault
from aura.ui.formatter import console

class IndorseAuthHandler:
    """Automates Auth flows for Indorse.io."""
    
    BASE_URL = "https://indorse.io"
    API_URL = "https://presto.indorse.io/graphql"

    async def register(self, email, password, username):
        """Attempts to automate registration via GraphQL or REST."""
        console.print(f"[*] Attempting Auto-Registration for [cyan]{username}[/cyan]...")
        # Most Indorse flows are GraphQL based. Building a signup mutation.
        mutation = {
            "query": """
            mutation Signup($email: String!, $password: String!, $username: String!) {
                signup(email: $email, password: $password, username: $username) {
                    token
                    user { id username }
                }
            }
            """,
            "variables": {
                "email": email,
                "password": password,
                "username": username
            }
        }
        
        async with httpx.AsyncClient(verify=False) as client:
            try:
                r = await client.post(self.API_URL, json=mutation)
                if r.status_code == 200:
                    data = r.json()
                    if "errors" in data:
                        console.print(f"  [yellow][!] Registration error: {data['errors'][0]['message']}[/yellow]")
                        return None
                    token = data["data"]["signup"]["token"]
                    console.print(f"  [bold green][+] Registration Successful![/bold green]")
                    return token
            except Exception as e:
                console.print(f"  [red][!] Registration failed: {e}[/red]")
        return None

    async def login(self, email, password):
        """Automates login to extract JWT."""
        console.print(f"[*] Attempting Auto-Login for [cyan]{email}[/cyan]...")
        mutation = {
            "query": """
            mutation Login($email: String!, $password: String!) {
                login(email: $email, password: $password) {
                    token
                    user { id username }
                }
            }
            """,
            "variables": {
                "email": email,
                "password": password
            }
        }
        
        async with httpx.AsyncClient(verify=False) as client:
            try:
                r = await client.post(self.API_URL, json=mutation)
                if r.status_code == 200:
                    data = r.json()
                    if "errors" in data:
                        console.print(f"  [yellow][!] Login error: {data['errors'][0]['message']}[/yellow]")
                        return None
                    token = data["data"]["login"]["token"]
                    # Save to vault
                    vault.set_session("presto.indorse.io", {"Authorization": f"Bearer {token}"})
                    console.print(f"  [bold green][+] Login Successful. Session stored.[/bold green]")
                    return token
            except Exception as e:
                console.print(f"  [red][!] Login failed: {e}[/red]")
        return None

async def main():
    # Example usage (CLI wrapper could be added later)
    handler = IndorseAuthHandler()
    # For now, we wait for user to decide if they want Auto-Reg or have an account.
    console.print("[bold yellow]Aura Auto-Auth Bot Loaded.[/bold yellow]")

if __name__ == "__main__":
    asyncio.run(main())
