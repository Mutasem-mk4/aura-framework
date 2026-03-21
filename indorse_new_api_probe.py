import asyncio
import httpx
import json
from aura.ui.formatter import console

async def test_indorse_new_api():
    base_url = "https://api-prod-test.indorse.io"
    console.print(f"[bold cyan][*] Probing Discovery: {base_url}[/bold cyan]")
    
    async with httpx.AsyncClient(verify=False, timeout=10) as client:
        # 1. Test Username Enumeration
        console.print("[*] Testing Username Enumeration (/findusername)...")
        try:
            r = await client.post(f"{base_url}/findusername", json={"username": "admin"})
            if r.status_code == 200:
                console.print(f"  [bold green][+] Enumeration Possible: {r.text}[/bold green]")
            else:
                console.print(f"  [.] /findusername -> {r.status_code}")
        except Exception as e:
            console.print(f"  [red][!] Error on /findusername: {e}[/red]")

        # 2. Test GraphQL Introspection on the new domain
        gql_url = f"{base_url}/graphql"
        console.print(f"[*] Testing GraphQL Introspection -> {gql_url}")
        query = {"query": "{ __schema { queryType { name } } }"}
        try:
            r = await client.post(gql_url, json=query)
            if r.status_code == 200:
                data = r.json()
                if "data" in data and "__schema" in data["data"]:
                    console.print(f"  [bold red][!!!] INTROSPECTION ENABLED ON PROD-TEST: {gql_url}[/bold red]")
                    # Save the schema
                    with open("indorse_prod_test_schema.json", "w") as f:
                        json.dump(data, f, indent=2)
                    return True
                else:
                    console.print(f"  [yellow][.] GQL 200 but no schema data.[/yellow]")
            else:
                console.print(f"  [.] GQL -> {r.status_code}")
                # console.print(r.text[:200])
        except Exception as e:
            console.print(f"  [red][!] Error on GQL: {e}[/red]")
            
    return False

if __name__ == "__main__":
    asyncio.run(test_indorse_new_api())
