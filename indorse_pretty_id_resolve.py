import asyncio
import httpx
import json
from aura.ui.formatter import console

async def resolve_pretty_id(pretty_id):
    url = "https://api-prod-test.indorse.io/graphql"
    console.print(f"[bold cyan][*] Resolving PrettyID: {pretty_id} -> {url}[/bold cyan]")
    
    q = {
        "query": """
        query ResolveId($prettyId: String!) {
            getCompanyByPrettyId(prettyId: $prettyId) {
                _id
                companyName
            }
        }
        """,
        "variables": {"prettyId": pretty_id}
    }
    
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        try:
            r = await client.post(url, json=q)
            if r.status_code == 200:
                data = r.json()
                if "data" in data and data["data"].get("getCompanyByPrettyId"):
                    res = data["data"]["getCompanyByPrettyId"]
                    console.print(f"  [bold green][+] RESOLVED: {pretty_id} -> {res['_id']} ({res['companyName']})[/bold green]")
                    return res["_id"]
                else:
                    console.print(f"  [.] No data returned for PrettyID: {pretty_id}")
            else:
                console.print(f"  [.] GQL -> {r.status_code}")
        except Exception as e:
            console.print(f"  [red][!] Error: {e}[/red]")
    return None

if __name__ == "__main__":
    asyncio.run(resolve_pretty_id("ems"))
