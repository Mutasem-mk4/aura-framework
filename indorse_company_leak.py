import asyncio
import httpx
import json
from aura.ui.formatter import console

async def discover_company_ids():
    url = "https://api-prod-test.indorse.io/graphql"
    console.print(f"[bold cyan][*] Probing Company ID Discovery: {url}[/bold cyan]")
    
    # Target 1: visitorListCompanies (Public List)
    q1 = {"query": "query { visitorListCompanies { _id companyName prettyId } }"}
    # Target 2: getCompaniesAutoComplete (Public Auto-Complete)
    q2 = {"query": "query { getCompaniesAutoComplete(searchText: \"a\") { _id companyName prettyId } }"}
    
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        # Check Public List
        console.print("[*] Probing visitorListCompanies...")
        try:
            r1 = await client.post(url, json=q1)
            if r1.status_code == 200:
                data = r1.json()
                if "data" in data and data["data"].get("visitorListCompanies"):
                    console.print(f"  [bold green][+] FOUND COMPANY IDs (visitorListCompanies):[/bold green]")
                    for c in data["data"]["visitorListCompanies"][:5]:
                        console.print(f"    -> {c['companyName']} (ID: {c['_id']})")
                    return [c['_id'] for c in data["data"]["visitorListCompanies"]]
                else:
                    console.print(f"  [.] visitorListCompanies -> 200 but null/unauthorized.")
            else:
                console.print(f"  [.] visitorListCompanies -> {r1.status_code}")
        except: pass

        # Check Auto-Complete
        console.print("[*] Probing getCompaniesAutoComplete...")
        try:
            r2 = await client.post(url, json=q2)
            if r2.status_code == 200:
                data = r2.json()
                if "data" in data and data["data"].get("getCompaniesAutoComplete"):
                    console.print(f"  [bold green][+] FOUND COMPANY IDs (getCompaniesAutoComplete):[/bold green]")
                    for c in data["data"]["getCompaniesAutoComplete"][:5]:
                        console.print(f"    -> {c['companyName']} (ID: {c['_id']})")
                    return [c['_id'] for c in data["data"]["getCompaniesAutoComplete"]]
                else:
                    console.print(f"  [.] getCompaniesAutoComplete -> 200 but null/unauthorized.")
        except: pass

    return []

if __name__ == "__main__":
    asyncio.run(discover_company_ids())
