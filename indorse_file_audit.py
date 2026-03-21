import asyncio
import httpx
from aura.ui.formatter import console

async def audit_files(domain):
    console.print(f"[bold cyan][*] Auditing Files on {domain}...[/bold cyan]")
    
    paths = [
        "/.env",
        "/.git/config",
        "/.well-known/security.txt",
        "/phpinfo.php",
        "/server-status"
    ]
    
    async with httpx.AsyncClient(verify=False, timeout=10) as client:
        for p in paths:
            url = f"https://{domain}{p}"
            try:
                r = await client.get(url, follow_redirects=False)
                if r.status_code == 200:
                    console.print(f"  [bold red][!!!] SENSITIVE FILE EXPOSURE: {url}[/bold red]")
                    console.print(f"    Preview: {r.text[:200]}...")
            except Exception: pass

if __name__ == "__main__":
    asyncio.run(audit_files("api-prod-test.indorse.io"))
