import httpx
import asyncio
from aura.ui.formatter import console

async def scout_subdomains():
    subdomains = [
        "https://admin.notion.so",
        "https://identity.notion.so",
        "https://api.mail.notion.so",
        "https://msgstore.www.notion.so",
        "https://audioprocessor.www.notion.so"
    ]
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    console.print("[bold cyan]💀 AURA SUBDOMAIN SCOUT: NOTION[/bold cyan]")

    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        for sub in subdomains:
            try:
                console.print(f"[*] Checking: {sub}...")
                resp = await client.get(sub, headers=headers, timeout=10)
                
                status = resp.status_code
                content_type = resp.headers.get("Content-Type", "N/A")
                
                if status == 200:
                    console.print(f"  [green][+] 200 OK | Content: {content_type}[/green]")
                    if "text/html" in content_type:
                        # Check for source maps or dev-mode clues in HTML
                        if ".js.map" in resp.text:
                            console.print(f"    [bold red][!!!] Source Map Disclosure on {sub}![/bold red]")
                elif status == 401 or status == 403:
                    console.print(f"  [yellow][!] {status} Access Denied (Expected)[/yellow]")
                else:
                    console.print(f"  [white][*] Status: {status}[/white]")
                    
                # Check for common vulnerable paths
                paths = ["/.env", "/robos.txt", "/v1/api-docs", "/v1/swagger.json"]
                for path in paths:
                    check_url = sub + path
                    r = await client.get(check_url, headers=headers, timeout=5)
                    if r.status_code == 200:
                        console.print(f"    [bold red][!] Found: {check_url}![/bold red]")
                        
            except Exception as e:
                console.print(f"  [red][!] Error checking {sub}: {e}[/red]")

if __name__ == "__main__":
    asyncio.run(scout_subdomains())
