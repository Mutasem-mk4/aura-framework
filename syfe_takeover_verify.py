import asyncio
import httpx
from aura.ui.formatter import console

async def verify_takeover(url):
    console.print(f"[*] Verifying Takeover -> {url}")
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            r = await client.get(url, follow_redirects=True)
            if r.status_code == 404:
                # Zendesk 404 with specific text means it's takeable
                if "No such help center" in r.text or "not found" in r.text.lower():
                    console.print(f"  [bold red][!!!] CONFIRMED TAKEOVER: {url}[/bold red]")
                    return True
                else:
                    console.print(f"  [yellow][.] Status 404 but signature mismatch.[/yellow]")
            else:
                console.print(f"  [.] {url} -> {r.status_code}")
    except Exception as e:
        console.print(f"  [red][!] Error: {e}[/red]")
    return False

if __name__ == "__main__":
    asyncio.run(verify_takeover("https://help.hk.syfe.com"))
