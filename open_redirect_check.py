import asyncio
import httpx
from aura.ui.formatter import console

async def check_open_redirect(url):
    redirect_params = ["?url=", "?redirect=", "?next=", "?dest=", "?to="]
    test_target = "http://google.com"
    
    console.print(f"[*] Testing Open Redirect -> {url}")
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=5) as client:
            for param in redirect_params:
                try:
                    r = await client.get(f"{url}{param}{test_target}")
                    if r.status_code in [301, 302, 307, 308]:
                        location = r.headers.get("Location", "")
                        if test_target in location:
                            console.print(f"  [bold green][!!] OPEN REDIRECT CONFIRMED: {url}{param}{test_target}[/bold green]")
                            return True
                except: continue
    except Exception as e:
        console.print(f"  [red]Test failed for {url}: {e}[/red]")
    return False

if __name__ == "__main__":
    targets = [
        "https://click.uber.com",
        "https://view.et.uber.com",
        "https://click.et.uber.com"
    ]
    loop = asyncio.get_event_loop()
    for t in targets:
        loop.run_until_complete(check_open_redirect(t))
