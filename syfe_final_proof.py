import asyncio
import httpx
import json
from aura.ui.formatter import console

async def final_proof(url):
    console.print(f"[*] FINAL PROOF: Auditing {url}")
    try:
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            r = await client.get(url)
            if r.status_code == 200:
                content = r.text
                # 1. Check if it's HTML or JSON
                if content.strip().startswith("<!doctype html") or content.strip().startswith("<html"):
                    console.print(f"  [red][!] FAIL: Content is HTML (Ghost Hit).[/red]")
                    return False
                
                # 2. Try to parse as JSON (Syfe Actuator usually returns JSON)
                try:
                    data = json.loads(content)
                    console.print(f"  [bold green][!!!] SUCCESS: Valid JSON Detected![/bold green]")
                    console.print(f"    -> Type: {type(data)}")
                    # Check for thread-related keys
                    if "threads" in data or isinstance(data, list):
                         console.print(f"    [bold red][BINGO] Confirmed REAL JVM Data leakage.[/bold red]")
                         console.print(f"    -> Preview (First 200 chars): {content[:200]}")
                         return True
                except:
                    # Maybe it's plain text (some actuators return text)
                    if "thread" in content.lower() or "state" in content.lower():
                        console.print(f"  [bold green][!!!] SUCCESS: Valid Text-based Thread Dump Detected![/bold green]")
                        console.print(f"    -> Preview: {content[:200]}")
                        return True
                    console.print(f"  [yellow][.] Content is not recognizable JSON/Thread-dump.[/yellow]")
            else:
                console.print(f"  [red][!] Status Code: {r.status_code}[/red]")
    except Exception as e:
        console.print(f"  [red][!] Connection Error: {e}[/red]")
    return False

if __name__ == "__main__":
    url = "https://uat-bugbounty.nonprod.syfe.com/actuator/threaddump"
    asyncio.run(final_proof(url))
