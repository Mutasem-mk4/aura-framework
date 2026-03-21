import asyncio
import httpx
from aura.ui.formatter import console

async def deep_dive_actuator(url):
    endpoints = [
        "/actuator/env", "/actuator/configprops", "/actuator/heapdump",
        "/actuator/mappings", "/actuator/beans", "/actuator/threaddump"
    ]
    console.print(f"[*] Deep Dive: {url}")
    async with httpx.AsyncClient(verify=False, timeout=10) as client:
        for ep in endpoints:
            try:
                r = await client.get(f"{url}{ep}")
                if r.status_code == 200:
                    console.print(f"  [bold red][!!!] CRITICAL EXPOSURE: {url}{ep}[/bold red]")
                    console.print(f"    -> Size: {len(r.text)} bytes")
                    # Preview some content to confirm leakage
                    if "propertySources" in r.text or "contexts" in r.text:
                        console.print(f"    [!] Confirmed sensitive data leakage.")
                else:
                    console.print(f"  [green][.] {ep}: {r.status_code}[/green]")
            except: pass

if __name__ == "__main__":
    url = "https://uat-bugbounty.nonprod.syfe.com"
    asyncio.run(deep_dive_actuator(url))
