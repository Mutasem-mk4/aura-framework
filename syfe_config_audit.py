import asyncio
import httpx
import json
from aura.ui.formatter import console

async def audit_syfe_config(url):
    console.print(f"[*] Auditing Syfe Config -> {url}")
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            r = await client.get(url)
            if r.status_code == 200:
                content = r.text
                if content.strip().startswith("{") or content.strip().startswith("["):
                    try:
                        data = json.loads(content)
                        console.print(f"  [bold red][!!!] VERIFIED CONFIG EXPOSURE: {url}[/bold red]")
                        console.print(f"    Preview: {json.dumps(data, indent=2)[:500]}...")
                        return True
                    except: pass
                console.print(f"  [yellow][.] Content is not valid JSON (Potential False Positive).[/yellow]")
            else:
                console.print(f"  [.] {url} -> {r.status_code}")
    except Exception as e:
        console.print(f"  [red][!] Error: {e}[/red]")
    return False

async def run_audit():
    targets = [
        "https://api-au.syfe.com/actuator/configprops",
        "https://api-au.syfe.com/actuator/env",
        "https://api-au.syfe.com/actuator/mappings",
        "https://api-sg.syfe.com/actuator/env",
        "https://api-hk.syfe.com/actuator/configprops"
    ]
    for t in targets:
        await audit_syfe_config(t)

if __name__ == "__main__":
    asyncio.run(run_audit())
