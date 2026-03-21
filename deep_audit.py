import asyncio
import httpx
from aura.ui.formatter import console

class BoneDeepAudit:
    """
    Advanced audit for 'Hard Targets'.
    Skips common CVEs and focuses on unique misconfigurations.
    """
    
    def __init__(self):
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        }
        self.sensitive_files = [
            "/.env", "/.git/config", "/package.json", "/composer.json",
            "/.vscode/settings.json", "/WEB-INF/web.xml", "/.aws/credentials"
        ]

    async def scan_sensitive(self, url):
        console.print(f"[*] Bone-Deep Audit -> {url}")
        try:
            async with httpx.AsyncClient(verify=False, timeout=5) as client:
                for path in self.sensitive_files:
                    try:
                        r = await client.get(f"{url}{path}", headers=self.headers)
                        if r.status_code == 200 and ("index" in r.text.lower() or "repository" in r.text.lower() or "dependencies" in r.text.lower()):
                            console.print(f"  [bold green][!!] CRITICAL LEAK: {url}{path}[/bold green]")
                            return True
                    except: continue
        except Exception: pass
        return False

if __name__ == "__main__":
    import json
    import os
    
    hits_file = r"c:\Users\User\.gemini\antigravity\scratch\aura\reports\eid_offensive_hits.json"
    if os.path.exists(hits_file):
        with open(hits_file, "r") as f:
            hits = json.load(f)
        
        auditor = BoneDeepAudit()
        loop = asyncio.get_event_loop()
        for hit in hits:
            loop.run_until_complete(auditor.scan_sensitive(hit["url"]))
