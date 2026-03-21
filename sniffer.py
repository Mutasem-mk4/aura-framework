import asyncio
import httpx
import json
import os
from aura.ui.formatter import console

class ScavengerSniffer:
    def __init__(self, targets_file):
        self.targets_file = targets_file
        self.headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        self.probes = [
            "/.env", "/.env.local", "/.env.production", "/.git/config",
            "/.aws/credentials", "/.s3.amazonaws.com", "/swagger-ui.html",
            "/v2/api-docs", "/actuator/env", "/actuator/health", "/config",
            "/phpinfo.php", "/wp-config.php.bak"
        ]
        self.hits = []

    async def probe_url(self, client, url, path):
        target = f"{url}{path}"
        try:
            r = await client.get(target, follow_redirects=False, timeout=5)
            if r.status_code == 200:
                # Basic validation to avoid 200 OK false positives (like login pages)
                content = r.text.lower()
                is_hit = False
                
                if path == "/.env" and ("db_" in content or "api_" in content or "key" in content):
                    is_hit = True
                elif path == "/.git/config" and "[core]" in content:
                    is_hit = True
                elif "swagger" in content or "openapi" in content:
                    is_hit = True
                elif "actuator" in path and ("propertySources" in content or "activeProfiles" in content):
                    is_hit = True
                elif r.status_code == 200 and len(content) < 5000: # General LHF heuristic
                     is_hit = True

                if is_hit:
                    console.print(f"  [bold green][!!] HIT: {target}[/bold green]")
                    self.hits.append({"url": target, "type": path, "size": len(r.text)})
                    return True
        except: pass
        return False

    async def audit_subdomain(self, client, subdomain):
        # Default protocols to try
        for proto in ["https://", "http://"]:
            base_url = f"{proto}{subdomain}"
            tasks = [self.probe_url(client, base_url, p) for p in self.probes]
            await asyncio.gather(*tasks)

    async def run(self):
        if not os.path.exists(self.targets_file):
            console.print(f"[red][!] Targets file missing: {self.targets_file}[/red]")
            return

        with open(self.targets_file, "r") as f:
            data = json.load(f)

        all_subs = []
        for domain, subs in data.items():
            all_subs.extend(subs)

        console.print(f"[*] Sniffer: Auditing {len(all_subs)} subdomains for LHF...")
        
        async with httpx.AsyncClient(verify=False, limits=httpx.Limits(max_connections=50)) as client:
            # Batch subdomains to avoid overwhelming the system
            batch_size = 10
            for i in range(0, len(all_subs), batch_size):
                batch = all_subs[i:i+batch_size]
                tasks = [self.audit_subdomain(client, sub) for sub in batch]
                await asyncio.gather(*tasks)
                console.print(f"  [.] Progress: {i+len(batch)}/{len(all_subs)}")

        # Save hits
        output_file = r"c:\Users\User\.gemini\antigravity\scratch\aura\reports\sniffer_hits.json"
        with open(output_file, "w") as f:
            json.dump(self.hits, f, indent=4)
        console.print(f"\n[bold green][!!] SNIFFER COMPLETE. {len(self.hits)} hits saved to reports\sniffer_hits.json[/bold green]")

if __name__ == "__main__":
    sniffer = ScavengerSniffer(r"c:\Users\User\.gemini\antigravity\scratch\aura\reports\scavenger_targets_v2.json")
    asyncio.run(sniffer.run())
