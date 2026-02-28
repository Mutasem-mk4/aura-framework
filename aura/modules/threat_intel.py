import os
from aura.core.stealth import AuraSession, StealthEngine
from rich.console import Console

console = Console()

class ThreatIntel:
    """Module for gathering passive threat intelligence from external APIs."""
    
    def __init__(self, stealth: StealthEngine = None):
        self.shodan_api_key = os.getenv("SHODAN_API_KEY")
        self.vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.otx_api_key = os.getenv("OTX_API_KEY")
        self.censys_id = os.getenv("CENSYS_API_ID")
        self.censys_secret = os.getenv("CENSYS_API_SECRET")
        self.greynoise_api_key = os.getenv("GREYNOISE_API_KEY")
        self.stealth = stealth or StealthEngine()
        self.session = AuraSession(self.stealth)

    def _warn_missing_key(self, service):
        console.print(f"[bold yellow][!] {service} API key missing. Aura is 'Blind' to historical external intelligence from this source.[/bold yellow]")

    async def query_censys(self, target_ip):
        """Query Censys for host data."""
        if not self.censys_id or not self.censys_secret:
            self._warn_missing_key("Censys")
            return None
            
        console.print(f"[blue][*] Querying Censys for: {target_ip}...[/blue]")
        url = f"https://search.censys.io/api/v2/hosts/{target_ip}"
        try:
            response = await self.session.get(url, auth=(self.censys_id, self.censys_secret), timeout=10)
            if response.status_code == 200:
                data = response.json().get("result", {})
                services = data.get("services", [])
                console.print(f"[green][+] Censys found {len(services)} services on {target_ip}.[/green]")
                return {"services_count": len(services), "services": services}
            else:
                console.print(f"[dim yellow][!] Censys API returned: {response.status_code}[/dim yellow]")
        except Exception as e:
            console.print(f"[dim red][!] Failed to connect to Censys: {str(e)}[/dim red]")
        return None

    async def query_greynoise(self, target_ip):
        """Query GreyNoise to check if the target is known noise/malicious."""
        if not self.greynoise_api_key:
            self._warn_missing_key("GreyNoise")
            return None
            
        console.print(f"[blue][*] Querying GreyNoise for: {target_ip}...[/blue]")
        url = f"https://api.greynoise.io/v3/community/{target_ip}"
        headers = {"key": self.greynoise_api_key}
        try:
            response = await self.session.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                noise = data.get("noise", False)
                riot = data.get("riot", False)
                classification = data.get("classification", "unknown")
                console.print(f"[green][+] GreyNoise Intel: Noise={noise}, RIOT={riot}, Class={classification}[/green]")
                return {"noise": noise, "riot": riot, "classification": classification}
            else:
                console.print(f"[dim yellow][!] GreyNoise API returned: {response.status_code}[/dim yellow]")
        except Exception as e:
            console.print(f"[dim red][!] Failed to connect to GreyNoise: {str(e)}[/dim red]")
        return None
        
    async def query_shodan(self, target_ip):
        """Query Shodan for open ports and known vulnerabilities."""
        if not self.shodan_api_key:
            self._warn_missing_key("Shodan")
            return None
            
        console.print(f"[blue][*] Querying Shodan for: {target_ip}...[/blue]")
        url = f"https://api.shodan.io/shodan/host/{target_ip}?key={self.shodan_api_key}"
        try:
            response = await self.session.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                ports = data.get("ports", [])
                vulns = data.get("vulns", [])
                console.print(f"[green][+] Shodan found {len(ports)} open ports and {len(vulns)} CVEs.[/green]")
                return {"ports": ports, "vulns": vulns}
            else:
                console.print(f"[dim yellow][!] Shodan API returned: {response.status_code}[/dim yellow]")
        except Exception as e:
            console.print(f"[dim red][!] Failed to connect to Shodan: {str(e)}[/dim red]")
        return None

    async def query_virustotal(self, domain):
        """Query VirusTotal for domain reputation and subdomains."""
        if not self.vt_api_key:
            self._warn_missing_key("VirusTotal")
            return None
            
        console.print(f"[blue][*] Querying VirusTotal for: {domain}...[/blue]")
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": self.vt_api_key}
        try:
            response = await self.session.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                console.print(f"[green][+] VirusTotal Intel: {malicious} engines flagged this domain as malicious.[/green]")
                return {"malicious": malicious, "stats": stats}
            else:
                console.print(f"[dim yellow][!] VirusTotal API returned: {response.status_code}[/dim yellow]")
        except Exception as e:
            console.print(f"[dim red][!] Failed to connect to VirusTotal: {str(e)}[/dim red]")
        return None

    async def query_otx(self, target):
        """Query AlienVault OTX for associated indicators of compromise (IoCs)."""
        if not self.otx_api_key:
            self._warn_missing_key("AlienVault OTX")
            return None
            
        console.print(f"[blue][*] Querying AlienVault OTX for: {target}...[/blue]")
        # Determine if target is IP or domain for the endpoint
        import re
        is_ip = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target)
        indicator_type = "IPv4" if is_ip else "domain"
        
        url = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{target}/general"
        headers = {"X-OTX-API-KEY": self.otx_api_key}
        try:
            response = await self.session.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                console.print(f"[green][+] AlienVault OTX Intel: Target found in {pulse_count} threat pulses.[/green]")
                return {"pulse_count": pulse_count}
            else:
                console.print(f"[dim yellow][!] AlienVault OTX API returned: {response.status_code}[/dim yellow]")
        except Exception as e:
            console.print(f"[dim red][!] Failed to connect to AlienVault OTX: {str(e)}[/dim red]")
        return None
