import os
import asyncio
import uuid
import socket
from typing import List, Dict, Any, Optional
from aura.core.stealth import AuraSession, StealthEngine
from aura.core import state
from aura.core.engine_interface import IEngine
from aura.core.models import Finding, Severity
from rich.console import Console

from aura.ui.formatter import console

class ThreatIntel(IEngine):
    """Module for gathering passive threat intelligence from external APIs."""
    
    ENGINE_ID = "threat_intel"

    def __init__(self, stealth: StealthEngine = None, persistence=None, telemetry=None, brain=None, **kwargs):
        self.shodan_api_key = os.getenv("SHODAN_API_KEY")
        self.vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.otx_api_key = os.getenv("OTX_API_KEY")
        self.censys_id = os.getenv("CENSYS_API_ID")
        self.censys_secret = os.getenv("CENSYS_API_SECRET")
        self.greynoise_api_key = os.getenv("GREYNOISE_API_KEY")
        self.abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY")
        self.securitytrails_api_key = os.getenv("SECURITYTRAILS_API_KEY")
        self.binaryedge_api_key = os.getenv("BINARYEDGE_API_KEY")
        self.intelx_api_key = os.getenv("INTELX_API_KEY")
        self.hunterio_api_key = os.getenv("HUNTERIO_API_KEY")
        self.fullhunt_api_key = os.getenv("FULLHUNT_API_KEY")
        self.stealth = stealth or StealthEngine()
        self.persistence = persistence
        self.telemetry = telemetry
        self.brain = brain
        self.session = AuraSession(self.stealth)
        self._status = "initialized"

    async def run(self, target: str, **kwargs) -> List[Finding]:
        """Unified entry point for IEngine (Phase 3 Integration)."""
        self._status = "running"
        findings = []
        
        # Determine if target is IP or domain
        is_ip = False
        try:
            socket.inet_aton(target)
            is_ip = True
        except socket.error:
            is_ip = False
            
        tasks = []
        if is_ip:
            tasks = [
                self.query_shodan(target),
                self.query_abuseipdb(target),
                self.query_censys(target),
                self.query_greynoise(target),
                self.query_otx(target)
            ]
        else:
            tasks = [
                self.query_virustotal(target),
                self.query_securitytrails(target),
                self.query_fullhunt(target),
                self.query_hunterio(target),
                self.query_otx(target)
            ]
            
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for res in results:
            if not res or isinstance(res, Exception):
                continue
            
            # Convert OSINT results to Findings
            findings.append(Finding(
                content=f"Passive intelligence gathered for {target}: {str(res)[:200]}...",
                finding_type="OSINT Intel Discovery",
                severity=Severity.INFO,
                target_value=target,
                meta={"engine": self.ENGINE_ID, "remediation": "Review passive intelligence for target fingerprinting.", "raw": res}
            ))
            
        self._status = "completed"
        return findings

    def get_status(self) -> Dict[str, Any]:
        return {"id": self.ENGINE_ID, "status": self._status}

    def _warn_missing_key(self, service):
        # Only warn if it's a critical missing core key
        core_keys = ["Shodan", "VirusTotal", "AlienVault"]
        if service in core_keys:
            console.print(f"[bold yellow][!] {service} API key missing. Aura is 'Blind' to historical external intelligence from this source.[/bold yellow]")
        else:
            # Silent skip for optional/secondary keys
            pass

    async def query_abuseipdb(self, target_ip):
        """Query AbuseIPDB for IP reputation and reports."""
        if not self.abuseipdb_api_key:
            self._warn_missing_key("AbuseIPDB")
            return None
            
        console.print(f"[blue][*] Querying AbuseIPDB for: {target_ip}...[/blue]")
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {
            'ipAddress': target_ip,
            'maxAgeInDays': '90'
        }
        headers = {
            'Accept': 'application/json',
            'Key': self.abuseipdb_api_key
        }
        try:
            response = await self.session.get(url, headers=headers, params=params, timeout=state.NETWORK_TIMEOUT, raw=True)
            if response and response.status_code == 200:
                data = response.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                reports = data.get("totalReports", 0)
                console.print(f"[green][+] AbuseIPDB: Confidence Score={score}%, Total Reports={reports}[/green]")
                return {"abuse_score": score, "total_reports": reports, "last_reported": data.get("lastReportedAt")}
            elif response:
                console.print(f"[dim yellow][!] AbuseIPDB API returned: {response.status_code}[/dim yellow]")
            else:
                console.print(f"[dim red][!] AbuseIPDB: No response (Blocked/Timeout)[/dim red]")
        except Exception as e:
            console.print(f"[dim red][!] Failed to connect to AbuseIPDB: {str(e)}[/dim red]")
        return None

    async def query_censys(self, target_ip):
        """Query Censys for host data."""
        if not self.censys_id or not self.censys_secret:
            self._warn_missing_key("Censys")
            return None
            
        console.print(f"[blue][*] Querying Censys for: {target_ip}...[/blue]")
        url = f"https://search.censys.io/api/v2/hosts/{target_ip}"
        try:
            response = await self.session.get(url, auth=(self.censys_id, self.censys_secret), timeout=state.NETWORK_TIMEOUT, raw=True)
            if response and response.status_code == 200:
                data = response.json().get("result", {})
                services = data.get("services", [])
                console.print(f"[green][+] Censys found {len(services)} services on {target_ip}.[/green]")
                return {"services_count": len(services), "services": services}
            elif response:
                console.print(f"[dim yellow][!] Censys API returned: {response.status_code}[/dim yellow]")
            else:
                console.print(f"[dim red][!] Censys: No response (Blocked/Timeout)[/dim red]")
        except Exception as e:
            console.print(f"[dim red][!] Failed to connect to Censys: {str(e)}[/dim red]")
        return None

    async def query_greynoise(self, target_ip):
        """Query GreyNoise to check if the target is known noise/malicious."""
        if not self.greynoise_api_key:
            # Silent skip, no local equivalent needed
            return None
            
        console.print(f"[blue][*] Querying GreyNoise for: {target_ip}...[/blue]")
        url = f"https://api.greynoise.io/v3/community/{target_ip}"
        headers = {"key": self.greynoise_api_key}
        try:
            response = await self.session.get(url, headers=headers, timeout=state.NETWORK_TIMEOUT, raw=True)
            if response and response.status_code == 200:
                data = response.json()
                noise = data.get("noise", False)
                riot = data.get("riot", False)
                classification = data.get("classification", "unknown")
                console.print(f"[green][+] GreyNoise Intel: Noise={noise}, RIOT={riot}, Class={classification}[/green]")
                return {"noise": noise, "riot": riot, "classification": classification}
            elif response:
                console.print(f"[dim yellow][!] GreyNoise API returned: {response.status_code}[/dim yellow]")
            else:
                console.print(f"[dim red][!] GreyNoise: No response (Blocked/Timeout)[/dim red]")
        except Exception as e:
            console.print(f"[dim red][!] Failed to connect to GreyNoise: {str(e)}[/dim red]")
        return None
        
    async def query_shodan(self, target_ip):
        """Query Shodan for open ports and known vulnerabilities."""
        if not self.shodan_api_key:
            console.print(f"[dim cyan][*] Shodan API key missing. Relying on local Nmap/TCP-Scanner for port discovery on {target_ip}.[/dim cyan]")
            return None
            
        console.print(f"[blue][*] Querying Shodan for: {target_ip}...[/blue]")
        url = f"https://api.shodan.io/shodan/host/{target_ip}?key={self.shodan_api_key}"
        try:
            response = await self.session.get(url, timeout=state.NETWORK_TIMEOUT, raw=True)
            if response and response.status_code == 200:
                data = response.json()
                ports = data.get("ports", [])
                vulns = data.get("vulns", [])
                console.print(f"[green][+] Shodan found {len(ports)} open ports and {len(vulns)} CVEs.[/green]")
                return {"ports": ports, "vulns": vulns}
            elif response and response.status_code == 403:
                console.print(f"[dim yellow][!] Shodan API returned 403 (Likely restricted CDN/Cloudflare IP).[/dim yellow]")
            elif response:
                console.print(f"[dim yellow][!] Shodan API returned: {response.status_code}[/dim yellow]")
            else:
                console.print(f"[dim red][!] Shodan: No response (Blocked/Timeout)[/dim red]")
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
            response = await self.session.get(url, headers=headers, timeout=state.NETWORK_TIMEOUT, raw=True)
            if response and response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                console.print(f"[green][+] VirusTotal Intel: {malicious} engines flagged this domain as malicious.[/green]")
                return {"malicious": malicious, "stats": stats}
            elif response:
                console.print(f"[dim yellow][!] VirusTotal API returned: {response.status_code}[/dim yellow]")
            else:
                console.print(f"[dim red][!] VirusTotal: No response (Blocked/Timeout)[/dim red]")
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
            response = await self.session.get(url, headers=headers, timeout=state.NETWORK_TIMEOUT, raw=True)
            if response and response.status_code == 200:
                data = response.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                console.print(f"[green][+] AlienVault OTX Intel: Target found in {pulse_count} threat pulses.[/green]")
                return {"pulse_count": pulse_count}
            elif response:
                console.print(f"[dim yellow][!] AlienVault OTX API returned: {response.status_code}[/dim yellow]")
            else:
                console.print(f"[dim red][!] AlienVault OTX: No response (Blocked/Timeout)[/dim red]")
        except Exception as e:
            console.print(f"[dim red][!] Failed to connect to AlienVault OTX: {str(e)}[/dim red]")
        return None

    async def query_securitytrails(self, domain):
        """Query SecurityTrails for DNS history and subdomains."""
        if not self.securitytrails_api_key:
            console.print(f"[dim cyan][*] SecurityTrails API key missing. Relying on local Subfinder/crt.sh for subdomain enumeration on {domain}.[/dim cyan]")
            return None
            
        console.print(f"[blue][*] Querying SecurityTrails for: {domain}...[/blue]")
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {"apikey": self.securitytrails_api_key}
        try:
            response = await self.session.get(url, headers=headers, timeout=state.NETWORK_TIMEOUT, raw=True)
            if response and response.status_code == 200:
                data = response.json()
                subdomains = data.get("subdomains", [])
                console.print(f"[green][+] SecurityTrails found {len(subdomains)} subdomains for {domain}.[/green]")
                return {"subdomains_count": len(subdomains), "subdomains": subdomains}
            elif response:
                console.print(f"[dim yellow][!] SecurityTrails API returned: {response.status_code}[/dim yellow]")
        except Exception as e:
            console.print(f"[dim red][!] Failed to connect to SecurityTrails: {str(e)}[/dim red]")
        return None

    async def query_binaryedge(self, target):
        """Query BinaryEdge for exposed services and vulnerabilities."""
        if not self.binaryedge_api_key:
            self._warn_missing_key("BinaryEdge")
            return None
            
        console.print(f"[blue][*] Querying BinaryEdge for: {target}...[/blue]")
        url = f"https://api.binaryedge.io/v2/query/target/{target}"
        headers = {"X-Key": self.binaryedge_api_key}
        try:
            response = await self.session.get(url, headers=headers, timeout=state.NETWORK_TIMEOUT, raw=True)
            if response and response.status_code == 200:
                results = response.json().get("events", [])
                console.print(f"[green][+] BinaryEdge found {len(results)} events for {target}.[/green]")
                return {"events_count": len(results), "events": results}
            elif response:
                console.print(f"[dim yellow][!] BinaryEdge API returned: {response.status_code}[/dim yellow]")
        except Exception as e:
            console.print(f"[dim red][!] Failed to connect to BinaryEdge: {str(e)}[/dim red]")
        return None

    async def query_fullhunt(self, domain):
        """Query FullHunt for attack surface mapping."""
        if not self.fullhunt_api_key:
            self._warn_missing_key("FullHunt")
            return None
            
        console.print(f"[blue][*] Querying FullHunt for: {domain}...[/blue]")
        url = f"https://fullhunt.io/api/v1/domain/{domain}/details"
        headers = {"X-API-KEY": self.fullhunt_api_key}
        try:
            response = await self.session.get(url, headers=headers, timeout=state.NETWORK_TIMEOUT, raw=True)
            if response and response.status_code == 200:
                data = response.json()
                hosts = data.get("hosts", [])
                console.print(f"[green][+] FullHunt identified {len(hosts)} hosts for {domain}.[/green]")
                return {"hosts_count": len(hosts), "hosts": hosts}
        except Exception as e:
            console.print(f"[dim red][!] Failed to connect to FullHunt: {str(e)}[/dim red]")
        return None

    async def query_intelx(self, target):
        """Query IntelX for leak and breach intelligence."""
        if not self.intelx_api_key:
            self._warn_missing_key("IntelX")
            return None
            
        console.print(f"[blue][*] Querying IntelX for: {target}...[/blue]")
        url = "https://2.intelx.io/phonebook/search"
        headers = {"x-key": self.intelx_api_key}
        data = {"term": target, "maxresults": 10}
        try:
            # IntelX uses a search/result pattern, this is a simplified probe
            response = await self.session.post(url, headers=headers, json=data, timeout=state.NETWORK_TIMEOUT, raw=True)
            if response and response.status_code == 200:
                search_id = response.json().get("id")
                console.print(f"[green][+] IntelX Search Initiated (ID: {search_id}).[/green]")
                return {"search_id": search_id}
        except Exception as e:
            console.print(f"[dim red][!] Failed to connect to IntelX: {str(e)}[/dim red]")
        return None

    async def query_hunterio(self, domain):
        """Query Hunter.io for employee emails and data."""
        if not self.hunterio_api_key:
            self._warn_missing_key("Hunter.io")
            return None
            
        console.print(f"[blue][*] Querying Hunter.io for: {domain}...[/blue]")
        url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={self.hunterio_api_key}"
        try:
            response = await self.session.get(url, timeout=state.NETWORK_TIMEOUT, raw=True)
            if response and response.status_code == 200:
                data = response.json().get("data", {})
                emails = data.get("emails", [])
                console.print(f"[green][+] Hunter.io found {len(emails)} emails for {domain}.[/green]")
                return {"emails_count": len(emails), "emails": [e.get("value") for e in emails]}
        except Exception as e:
            console.print(f"[dim red][!] Failed to connect to Hunter.io: {str(e)}[/dim red]")
        return None

    # --- Phase 15: 0-Day Radar ---
    async def query_github_0days(self, tech_stack: list) -> list:
        """
        0-Day Radar: Scans GitHub for recently published Proof of Concepts (PoCs)
        for the given technologies (e.g., searching for 'CVE-202X Next.js PoC').
        """
        if not tech_stack:
            return []
            
        console.print(f"[bold magenta][📡] 0-Day Radar: Scanning global threat feeds for {len(tech_stack)} technologies...[/bold magenta]")
        
        # We query GitHub Search API for recent CVE PoCs matching the tech stack
        # To avoid rate limits and noise, we just make a few targeted queries.
        # Format: CVE {tech} PoC created:>yyyy-mm-dd
        import datetime
        last_week = (datetime.datetime.now() - datetime.timedelta(days=7)).strftime('%Y-%m-%d')
        
        found_0days = []
        for tech in tech_stack[:3]: # Limit to top 3 core techs to avoid rate limiting
            # Clean up tech name (e.g., "Next.js" -> "Next.js")
            clean_tech = tech.split()[0].replace(',', '').strip()
            query = f'"{clean_tech}" CVE PoC created:>{last_week}'
            url = f"https://api.github.com/search/repositories?q={query}&sort=updated"
            
            try:
                # GitHub allows 60 req/hr unauthenticated.
                response = await self.session.get(url, timeout=state.NETWORK_TIMEOUT, raw=True)
                if response and response.status_code == 200:
                    data = response.json()
                    items = data.get("items", [])
                    if items:
                        console.print(f"[bold red][!!!] 0-DAY RADAR HIT: Found {len(items)} recent exploits for {clean_tech}![/bold red]")
                        for item in items[:2]: # Take top 2
                            found_0days.append({
                                "tech": clean_tech,
                                "repo": item.get('html_url'),
                                "description": item.get('description'),
                                "date": item.get('created_at')
                            })
                await __import__("asyncio").sleep(1) # Courtesy delay
            except Exception as e:
                console.print(f"[dim red][!] 0-Day Radar GitHub query failed: {e}[/dim red]")
                
        return found_0days

