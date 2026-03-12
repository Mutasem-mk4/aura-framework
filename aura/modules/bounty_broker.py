import os
import json
import httpx
from rich.console import Console
from aura.core.brain import AuraBrain
import asyncio

console = Console()

class BountyBroker:
    """
    v25.0 Apex Automation: The Bounty Broker.
    Autonomously submits high-confidence, critical/high severity reports directly
    to Bug Bounty platforms (HackerOne, Bugcrowd).
    """

    def __init__(self):
        self.brain = AuraBrain()
        # HackerOne API credentials
        self.h1_identifier = os.getenv("H1_API_IDENTIFIER")
        self.h1_token = os.getenv("H1_API_TOKEN")
        self.h1_program = os.getenv("H1_PROGRAM_HANDLE") # fallback or global

        # Bugcrowd API credentials
        self.bc_token = os.getenv("BUGCROWD_API_TOKEN")
        
        self.enabled = bool((self.h1_identifier and self.h1_token) or self.bc_token)
        if not self.enabled:
            console.print("[dim yellow][Broker] Bounty Broker offline. Missing API credentials in environment.[/dim yellow]")

    async def _submit_hackerone(self, target: str, severity: str, md_content: str, program_handle: str = None) -> bool:
        """Submits a report to HackerOne via their API."""
        handle = program_handle or self.h1_program
        if not self.h1_identifier or not self.h1_token or not handle:
            return False

        url = "https://api.hackerone.com/v1/reports"
        
        # H1 Severity Mapping: none, low, medium, high, critical
        h1_severity = severity.lower()
        if h1_severity not in ["low", "medium", "high", "critical"]:
            h1_severity = "medium"

        payload = {
            "data": {
                "type": "report",
                "attributes": {
                    "team_handle": handle,
                    "title": f"[AURA-AUTOMATED] {severity} Vulnerability on {target}",
                    "vulnerability_information": md_content,
                    "severity_rating": h1_severity,
                    # We would map the exact weakness_id if possible, but leaving default for now
                }
            }
        }

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    url,
                    json=payload,
                    auth=(self.h1_identifier, self.h1_token),
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                    timeout=30
                )
                if resp.status_code in (200, 201):
                    data = resp.json()
                    report_url = data.get("data", {}).get("links", {}).get("self", "Unknown URL")
                    console.print(f"[bold green][💵 BROKER] Report successfully submitted to HackerOne! {report_url}[/bold green]")
                    return True
                else:
                    console.print(f"[red][Broker] HackerOne submission failed: {resp.status_code} - {resp.text}[/red]")
        except Exception as e:
            console.print(f"[red][Broker] HackerOne connection error: {e}[/red]")
        return False

    async def _submit_bugcrowd(self, target: str, severity: str, md_content: str, program_id: str = None) -> bool:
        """Submits a report to Bugcrowd via their API."""
        if not self.bc_token:
            return False
            
        # Bugcrowd uses program UUIDs or shortnames, this requires highly specific config per target
        if not program_id:
            console.print("[yellow][Broker] Bugcrowd requires a specific program_id for submission. Skipping.[/yellow]")
            return False

        url = f"https://api.bugcrowd.com/submissions"
        
        payload = {
            "submission": {
                "target_uuid": program_id,
                "title": f"[AURA-AUTOMATED] {severity} Vulnerability on {target}",
                "description": md_content,
            }
        }

        headers = {
            "Authorization": f"Token {self.bc_token}",
            "Accept": "application/vnd.bugcrowd.v4+json",
            "Content-Type": "application/json"
        }

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(url, json=payload, headers=headers, timeout=30)
                if resp.status_code in (200, 201):
                    console.print(f"[bold green][💵 BROKER] Report successfully submitted to Bugcrowd![/bold green]")
                    return True
                else:
                    console.print(f"[red][Broker] Bugcrowd submission failed: {resp.status_code} - {resp.text}[/red]")
        except Exception as e:
            console.print(f"[red][Broker] Bugcrowd connection error: {e}[/red]")
        return False

    async def _draft_sentient_justification(self, finding: dict) -> str:
        """v38.0 OMEGA: Uses Brain to draft professional severity and repro guide."""
        prompt = f"""
        Draft a professional Bug Bounty report section for this finding:
        Finding Type: {finding.get('type')}
        Severity: {finding.get('severity')}
        Evidence: {json.dumps(finding.get('evidence', {}))}
        Content: {finding.get('content')}
        
        Requirements:
        1. Calculate the CVSS v3.1 score and provide a justification.
        2. Provide a clear, step-by-step reproduction guide.
        3. Explain the business impact (PII exposure, regulatory risk, etc.).
        
        Formatting: Markdown only.
        """
        try:
            return await asyncio.to_thread(self.brain.reason, prompt)
        except Exception:
            return "Sentient Justification failed."

    async def process_report(self, target: str, finding: dict, report_path: str, platform: str = None, program_id: str = None) -> bool:
        """
        Takes a finalized report path and finding data, and routes it to the correct platform.
        Will only process CRITICAL or HIGH severities to avoid penalization for low-quality automated reports.
        """
        if not self.enabled:
            return False
            
        severity = finding.get("severity", "MEDIUM").upper()
        
        # Apex Safety: Only auto-submit high impact findings unless explicitly forced
        if severity not in ["CRITICAL", "HIGH"]:
            console.print(f"[dim][Broker] Skipping auto-submit for {severity} finding on {target}. (Only Critical/High allowed)[/dim]")
            return False

        console.print(f"[bold magenta][💵 BROKER] Initiating Auto-Submit Protocol for {target} ({severity})...[/bold magenta]")
        
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                md_content = f.read()
            
            # v38.0 OMEGA: Sentient Justification Injection
            justification = await self._draft_sentient_justification(finding)
            md_content = f"{md_content}\n\n---\n## [🧠 SENTIENT HUNTER] Severity Justification & Reproduction\n{justification}"
                
            # Determine platform (fallback to HackerOne if configured)
            if platform and platform.lower() == "bugcrowd":
                return await self._submit_bugcrowd(target, severity, md_content, program_id)
            else:
                # Default to H1
                return await self._submit_hackerone(target, severity, md_content, program_id)
                
        except Exception as e:
            console.print(f"[red][Broker] Failed to process report file: {e}[/red]")
            
        return False
