import os
import httpx
import json
from typing import Dict, List, Optional
from rich.console import Console

console = Console()

class AutonomousSubmitter:
    """
    Aura v33 Zenith: Autonomous Bounty Submitter.
    Supports HackerOne, Intigriti, and Bugcrowd API integration.
    """
    
    def __init__(self):
        self.h1_token = os.getenv("H1_API_TOKEN")
        self.h1_user = os.getenv("H1_USERNAME")
        self.intigriti_token = os.getenv("INTIGRITI_API_TOKEN")
        self.dry_run = True

    async def submit_to_hackerone(self, program: str, report_data: Dict) -> bool:
        """Automated submission to HackerOne."""
        if self.dry_run:
            console.print(f"[bold yellow][DRY-RUN] Would submit to HackerOne program: {program}[/bold yellow]")
            return True
        
        url = "https://api.hackerone.com/v1/reports"
        auth = (self.h1_user, self.h1_token)
        payload = {
            "data": {
                "type": "report",
                "attributes": {
                    "title": report_data['title'],
                    "vulnerability_information": report_data['content'],
                    "impact": report_data['impact'],
                    "severity_rating": report_data['severity'].lower()
                },
                "relationships": {
                    "program": {
                        "data": {
                            "type": "program",
                            "attributes": { "handle": program }
                        }
                    }
                }
            }
        }
        
        async with httpx.AsyncClient() as client:
            resp = await client.post(url, auth=auth, json=payload)
            if resp.status_code == 201:
                console.print(f"[bold green][✓] Successfully submitted to HackerOne: {program}[/bold green]")
                return True
        return False

    async def submit_to_intigriti(self, program_id: str, report_data: Dict) -> bool:
        """Automated submission to Intigriti."""
        if self.dry_run:
            console.print(f"[bold yellow][DRY-RUN] Would submit to Intigriti program: {program_id}[/bold yellow]")
            return True
            
        url = f"https://api.intigriti.com/external/v1/programs/{program_id}/submissions"
        headers = {"Authorization": f"Bearer {self.intigriti_token}", "Content-Type": "application/json"}
        
        async with httpx.AsyncClient() as client:
            resp = await client.post(url, headers=headers, json=report_data)
            if resp.status_code == 200:
                console.print(f"[bold green][✓] Successfully submitted to Intigriti: {program_id}[/bold green]")
                return True
        return False

    async def run(self, report_path: str, platform: str = "hackerone", program: str = "", dry_run: bool = True):
        """Unified submission entry point."""
        self.dry_run = dry_run
        
        if not os.path.exists(report_path):
            console.print(f"[bold red]❌ Report not found: {report_path}[/bold red]")
            return

        with open(report_path, "r", encoding="utf-8") as f:
            content = f.read()
            
        # Basic parsing (in real Zenith, AI would structure this)
        report_data = {
            "title": f"Vulnerability Report - {os.path.basename(str(report_path))}",
            "content": content,
            "impact": "High-impact data exposure or system compromise.",
            "severity": "high"
        }

        if platform == "hackerone":
            await self.submit_to_hackerone(program, report_data)
        elif platform == "intigriti":
            await self.submit_to_intigriti(program, report_data)
        else:
            console.print(f"[bold red]❌ Unsupported platform: {platform}[/bold red]")

# Quick CLI Handler for aura-submit
def run_submit(report_path: str, dry_run: bool = True):
    import asyncio
    submitter = AutonomousSubmitter()
    platform = os.getenv("PREFERRED_PLATFORM", "hackerone")
    program = os.getenv("H1_PROGRAM_HANDLE", "test_program")
    asyncio.run(submitter.run(report_path, platform=platform, program=program, dry_run=dry_run))
