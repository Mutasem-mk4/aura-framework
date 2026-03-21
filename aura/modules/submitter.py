"""
Aura v21.0 — One-Click Bug Bounty Submitter (D4)
Submits reports directly to Intigriti and HackerOne via their APIs.

Setup:
    export INTIGRITI_TOKEN=your_token
    export HACKERONE_USER=your_username
    export HACKERONE_TOKEN=your_api_token

Usage:
    aura submit --platform intigriti --program ubisoft --title "AWS Key Exposed" --severity critical
    aura submit --platform hackerone  --program ubisoft --title "JWT alg:none bypass"
"""
import os
import json
import asyncio
from datetime import datetime, timezone
from rich.console import Console

from aura.ui.formatter import console


class BountySubmitter:
    """
    D4: One-Click Bug Bounty Submission Engine.
    Submits formatted reports to Intigriti and HackerOne via API.
    """

    # Intigriti severity IDs
    INTIGRITI_SEVERITY_MAP = {
        "exceptional": 5, "critical": 4, "high": 3, "medium": 2, "low": 1
    }

    # HackerOne severity map
    H1_SEVERITY_MAP = {
        "critical": "critical", "exceptional": "critical",
        "high": "high", "medium": "medium", "low": "low"
    }

    def __init__(self):
        self.intigriti_token = os.environ.get("INTIGRITI_TOKEN", "")
        self.h1_user = os.environ.get("HACKERONE_USER", "")
        self.h1_token = os.environ.get("HACKERONE_TOKEN", "")

    def _check_creds(self, platform: str) -> bool:
        """Checks if the API credentials are configured."""
        if platform == "intigriti":
            if not self.intigriti_token:
                console.print("[bold red][Submit] INTIGRITI_TOKEN not set. Run:[/bold red]")
                console.print("  [yellow]$env:INTIGRITI_TOKEN='your_token'  [Windows][/yellow]")
                console.print("  [yellow]export INTIGRITI_TOKEN='your_token'  [Linux][/yellow]")
                return False
        elif platform in ("hackerone", "h1"):
            if not self.h1_user or not self.h1_token:
                console.print("[bold red][Submit] HACKERONE_USER or HACKERONE_TOKEN not set.[/bold red]")
                return False
        return True

    async def submit_to_intigriti(self, program_id: str, title: str, description: str,
                                   severity: str = "medium", impact: str = "",
                                   steps: str = "", remediation: str = "") -> dict:
        """
        Submits a vulnerability report to Intigriti.
        Returns the API response dict.
        """
        if not self._check_creds("intigriti"):
            return {"error": "Missing credentials"}

        severity_id = self.INTIGRITI_SEVERITY_MAP.get(severity.lower(), 2)

        payload = {
            "programId": program_id,
            "title": title,
            "description": description,
            "reproductionSteps": steps,
            "impact": impact or f"See description: {title}",
            "remediation": remediation,
            "severityId": severity_id,
        }

        try:
            import httpx
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.post(
                    "https://api.intigriti.com/external/researcher/v1/vulnerabilities",
                    json=payload,
                    headers={
                        "Authorization": f"Bearer {self.intigriti_token}",
                        "Content-Type": "application/json",
                    }
                )
                if r.status_code in (200, 201):
                    data = r.json()
                    report_id = data.get("id", "N/A")
                    console.print(f"[bold green][Submit] Intigriti report submitted! ID: {report_id}[/bold green]")
                    console.print(f"[cyan]  View at: https://app.intigriti.com/researcher/submissions/{report_id}[/cyan]")
                    return {"success": True, "id": report_id, "platform": "intigriti"}
                else:
                    console.print(f"[red][Submit] Intigriti API error {r.status_code}: {r.text[:200]}[/red]")
                    return {"error": r.text, "status": r.status_code}
        except Exception as e:
            console.print(f"[red][Submit] Intigriti submission failed: {e}[/red]")
            return {"error": str(e)}

    async def submit_to_hackerone(self, program_handle: str, title: str, description: str,
                                   severity: str = "medium", impact: str = "",
                                   weakness_id: int = 1) -> dict:
        """
        Submits a vulnerability report to HackerOne.
        Returns the API response dict.
        """
        if not self._check_creds("hackerone"):
            return {"error": "Missing credentials"}

        h1_severity = self.H1_SEVERITY_MAP.get(severity.lower(), "medium")

        payload = {
            "data": {
                "type": "report",
                "attributes": {
                    "team_handle": program_handle,
                    "title": title,
                    "vulnerability_information": description,
                    "impact": impact or description[:200],
                    "severity_rating": h1_severity,
                    "weakness_id": weakness_id,
                }
            }
        }

        try:
            import httpx
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.post(
                    "https://api.hackerone.com/v1/reports",
                    json=payload,
                    auth=(self.h1_user, self.h1_token),
                    headers={"Content-Type": "application/json"},
                )
                if r.status_code in (200, 201):
                    data = r.json()
                    report_id = data.get("data", {}).get("id", "N/A")
                    console.print(f"[bold green][Submit] HackerOne report submitted! ID: #{report_id}[/bold green]")
                    console.print(f"[cyan]  View at: https://hackerone.com/reports/{report_id}[/cyan]")
                    return {"success": True, "id": report_id, "platform": "hackerone"}
                else:
                    console.print(f"[red][Submit] HackerOne API error {r.status_code}: {r.text[:200]}[/red]")
                    return {"error": r.text, "status": r.status_code}
        except Exception as e:
            console.print(f"[red][Submit] HackerOne submission failed: {e}[/red]")
            return {"error": str(e)}

    async def submit(self, platform: str, program: str, title: str, description: str,
                     severity: str = "medium", impact: str = "", steps: str = "",
                     remediation: str = "") -> dict:
        """Unified entry point for submission."""
        platform = platform.lower().strip()
        if platform == "intigriti":
            return await self.submit_to_intigriti(
                program_id=program, title=title, description=description,
                severity=severity, impact=impact, steps=steps, remediation=remediation
            )
        elif platform in ("hackerone", "h1"):
            return await self.submit_to_hackerone(
                program_handle=program, title=title, description=description,
                severity=severity, impact=impact
            )
        else:
            console.print(f"[red][Submit] Unknown platform: {platform}[/red]")
            return {"error": f"Unknown platform: {platform}"}
