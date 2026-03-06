"""
Aura v22.0 — Integrity Guard (Anti-Rejection Engine)
The final gatekeeper before submission. Audits findings for impact,
scope, and professional quality to prevent N/A, Informative, or Duplicates.
"""

import json
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from aura.core.brain import AuraBrain
from aura.core.config import cfg

console = Console()

class AuraIntegrityGuard:
    """
    Tier 6 intelligence layer for triage validation.
    Reduces rejection rates by auditing impact and polishing language.
    """

    def __init__(self):
        self.brain = AuraBrain()
        self.rejection_risk_keywords = [
            "missing security header", "hsts", "x-content-type", 
            "clickjacking", "autocomplete", "cookie without secure flag",
            "disclosure", "version", "fingerprint"
        ]

    async def triage_finding(self, finding: dict) -> dict:
        """
        Performs a full AI-driven audit of a finding.
        Returns a triage assessment dict.
        """
        f_type = finding.get("finding_type", finding.get("type", "Unknown"))
        content = finding.get("content", "")
        sev = finding.get("severity", "MEDIUM")
        
        # 1. AI Analysis
        prompt = (
            f"As a Bug Bounty Triage Specialist, audit this finding to prevent rejection.\n"
            f"Type: {f_type}\n"
            f"Details: {content[:1000]}\n"
            f"Claimed Severity: {sev}\n\n"
            "Analyze the following:\n"
            "1. Real-world business impact (is it 'theoretical' or 'practical'?)\n"
            "2. Polished Description (rewrite to be highly professional/persuasive)\n"
            "3. Integrity Score (0-100)\n"
            "4. Rejection Risk (High/Medium/Low)\n\n"
            "Respond ONLY in JSON: {"
            "'integrity_score': int, "
            "'rejection_risk': 'string', "
            "'polished_description': 'string', "
            "'impact_justification': 'string', "
            "'suggestions_to_boost_score': ['string']"
            "}"
        )
        
        triage_data = {}
        if self.brain.enabled:
            res = self.brain.reason_json(prompt)
            try:
                triage_data = json.loads(res)
            except:
                triage_data = self._get_fallback_triage(finding)
        else:
            triage_data = self._get_fallback_triage(finding)

        # 2. Heuristic Refinement
        self._refine_heuristics(finding, triage_data)
        
        return triage_data

    def _get_fallback_triage(self, finding: dict) -> dict:
        """Simple rules-based triage when AI is offline."""
        f_type = finding.get("finding_type", finding.get("type", "")).lower()
        score = 50
        risk = "MEDIUM"
        
        if any(k in f_type for k in self.rejection_risk_keywords):
            score = 30
            risk = "HIGH"
        elif any(k in f_type for k in ["sqli", "rce", "idor", "ssrf"]):
            score = 90
            risk = "LOW"
            
        return {
            "integrity_score": score,
            "rejection_risk": risk,
            "polished_description": finding.get("content", "Report requires manual polish."),
            "impact_justification": "Automated impact assessment suggests potential security risk.",
            "suggestions_to_boost_score": ["Add a manual Proof-of-Concept", "Explain business risk clearly"]
        }

    def _refine_heuristics(self, finding: dict, triage: dict):
        """Manual adjustments to AI assessment based on hard rules."""
        f_type = finding.get("finding_type", finding.get("type", "")).lower()
        
        # Rule: Informative/Low findings are always risky
        if triage.get("integrity_score", 0) > 70 and any(k in f_type for k in ["header", "info disclosure"]):
            triage["integrity_score"] = 60
            triage["rejection_risk"] = "MEDIUM"

    def show_triage_report(self, finding: dict, triage: dict):
        """Displays a beautiful Rich report of the triage assessment."""
        score = triage.get("integrity_score", 0)
        color = "green" if score > 75 else ("yellow" if score > 50 else "red")
        
        console.print(Panel(
            f"[bold {color}]Integrity Score: {score}/100[/bold {color}]\n"
            f"[bold]Rejection Risk:[/bold] {triage.get('rejection_risk', 'Unknown')}\n\n"
            f"[bold cyan]AI Impact Justification:[/bold cyan]\n{triage.get('impact_justification', 'N/A')}",
            title="🔍 Aura Integrity Guard Assessment",
            subtitle="Anti-Rejection Mode",
            border_style=color
        ))
        
        if triage.get("suggestions_to_boost_score"):
            table = Table(title="💡 Suggestions to Improve Report", show_header=False, box=None)
            for s in triage["suggestions_to_boost_score"]:
                table.add_row(f"[yellow]• {s}[/yellow]")
            console.print(table)
        
        if score < 50:
            console.print("[bold red][!] WARNING: This finding is at high risk of being rejected (N/A or Informative).[/bold red]")
            console.print("[dim]Action: Follow suggestions above to demonstrate higher business impact.[/dim]")
        else:
            console.print("[bold green][+] VALIDATED: This finding meets professional submission standards.[/bold green]")
