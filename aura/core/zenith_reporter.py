
import os
import json
import asyncio
from datetime import datetime

class ZenithReporter:
    """
    v20.0 Zenith Sovereignty: The Autonomous Report Finalizer.
    Transforms raw technical findings into professional, platform-ready Markdown reports.
    """
    
    def __init__(self, brain=None):
        if brain is None:
            from aura.core.brain import AuraBrain
            self.brain = AuraBrain()
        else:
            self.brain = brain
        self.report_dir = "reports"
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)

    async def generate_final_report(self, target: str, finding: dict, tech_stack: str = "Generic") -> str:
        """
        Synthesizes a complete, P1-grade Markdown report from a finding object.
        v22.0: Includes Deep-Stack Remediation advice.
        """
        v_type = finding.get("type", "Security Vulnerability")
        v_content = finding.get("content", str(finding))
        severity = finding.get("severity", "HIGH")
        
        prompt = (
            f"As AURA-Zenith AI, synthesize a PROFESSIONAL BUG BOUNTY REPORT for the following discovery.\n"
            f"Target: {target}\n"
            f"Vulnerability Type: {v_type}\n"
            f"Severity: {severity}\n"
            f"Technology Stack: {tech_stack}\n"
            f"Raw Finding Data: {v_content}\n\n"
            "The report MUST include the following sections in Markdown:\n"
            "1. Summary: A concise overview of the flaw.\n"
            "2. Impact: A deep explanation of the business and security consequences.\n"
            "3. Step-by-Step Reproduction: Clear instructions for a triager.\n"
            f"4. Deep-Stack Remediation: Concrete code or configuration fixes specifically for {tech_stack}.\n\n"
            "Tone: Highly technical, authoritative, and professional.\n"
            "Do NOT use placeholders. Generate a full, submission-ready report."
        )

        try:
            # v20.0: We use the brain to generate the submission content
            report_body = await asyncio.to_thread(self.brain._call_ai, prompt)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"Zenith_Report_{target.replace('.', '_')}_{v_type.replace(' ', '_')}_{timestamp}.md"
            filepath = os.path.join(self.report_dir, filename)
            
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(f"# AURA ZENITH SECURITY ADVISORY\n")
                f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d')}\n")
                f.write(f"**Target:** `{target}`\n")
                f.write(f"**Severity:** `{severity}`\n")
                f.write(f"**Stack Ident:** `{tech_stack}`\n\n")
                f.write(report_body)
                
            return filepath
        except Exception as e:
            return f"Error generating report: {e}"

    async def finalize_mission(self, target: str, findings: list, tech_stack: str = "Generic"):
        """Generates reports for all findings in a mission."""
        report_paths = []
        for f in findings:
            if f.get("severity") in ["CRITICAL", "HIGH", "MEDIUM", "PREDICTIVE"]:
                path = await self.generate_final_report(target, f, tech_stack=tech_stack)
                report_paths.append(path)
        return report_paths
