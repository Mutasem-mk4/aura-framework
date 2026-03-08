
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
        # v22.6: Use __file__ to anchor to project root (not os.getcwd())
        _pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        self.report_dir = os.path.join(_pkg_root, "reports")
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)
            
        # v25.0 Apex Automation
        from aura.modules.bounty_broker import BountyBroker
        self.broker = BountyBroker()

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
            "4. 1-Click Exploit (PoC): If 'poc_link' or a 1-click URL is present in the data, feature it prominently as an actionable link.\n"
            f"5. Deep-Stack Remediation: Concrete code or configuration fixes specifically for {tech_stack}.\n\n"
            "Tone: Highly technical, authoritative, and professional.\n"
            "Do NOT use placeholders. Generate a full, submission-ready report."
        )

        try:
            # v26.0: Generate Visual Proof if a 1-click PoC exists
            poc_link = finding.get("poc_link")
            screenshot_path = None
            if poc_link:
                from aura.modules.poc_visualizer import PoCVisualizer
                visualizer = PoCVisualizer()
                screenshot_path = await visualizer.generate_visual_proof(poc_link, v_type)

            # v26.0: Generate Weaponized HTML Exploit (CORS/CSRF)
            from aura.modules.artifact_builder import ArtifactBuilder
            artifact_path = ArtifactBuilder().build_artifact(finding)

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
                
                # Attach Visual Proof
                if screenshot_path and os.path.exists(screenshot_path):
                    # Use absolute path or relative path to the image
                    # Markdown image format: ![alt](path)
                    f.write(f"\n\n---\n\n## 📸 Visual Exploitation Proof\n\n![PoC Screenshot]({screenshot_path})\n\n")

                # Attach HTML Exploit Artifact
                if artifact_path and os.path.exists(artifact_path):
                    f.write(f"\n\n---\n\n## 📦 Weaponized Exploit Artifact\n\n")
                    f.write(f"An automated HTML exploit payload was generated for this vulnerability to demonstrate the attack impact.\n")
                    f.write(f"The weaponized file is located at:\n`{artifact_path}`\n\n")

                # Attach Raw Dumps
                raw_req = finding.get("raw_request")
                raw_res = finding.get("raw_response")
                if raw_req or raw_res:
                    f.write("\n\n---\n\n## 🕵️‍♂️ Raw Evidence Dumps (Triager's View)\n\n")
                    if raw_req:
                        f.write("### HTTP Request\n```http\n" + raw_req + "\n```\n\n")
                    if raw_res:
                        f.write("### HTTP Response\n```http\n" + raw_res + "\n```\n\n")
                        
            return filepath
        except Exception as e:
            return f"Error generating report: {e}"

    async def finalize_mission(self, target: str, findings: list, tech_stack: str = "Generic"):
        """Generates reports for all findings in a mission."""
        report_paths = []
        for f in findings:
            # v22.6 P2 Fix: Only generate AI reports for real confirmed findings
            # (must have an evidence_url meaning a real HTTP response was received)
            has_evidence = bool(f.get("evidence_url") or f.get("url") or f.get("location"))
            is_confirmed = f.get("confirmed", False)
            sev_ok = f.get("severity") in ["CRITICAL", "HIGH", "MEDIUM"]
            if sev_ok and (is_confirmed or has_evidence):
                path = await self.generate_final_report(target, f, tech_stack=tech_stack)
                report_paths.append(path)
                
                # v25.0 Apex Automation: Auto-Submit to Bug Bounty Platforms
                if "Error generating report" not in path:
                    # Program ID could be dynamically retrieved from scope if we integrated it
                    # For now we use the global environment variable fallback config inside the broker
                    await self.broker.process_report(target, f, path)

        return report_paths
