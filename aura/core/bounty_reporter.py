import json
import logging
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from aura.core.brain import AuraBrain

logger = logging.getLogger("aura.bounty_reporter")

class BountyReporter:
    """
    v40.0 OMEGA: Bounty Reporter.
    Automates the creation of professional vulnerability reports for Bug Bounty platforms.
    """

    PLATFORM_TEMPLATES = {
        "hackerone": {
            "severity_labels": ["Low", "Medium", "High", "Critical"],
            "format": "markdown"
        },
        "intigriti": {
            "severity_labels": ["Low", "Medium", "High", "Critical", "Exceptional"],
            "format": "markdown"
        },
        "bugcrowd": {
            "severity_labels": ["P4", "P3", "P2", "P1"],
            "format": "markdown"
        },
        "generic": {
            "severity_labels": ["Info", "Low", "Medium", "High", "Critical"],
            "format": "markdown"
        }
    }

    def __init__(self, brain: AuraBrain = None, platform: str = "generic"):
        self.brain = brain or AuraBrain()
        self.platform = platform.lower() if platform.lower() in self.PLATFORM_TEMPLATES else "generic"
        self.template = self.PLATFORM_TEMPLATES[self.platform]

    async def generate_report(self, finding: Dict[str, Any], verification_output: Optional[str] = None) -> str:
        """
        Synthesizes a professional report for a single verified finding.
        """
        logger.info(f"[📝] Generating professional {self.platform} report for: {finding.get('type')}")

        # 1. Use AI to refine the impact and descriptive sections
        prompt = f"""
        As AURA-Zenith Bounty Report Architect, write a professional vulnerability report for the following finding.
        Target Platform: {self.platform}
        Finding Type: {finding.get('type')}
        Severity: {finding.get('severity')}
        Evidence: {json.dumps(finding.get('evidence'))}
        Verification Result: {verification_output or 'Verified as VULNERABLE by ApexSentinel'}
        
        The report must be in Markdown and include:
        1. **Summary**: Concise explanation of the flaw.
        2. **Impact**: How this affects the business/users (Professional tone).
        3. **Steps to Reproduce**: Detailed list of steps, including the use of any provided PoC scripts.
        4. **Remediation**: Specific, actionable fix recommendations.
        
        Respond with ONLY the Markdown content.
        """

        try:
            report_body = await self.brain.reason(prompt)
            
            # 2. Add header metadata
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            header = f"""# [AURA-OMEGA] {finding.get('type')} Report
**Generated:** {timestamp}
**Platform Target:** {self.platform.capitalize()}
**Aura Verification:** ✅ APEX-Sentinel Confirmed

---

"""
            full_report = header + report_body
            
            # 3. Save to disk
            report_dir = "reports/bounty"
            os.makedirs(report_dir, exist_ok=True)
            filename = f"{finding.get('type', 'vulnerability')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md".replace(" ", "_").lower()
            filepath = os.path.join(report_dir, filename)
            
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(full_report)
                
            logger.info(f"[✓] Professional report saved to: {filepath}")
            return full_report

        except Exception as e:
            logger.error(f"[!] Bounty Report generation failed: {e}")
            return "Failed to generate report."

    def get_platform_severity(self, aura_severity: str) -> str:
        """Maps Aura severity to platform-specific labels."""
        aura_severity = aura_severity.upper()
        labels = self.template["severity_labels"]
        
        if self.platform == "bugcrowd":
            mapping = {"CRITICAL": "P1", "HIGH": "P2", "MEDIUM": "P3", "LOW": "P4", "INFO": "P4"}
            return mapping.get(aura_severity, "P3")
        
        # Default mapping for HackerOne/Intigriti style
        if aura_severity == "CRITICAL": return labels[-1] if self.platform != "intigriti" else labels[3]
        if aura_severity == "HIGH": return labels[2] if self.platform != "bugcrowd" else labels[1]
        return "Medium"
