import time
from typing import Dict, List, Optional
from dataclasses import dataclass

@dataclass
class BountyScale:
    severity: str
    min_usd: float
    max_usd: float
    multiplier: float

class ProfitEngine:
    """
    Aura v33 Zenith: Strategic ROI & Bounty Estimation Engine.
    Maximizes earnings by prioritizing high-payout vulnerability chains.
    """
    
    SEVERITY_SCALES = {
        "CRITICAL": BountyScale("CRITICAL", 5000, 100000, 4.0),
        "EXCEPTIONAL": BountyScale("EXCEPTIONAL", 3000, 50000, 3.5),
        "HIGH": BountyScale("HIGH", 1000, 10000, 2.0),
        "MEDIUM": BountyScale("MEDIUM", 100, 2000, 1.2),
        "LOW": BountyScale("LOW", 50, 500, 1.0)
    }

    TYPE_MULTIPLIERS = {
        "RCE": 4.0,
        "HTTP_SMUGGLING": 4.0,
        "DESERIALIZATION": 3.5,
        "RACE_CONDITION": 3.0,
        "SSTI": 3.0,
        "XXE": 2.5,
        "CACHE_POISONING": 2.5,
        "SSRF": 2.0,
        "SQLI": 2.0,
        "IDOR": 2.0,
        "OAUTH": 2.0,
        "GRAPHQL": 2.0,
        "FILE_UPLOAD": 1.8,
        "DOM_XSS": 1.5,
        "PROTOTYPE_POLLUTION": 1.5,
        "XSS": 1.2,
        "OPEN_REDIRECT": 1.2
    }

    def __init__(self, platform: str = "hackerone"):
        self.platform = platform
        self.total_estimated_earnings = 0.0
        self.findings_log = []

    def calculate_roi(self, vuln_type: str, severity: str) -> float:
        """Calculates the ROI score for a finding."""
        scale = self.SEVERITY_SCALES.get(severity.upper(), self.SEVERITY_SCALES["LOW"])
        type_mult = self.TYPE_MULTIPLIERS.get(vuln_type.upper(), 1.0)
        
        # Formula: (Base Multiplier * Severity Multiplier * Type Multiplier)
        roi_score = (scale.multiplier * type_mult)
        return round(roi_score, 2)

    def estimate_payout(self, vuln_type: str, severity: str) -> str:
        """Estimates the USD payout range."""
        scale = self.SEVERITY_SCALES.get(severity.upper(), self.SEVERITY_SCALES["LOW"])
        type_mult = self.TYPE_MULTIPLIERS.get(vuln_type.upper(), 1.0)
        
        est_min = scale.min_usd * (type_mult / 2) # Weighted min
        est_max = scale.max_usd
        
        return f"${int(est_min):,}-{int(est_max):,}"

    def get_priority_score(self, domain: str, discovered_vulns: List[Dict]) -> float:
        """Calculates a global priority score for a target domain."""
        if not discovered_vulns:
            return 0.0
        
        max_roi = max([self.calculate_roi(v['type'], v['severity']) for v in discovered_vulns])
        return max_roi

    def generate_platform_report_summary(self, finding: Dict) -> str:
        """Generates a summary based on platform-specific expectations."""
        # v33: Pre-formatted for H1/Intigriti
        report = f"## [{finding['type'].upper()}] - Impact Analysis\n"
        report += f"- Estimated Severity: {finding['severity']}\n"
        report += f"- Reward Potential: {self.estimate_payout(finding['type'], finding['severity'])}\n\n"
        report += "### Executive Summary\n"
        report += "Automated analysis detected a high-impact vulnerability that could lead to...\n"
        return report

# Global instance
profit_engine = ProfitEngine()
