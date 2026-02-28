import random

class CVEProvider:
    """Ghost v4: Intelligence module for matching tech stacks with CVE data."""
    
    # Mock CVE Database (In real impl, this would fetch from NVD/Shodan)
    CVE_DB = {
        "WordPress": [
            {"id": "CVE-2024-1234", "severity": "HIGH", "desc": "Unauthenticated RCE in WP-Core"},
            {"id": "CVE-2023-5678", "severity": "MEDIUM", "desc": "Stored XSS in popular plugin"}
        ],
        "React": [
            {"id": "CVE-2023-0001", "severity": "LOW", "desc": "Potential XSS in server-side rendering"}
        ],
        "Apache": [
            {"id": "CVE-2021-41773", "severity": "CRITICAL", "desc": "Path Traversal and RCE"},
            {"id": "CVE-2021-42013", "severity": "CRITICAL", "desc": "Incomplete fix for path traversal"}
        ],
        "Nginx": [
            {"id": "CVE-2022-41741", "severity": "MEDIUM", "desc": "Memory corruption in mp4 module"}
        ]
    }

    def get_cves_for_stack(self, tech_stack):
        """Returns a list of matching CVEs for the detected technologies."""
        matches = []
        for tech in tech_stack:
            if tech in self.CVE_DB:
                matches.extend(self.CVE_DB[tech])
        return matches

    def calculate_tech_risk(self, tech_stack):
        """Calculates a risk score based on the severity of matching CVEs."""
        cves = self.get_cves_for_stack(tech_stack)
        score = 0
        severity_map = {"CRITICAL": 5000, "HIGH": 3000, "MEDIUM": 1000, "LOW": 500}
        
        for cve in cves:
            score += severity_map.get(cve["severity"], 100)
            
        return score
