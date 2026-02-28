import random
from typing import List, Dict

class LeakProber:
    """Ghost v4: Passive module for probing historical credential leaks."""
    
    # Mock Leak Database (Simulating Shodan/DeHashed/BreachDirectory)
    LEAK_DB = {
        "example.com": [
            {"email": "admin@example.com", "leak": "Collection #1", "date": "2019", "severity": "HIGH"},
            {"email": "dev@example.com", "leak": "Adobe Leak", "date": "2013", "severity": "MEDIUM"}
        ],
        "test.com": [
            {"email": "user@test.com", "leak": "LinkedIn Leak", "date": "2016", "severity": "LOW"}
        ]
    }

    def probe_domain(self, domain: str) -> List[Dict]:
        """Simulates a lookup for leaked credentials for a given domain."""
        # In a real implementation, this would call an API like HaveIBeenPwned or BreachDirectory
        for k, v in self.LEAK_DB.items():
            if k in domain:
                return v
        return []

    def get_risk_impact(self, leaks: List[Dict]) -> int:
        """Calculates risk score based on leak severity."""
        score = 0
        severity_map = {"HIGH": 5000, "MEDIUM": 2000, "LOW": 500}
        for leak in leaks:
            score += severity_map.get(leak["severity"], 100)
        return score
