import logging

logger = logging.getLogger("aura")

class CorrelationEngine:
    """The 'Brain' that connects disparate data points into attack paths."""
    
    def __init__(self):
        self.state = {
            "targets": {},  # host -> data mapping
            "high_risk_keywords": ["dev", "staging", "api", "admin", "vpn", "internal"],
            "vulnerable_services": ["jenkins", "docker", "k8s", "redis", "mongodb"]
        }

    def correlate(self, results):
        """Processes raw results and produces enriched 'Attack Paths'."""
        attack_paths = []
        
        for res in results:
            value = res.get("value", "").lower()
            score = 0
            findings = []

            # 1. Keyword-based risk assessment
            for word in self.state["high_risk_keywords"]:
                if word in value:
                    score += 10
                    findings.append(f"High-risk keyword detected: {word}")

            # 2. Service detection (simulated logic for now)
            for svc in self.state["vulnerable_services"]:
                if svc in value:
                    score += 25
                    findings.append(f"Potentially vulnerable service identified: {svc}")

            # 3. Create an attack path object if score is significant
            if score > 0:
                attack_paths.append({
                    "target": value,
                    "risk_score": score,
                    "insight": " | ".join(findings),
                    "priority": "CRITICAL" if score >= 30 else "HIGH" if score >= 20 else "MEDIUM"
                })

        return sorted(attack_paths, key=lambda x: x["risk_score"], reverse=True)
