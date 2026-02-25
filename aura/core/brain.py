import logging

logger = logging.getLogger("aura")

class AuraBrain:
    """The intelligence layer that explains attack paths and suggests exploits."""
    
    REASONING_PATTERNS = {
        "admin": "Administrative panels are entry points for lateral movement and credential harvesting. Recommendation: Brute-force discovery of sub-directories (/admin, /wp-admin) or check for default credentials.",
        "jenkins": "Jenkins instances often contain CI/CD secrets and SSH keys. If accessed, it could lead to a full Supply Chain compromise.",
        "api": "Unprotected APIs often suffer from Broken Object Level Authorization (BOLA). Recommendation: Fuzz endpoints for IDOR vulnerabilities.",
        "staging": "Staging environments are often less protected than production and may contain legacy data or debug symbols.",
        "docker": "Exposed Docker registries or sockets can lead to container escape and host takeover.",
        "vpn": "VPN endpoints are high-value targets for initial access. Recommendation: Check for known CVEs in the underlying software (Pulse Secure, Fortinet, etc.)."
    }

    def reason(self, target_data):
        """Analyzes a target and provides strategic advice."""
        value = target_data.get("target", "").lower()
        insights = []

        for pattern, explanation in self.REASONING_PATTERNS.items():
            if pattern in value:
                insights.append(explanation)

        if not insights:
            return "General reconnaissance target. Recommendation: Perform port scanning and service enumeration to identify potential attack surface."
        
        return "\n\n".join(insights)
