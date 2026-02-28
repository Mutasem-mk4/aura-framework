from aura.modules.forge.base import AuraPlugin

class HeaderInspector(AuraPlugin):
    """Example plugin to inspect security headers."""
    
    @property
    def name(self):
        return "HeaderInspector"

    @property
    def description(self):
        return "Checks for missing security headers (HSTS, CSP, etc.)"

    async def run(self, target: str, data: dict = None):
        # Simulated check
        return {
            "findings": [
                {"type": "Missing Header", "detail": "Content-Security-Policy not found", "severity": "MEDIUM"},
                {"type": "Missing Header", "detail": "Strict-Transport-Security not found", "severity": "LOW"}
            ]
        }
