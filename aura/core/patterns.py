import json
from typing import List, Dict
from aura.core.brain import AuraBrain

class AuraPatternEngine:
    """The 'Nuclei Killer': Generates dynamic, tech-aware attack patterns using AI."""
    
    def __init__(self, brain: AuraBrain):
        self.brain = brain
        # Base templates for different stacks
        self.base_patterns = {
            "PHP": ["/phpinfo.php", "/config.php", "/vendor/autoload.php", "/.env"],
            "Laravel": ["/storage/logs/laravel.log", "/.env", "/artisan"],
            "Node.js": ["/package.json", "/package-lock.json", "/.env", "/node_modules"],
            "Python": ["/requirements.txt", "/Pipfile", "/.env", "/manage.py"],
            "WordPress": ["/wp-config.php", "/wp-content/debug.log", "/wp-json/wp/v2/users"]
        }

    async def generate_contextual_patterns(self, tech_stack: str, domain: str) -> List[Dict]:
        """Ghost v6: Uses AI to generate a list of high-value probes specifically for this target."""
        print(f"[🧠] PatternEngine: Generating contextual templates for {tech_stack} stack on {domain}...")
        
        # 1. Start with base patterns
        probes = []
        for tech in tech_stack.split("/"):
            if tech in self.base_patterns:
                for path in self.base_patterns[tech]:
                    probes.append({"path": path, "type": "Info Disclosure", "reason": f"Common {tech} configuration file"})

        # 2. Use AI to generate "Zero-Day" or obscure probes
        prompt = f"""
        Act as an Advanced Penetration Tester. I have a target '{domain}' running the '{tech_stack}' stack.
        Generate 5 very specific, obscure, or high-yield file paths or API endpoints to probe for vulnerabilities 
        (like CVEs, info leaks, or misconfigs) that are unique to this specific technology.
        Return ONLY a JSON list of objects with the following keys: 'path', 'type', 'reason'.
        Do not include markdown or explanations.
        """
        
        try:
            raw_json = self.brain.reason_json(prompt)
            ai_probes = json.loads(raw_json)
            if isinstance(ai_probes, list):
                probes.extend(ai_probes)
        except Exception as e:
            print(f"[!] PatternEngine Warning: AI generation failed: {e}")



        return probes

    def map_to_vulnerability(self, path: str, content: str) -> Dict:
        """Determines the severity and type of finding based on the path and content returned."""
        # This is a heuristic wrapper for the reporter
        if ".env" in path and "DB_PASSWORD" in content:
            return {"type": "Critical Secret Exposure", "severity": "CRITICAL", "desc": "Found raw environment secrets (DB Credentials)."}
        if "wp-config.php" in path and "DB_PASSWORD" in content:
            return {"type": "Critical Config Exposure", "severity": "CRITICAL", "desc": "Found raw WordPress configuration file."}
        if "phpinfo" in path and "PHP Version" in content:
            return {"type": "Information Disclosure", "severity": "MEDIUM", "desc": "Found exposed PHP configuration details."}
        
        return None
