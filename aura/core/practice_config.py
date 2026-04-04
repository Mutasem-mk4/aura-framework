"""
Aura v22.X — Practice Mode Configuration
Safe vulnerable targets for beginners to practice on.

Usage:
    from aura.core.practice_config import PracticeConfig
    PracticeConfig.list_targets()
    PracticeConfig.get_target("juice_shop")
"""
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# Practice mode database (isolated from production)
PRACTICE_DB = os.path.join(os.path.expanduser("~"), ".aura_practice.db")

# Pre-configured vulnerable practice targets
PRACTICE_TARGETS = {
    "juice_shop": {
        "name": "OWASP Juice Shop",
        "url": "https://juice-shop.herokuapp.com",
        "description": "Modern web application security training target with many vulnerabilities",
        "difficulty": "Beginner",
        "vulnerabilities": ["SQLi", "XSS", "IDOR", "Broken Auth", "Security Misconfiguration", "CSRF"],
        "platform": "Heroku",
        "category": "Web App"
    },
    "badstore": {
        "name": "BadStore",
        "url": "https://www.badstore.net",
        "description": "Classic vulnerable webapp for learning basic web vulnerabilities",
        "difficulty": "Beginner",
        "vulnerabilities": ["SQLi", "XSS", "Command Injection", "Path Traversal"],
        "platform": "Docker",
        "category": "Web App"
    },
    "dvwa": {
        "name": "Damn Vulnerable Web App (DVWA)",
        "url": "http://dvwa.local",
        "description": "PHP/MySQL web application with intentional vulnerabilities at multiple difficulty levels",
        "difficulty": "Beginner-Intermediate",
        "vulnerabilities": ["SQLi", "XSS", "CSRF", "File Inclusion", "Brute Force", "Command Injection"],
        "platform": "Docker",
        "category": "Web App"
    },
    "webgoat": {
        "name": "OWASP WebGoat",
        "url": "http://webgoat.local:8080/WebGoat",
        "description": "Interactive teaching platform for web security with guided lessons",
        "difficulty": "Beginner-Intermediate",
        "vulnerabilities": ["SQLi", "XSS", "IDOR", "JWT flaws", "Race Conditions", "SSRF"],
        "platform": "Docker",
        "category": "Web App"
    },
    "hackazon": {
        "name": "Hackazon",
        "url": "http://hackazon.local",
        "description": "Modern vulnerable e-commerce application with REST API vulnerabilities",
        "difficulty": "Intermediate",
        "vulnerabilities": ["SQLi", "XSS", "XXE", "Auth bypass", "API vulnerabilities"],
        "platform": "Docker",
        "category": "Web App"
    },
    "juice_shop_local": {
        "name": "OWASP Juice Shop (Local)",
        "url": "http://localhost:3000",
        "description": "Local instance of Juice Shop for offline practice",
        "difficulty": "Beginner",
        "vulnerabilities": ["SQLi", "XSS", "IDOR", "Broken Auth", "Security Misconfiguration"],
        "platform": "Docker",
        "category": "Web App"
    }
}


@dataclass
class PracticeConfig:
    """
    Configuration for practice mode.
    Isolated from production config to ensure safe scanning.
    """
    enabled: bool = False
    current_target: Optional[str] = None
    current_target_config: Optional[dict] = None
    db_path: str = PRACTICE_DB
    isolation_mode: bool = True  # Always isolate from production

    # Settings
    allow_exploit_modules: bool = True  # Allow exploitation on practice targets
    show_hints: bool = True
    track_progress: bool = True

    @classmethod
    def load(cls) -> "PracticeConfig":
        """Load practice config from environment or defaults."""
        import os
        return cls(
            enabled=os.environ.get("AURA_PRACTICE_MODE", "false").lower() == "true",
            current_target=os.environ.get("AURA_PRACTICE_TARGET", None),
            isolation_mode=True,
        )

    def save(self):
        """Persist practice config to environment (for state.py to pick up)."""
        import os
        if self.enabled:
            os.environ["AURA_PRACTICE_MODE"] = "true"
        else:
            os.environ["AURA_PRACTICE_MODE"] = "false"
        if self.current_target:
            os.environ["AURA_PRACTICE_TARGET"] = self.current_target

    @classmethod
    def get_target(cls, target_name: str) -> Optional[dict]:
        """Get practice target by name."""
        return PRACTICE_TARGETS.get(target_name.lower())

    @classmethod
    def list_targets(cls) -> list:
        """List all available practice targets."""
        return [
            {**v, "id": k} for k, v in PRACTICE_TARGETS.items()
        ]

    @classmethod
    def list_by_difficulty(cls, difficulty: str) -> list:
        """List practice targets by difficulty level."""
        return [
            {**v, "id": k} for k, v in PRACTICE_TARGETS.items()
            if v.get("difficulty", "").lower() == difficulty.lower()
        ]

    @classmethod
    def get_categories(cls) -> list:
        """Get list of unique categories."""
        cats = set()
        for t in PRACTICE_TARGETS.values():
            cats.add(t.get("category", "Other"))
        return sorted(list(cats))

    @classmethod
    def is_docker_available(cls) -> bool:
        """Check if Docker is available for running local targets."""
        import subprocess
        try:
            result = subprocess.run(
                ["docker", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
