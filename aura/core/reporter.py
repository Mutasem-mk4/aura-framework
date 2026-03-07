
import os
import json
import sqlite3

def get_mitre(vuln_type: str) -> str:
    """Shim for get_mitre utility."""
    mapping = {
        "sql injection": "T1190 - Exploit Public-Facing Application",
        "ssrf": "T1071.001 - Application Layer Protocol",
        "secret": "T1552 - Unsecured Credentials"
    }
    return mapping.get(vuln_type.lower(), "T1059 - Command and Scripting Interpreter")

class AuraReporter:
    """Shim for legacy AuraReporter used by other modules."""
    def __init__(self, db_path=None):
        self.db_path = db_path

    def _fetch_data(self, target_filter=None):
        # Dummy return to satisfy imports
        return [], [], [], []
