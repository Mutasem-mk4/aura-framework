import sqlite3
from typing import List, Set
from aura.core.storage import AuraStorage

class DeepMemoryFuzzer:
    """The 'Experience Engine': Remembers historically vulnerable parameters to prioritize attacks."""
    
    def __init__(self, storage: AuraStorage):
        self.storage = storage

    def get_vulnerable_history(self, domain: str) -> Set[str]:
        """Retrieves a set of parameters that have been vulnerable on this domain or similar tech stacks."""
        vulnerable_params = set()
        with sqlite3.connect(self.storage.db_path) as conn:
            cursor = conn.cursor()
            # Look for findings that have a specific parameter in their content
            cursor.execute('''
                SELECT content FROM findings 
                WHERE target_id IN (SELECT id FROM targets WHERE value LIKE ?)
                AND severity IN ('CRITICAL', 'HIGH')
            ''', (f"%{domain}%",))
            
            rows = cursor.fetchall()
            for row in rows:
                content = row[0]
                # Heuristic extraction of parameter name from content strings like "via 'id' parameter"
                import re
                matches = re.findall(r"via ['\"](.+)['\"] parameter", content)
                for m in matches:
                    vulnerable_params.add(m)
        
        return vulnerable_params

    def prioritize_attack_vectors(self, params: List[str], domain: str) -> List[str]:
        """Sorts parameters based on historical vulnerability data."""
        history = self.get_vulnerable_history(domain)
        # Parameters in history go to the front
        prioritized = [p for p in params if p in history]
        others = [p for p in params if p not in history]
        return prioritized + others
