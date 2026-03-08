
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
    """The True Reporting Engine - Fetches real findings from AuraStorage."""
    def __init__(self, db_path=None):
        from aura.core.storage import AuraStorage
        self.db = AuraStorage(db_path)

    def _fetch_data(self, target_filter=None):
        """Fetches unified targets and findings from the DB, ensuring compatibility with all reporters."""
        targets = []
        try:
            with self.db._get_connection() as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Filter based on domain substring if provided
                if target_filter:
                    cursor.execute("SELECT * FROM targets WHERE value LIKE ?", (f"%{target_filter}%",))
                else:
                    cursor.execute("SELECT * FROM targets")
                    
                target_rows = cursor.fetchall()
                
                for t_row in target_rows:
                    t_dict = dict(t_row)
                    target_id = t_dict['id']
                    
                    # Fetch findings tied to this specific target
                    cursor.execute("SELECT * FROM findings WHERE target_id = ?", (target_id,))
                    finding_rows = cursor.fetchall()
                    
                    if finding_rows:
                        findings_list = []
                        for f_row in finding_rows:
                            f_dict = dict(f_row)
                            
                            # Safely attempt to unpack the 'content' JSON column into the dictionary
                            # to provide flat access to dynamic attributes like payload, url, etc.
                            if isinstance(f_dict.get('content'), str):
                                try:
                                    import json as _json
                                    content_data = _json.loads(f_dict['content'])
                                    if isinstance(content_data, dict):
                                        f_dict.update(content_data)
                                except Exception:
                                    pass
                                    
                            findings_list.append(f_dict)
                            
                        t_dict['findings'] = findings_list
                        targets.append(t_dict)
                        
        except Exception as e:
            # Prevent crashing the reporting pipeline
            pass
            
        # Returns (targets, [], [], []) to satisfy the tuple unpacking signature expected by callers
        return targets, [], [], []
