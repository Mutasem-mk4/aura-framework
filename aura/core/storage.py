import sqlite3
import os
import json
from datetime import datetime

class AuraStorage:
    """Persistent storage engine for Aura using SQLite."""
    
    def __init__(self, db_path=None):
        # Force a consistent path relative to the project root (where this file is)
        if db_path is None:
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            self.db_path = os.path.join(project_root, "aura_intel.db")
        else:
            self.db_path = os.path.abspath(db_path)
            
        self._init_db()

    def _init_db(self):
        """Initializes the database schema with campaigns and audit logs."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Table for Targets (Domains/Subdomains/IPs)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    value TEXT UNIQUE,
                    type TEXT,
                    source TEXT,
                    risk_score INTEGER DEFAULT 0,
                    priority TEXT DEFAULT 'LOW',
                    first_seen DATETIME,
                    last_seen DATETIME,
                    status TEXT DEFAULT 'ACTIVE'
                )
            ''')
            
            # Table for Scan Results/Findings
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id INTEGER,
                    content TEXT,
                    finding_type TEXT,
                    created_at DATETIME,
                    owasp TEXT,
                    mitre TEXT,
                    severity TEXT,
                    status TEXT DEFAULT 'UNREVIEWED',
                    campaign_id INTEGER,
                    proof TEXT,
                    FOREIGN KEY (target_id) REFERENCES targets(id)
                )
            ''')

            # Table for Campaigns (Mission Tracking)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS campaigns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT,
                    target_config TEXT,
                    created_at DATETIME,
                    status TEXT DEFAULT 'ACTIVE'
                )
            ''')

            # Table for Audit Logs (Legal/Safety Compliance)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME,
                    action TEXT,
                    target TEXT,
                    details TEXT,
                    campaign_id INTEGER,
                    FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
                )
            ''')
            
            # Migration logic for findings table
            cursor.execute("PRAGMA table_info(findings)")
            findings_cols = [column[1] for column in cursor.fetchall()]

            findings_migrations = [
                ("finding_type", "TEXT"),
                ("created_at", "DATETIME"),
                ("owasp", "TEXT"),
                ("mitre", "TEXT"),
                ("severity", "TEXT"),
                ("status", "TEXT DEFAULT 'UNREVIEWED'"),
                ("campaign_id", "INTEGER"),
                ("proof", "TEXT")
            ]
            
            for col_name, col_type in findings_migrations:
                if col_name not in findings_cols:
                    try:
                        cursor.execute(f"ALTER TABLE findings ADD COLUMN {col_name} {col_type}")
                    except sqlite3.OperationalError:
                        pass # Safety

            # Migration logic for targets table (Fix for status column crash)
            cursor.execute("PRAGMA table_info(targets)")
            targets_cols = [column[1] for column in cursor.fetchall()]
            
            if "status" not in targets_cols:
                try:
                    cursor.execute("ALTER TABLE targets ADD COLUMN status TEXT DEFAULT 'ACTIVE'")
                except sqlite3.OperationalError:
                    pass
            
            conn.commit()

    def normalize_target(self, value):
        """Universal normalization: strips protocol, www, and trailing slashes."""
        if not value: return ""
        v = str(value).lower().strip()
        if "://" in v:
            v = v.split("://")[-1]
        v = v.replace("www.", "")
        v = v.split("/")[0] # Keep only domain part
        return v.rstrip("/")

    def save_target(self, target_data):
        """Saves or updates a target in the database. Normalizes value to prevent fragmentation."""
        now = datetime.now().isoformat()
        raw_val = target_data.get("target") or target_data.get("value")
        val = self.normalize_target(raw_val)
        status = target_data.get("status", "ACTIVE")
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO targets (value, type, source, risk_score, priority, first_seen, last_seen, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(value) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    risk_score = MAX(risk_score, excluded.risk_score),
                    status = excluded.status,
                    priority = CASE 
                        WHEN excluded.priority = 'CRITICAL' THEN 'CRITICAL'
                        WHEN targets.priority = 'CRITICAL' THEN 'CRITICAL'
                        WHEN excluded.priority = 'HIGH' THEN 'HIGH'
                        WHEN targets.priority = 'HIGH' THEN 'HIGH'
                        ELSE excluded.priority
                    END
            ''', (
                val, 
                target_data.get("type", "unknown"),
                target_data.get("source", "manual"),
                target_data.get("risk_score", 0),
                target_data.get("priority", "LOW"),
                now, now, status
            ))
            conn.commit()
            return cursor.lastrowid

    def log_action(self, action: str, target: str, details: str = "", campaign_id: int = None):
        """Logs an operational action for audit compliance."""
        now = datetime.now().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO audit_log (timestamp, action, target, details, campaign_id)
                VALUES (?, ?, ?, ?, ?)
            ''', (now, action, target, details, campaign_id))
            conn.commit()

    def create_campaign(self, name: str, target_config: dict = None):
        """Creates a new mission campaign."""
        now = datetime.now().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO campaigns (name, target_config, created_at)
                VALUES (?, ?, ?)
            ''', (name, json.dumps(target_config or {}), now))
            conn.commit()
            return cursor.lastrowid

    def add_finding(self, target_value, content, finding_type, campaign_id=None, proof=None):
        """Adds a finding linked to a target value, preventing duplicates and normalizing targets."""
        now = datetime.now().isoformat()
        # Universal Normalization
        norm_val = self.normalize_target(target_value)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Find target ID - use normalized value
            cursor.execute("SELECT id FROM targets WHERE value = ?", (norm_val,))
            row = cursor.fetchone()
            if not row:
                # If target doesn't exist, create it using normalized value
                target_id = self.save_target({"target": norm_val, "type": "Domain", "risk_score": 0})
            else:
                target_id = row[0]
            
            # Check for existing identical finding in this campaign to prevent inflation
            if campaign_id:
                cursor.execute('''
                    SELECT id FROM findings 
                    WHERE target_id = ? AND content = ? AND finding_type = ? AND campaign_id = ?
                ''', (target_id, content, finding_type, campaign_id))
            else:
                cursor.execute('''
                    SELECT id FROM findings 
                    WHERE target_id = ? AND content = ? AND finding_type = ? AND campaign_id IS NULL
                ''', (target_id, content, finding_type))
            
            existing = cursor.fetchone()
            if existing:
                # Update timestamp on existing finding instead of creating a duplicate
                cursor.execute("UPDATE findings SET created_at = ? WHERE id = ?", (now, existing[0]))
            else:
                cursor.execute('''
                    INSERT INTO findings (target_id, content, finding_type, created_at, owasp, mitre, severity, status, campaign_id, proof)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (target_id, content, finding_type, now, "None", "None", "MEDIUM", "UNREVIEWED", campaign_id, proof))
            conn.commit()

    def update_finding_metadata(self, target_value, content, severity):
        """Updates the severity of a specific finding."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE findings 
                SET severity = ? 
                WHERE target_id = (SELECT id FROM targets WHERE value = ?) 
                AND content = ?
            ''', (severity, target_value, content))
            conn.commit()

    def get_audit_logs(self, campaign_id: int = None):
        """Retrieves audit logs, optionally filtered by campaign."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            if campaign_id:
                cursor.execute("SELECT * FROM audit_log WHERE campaign_id = ? ORDER BY timestamp DESC", (campaign_id,))
            else:
                cursor.execute("SELECT * FROM audit_log ORDER BY timestamp DESC")
            return [dict(row) for row in cursor.fetchall()]

    def update_finding_status(self, finding_id: int, status: str):
        """Updates the triage status of a specific finding."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE findings SET status = ? WHERE id = ?", (status, finding_id))
            conn.commit()
            return cursor.rowcount > 0

    def get_battle_plan(self):
        """Retrieves high-risk targets for the Battle Plan."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM targets WHERE risk_score > 0 ORDER BY risk_score DESC")
            return [dict(row) for row in cursor.fetchall()]

    def get_target_by_id(self, target_id):
        """Retrieves a single target by its DB ID."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM targets WHERE id = ?", (target_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_all_targets(self):
        """Retrieves all targets for the Nexus Intelligence Feed."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM targets ORDER BY id DESC")
            return [dict(row) for row in cursor.fetchall()]

    def get_all_findings(self):
        """Retrieves all findings for the Nexus overview."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM findings")
            return [dict(row) for row in cursor.fetchall()]
    def get_findings_by_target(self, target_value: str):
        """Retrieves all findings for a specific target value."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            # Find target ID first
            cursor.execute("SELECT id FROM targets WHERE value = ?", (target_value,))
            row = cursor.fetchone()
            if not row: return []
            
            cursor.execute("SELECT * FROM findings WHERE target_id = ?", (row["id"],))
            return [dict(row) for row in cursor.fetchall()]

    def get_osint_for_target(self, target_value: str):
        """Retrieves aggregated OSINT data from audit logs for a target."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            # Look for INTEL_GATHERED or similar intel-related actions
            cursor.execute('''
                SELECT details FROM audit_log 
                WHERE (target = ? OR target LIKE ?) 
                AND action = 'INTEL_GATHERED' 
                ORDER BY timestamp DESC
            ''', (target_value, f"%.{target_value}"))
            
            rows = cursor.fetchall()
            intel_summary = {}
            for row in rows:
                try:
                    # In newer versions, details might contain JSON
                    details = row["details"]
                    if details.startswith("{"):
                        data = json.loads(details)
                        intel_summary.update(data)
                    else:
                        # Fallback for older string-based logs
                        pass 
                except:
                    pass
            return intel_summary
