import sqlite3
import os
import json
from datetime import datetime
from aura.core.poc_generator import PoCSynthesizer

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

    def _get_connection(self):
        """v27.0: Returns a configured SQLite connection tailored for extreme concurrency (WAL mode)."""
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        # WAL mode permits concurrent read/write operations
        conn.execute('PRAGMA journal_mode=WAL;')
        # synchronous=NORMAL improves write performance significantly during heavy fuzzing
        conn.execute('PRAGMA synchronous=NORMAL;')
        return conn

    def _init_db(self):
        """Initializes the database schema with campaigns and audit logs."""
        with self._get_connection() as conn:
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
            
            # Table for v12.0 Operation Logs
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS operation_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME,
                    path TEXT,
                    payload TEXT,
                    status_code INTEGER
                )
            ''')

            # Table for v20.0 Sovereign Intelligence (Cross-Domain)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sovereign_intelligence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tech_stack TEXT,
                    vulnerability_type TEXT,
                    successful_payload TEXT,
                    success_rate REAL DEFAULT 1.0,
                    first_discovery DATETIME,
                    last_applied DATETIME,
                    UNIQUE(tech_stack, vulnerability_type, successful_payload)
                )
            ''')

            # Table for v20.0 Mission State (Self-Healing)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS mission_states (
                    target_value TEXT PRIMARY KEY,
                    current_step TEXT,
                    findings_count INTEGER DEFAULT 0,
                    urls_discovered INTEGER DEFAULT 0,
                    last_update DATETIME,
                    state_json TEXT
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
                ("proof", "TEXT"),
                ("evidence_url", "TEXT"),
                ("secret_type", "TEXT"),
                ("secret_value", "TEXT"),
                ("cvss_score", "REAL"),
                ("cvss_vector", "TEXT"),
                ("remediation_fix", "TEXT"),
                ("impact_desc", "TEXT"),
                ("patch_priority", "TEXT"),
                ("bounty_estimate", "TEXT"),
                ("platform_recommendation", "TEXT"),
                ("poc_link", "TEXT"),
                ("raw_request", "TEXT"),
                ("raw_response", "TEXT")
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

    def vacuum(self):
        """v32.0 Titan Memory Optimizer: Forces SQLite VACUUM to free disk space and memory locks."""
        try:
            with self._get_connection() as conn:
                conn.execute("VACUUM;")
        except Exception as e:
            pass

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
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO targets (value, type, source, risk_score, priority, first_seen, last_seen, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(value) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    risk_score = CASE 
                        WHEN excluded.status = 'BLOCKED' THEN MAX(risk_score, 15) -- Hardened targets are high priority
                        ELSE MAX(risk_score, excluded.risk_score)
                    END,
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
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO audit_log (timestamp, action, target, details, campaign_id)
                VALUES (?, ?, ?, ?, ?)
            ''', (now, action, target, details, campaign_id))
            conn.commit()

    def get_stats(self) -> dict:
        """v17.0: Quick stats for the Omni-Hub dashboard."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM findings")
                findings_count = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(DISTINCT domain) FROM findings")
                targets_count = cursor.fetchone()[0]
                return {"findings": findings_count, "targets": targets_count}
        except:
            return {"findings": 0, "targets": 0}

    def log_operation(self, path: str, payload: str, status_code: int):
        """v12.0 Hardcoded Execution: Logs a raw operation directly to the Operation Logs table."""
        now = datetime.now().isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO operation_logs (timestamp, path, payload, status_code)
                VALUES (?, ?, ?, ?)
            ''', (now, path, payload, status_code))
            conn.commit()

    def get_operation_logs(self):
        """Fetches all operation logs."""
        try:
            with self._get_connection() as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM operation_logs ORDER BY id DESC LIMIT 500')
                return [dict(row) for row in cursor.fetchall()]
        except:
            return []

    def create_campaign(self, name: str, target_config: dict = None):
        """Creates a new mission campaign."""
        now = datetime.now().isoformat()
        with self._get_connection() as conn:
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
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Find target ID - use normalized value
            cursor.execute("SELECT id FROM targets WHERE value = ?", (norm_val,))
            row = cursor.fetchone()
            if not row:
                # If target doesn't exist, create it using normalized value
                target_id = self.save_target({"target": norm_val, "type": "Domain", "risk_score": 0})
            else:
                target_id = row[0]
            
            content_str = content if isinstance(content, str) else __import__("json").dumps(content)
            
            # Check for existing identical finding in this campaign to prevent inflation
            if campaign_id:
                cursor.execute('''
                    SELECT id FROM findings 
                    WHERE target_id = ? AND content = ? AND finding_type = ? AND campaign_id = ?
                ''', (target_id, content_str, finding_type, campaign_id))
            else:
                cursor.execute('''
                    SELECT id FROM findings 
                    WHERE target_id = ? AND content = ? AND finding_type = ? AND campaign_id IS NULL
                ''', (target_id, content_str, finding_type))
            
            existing = cursor.fetchone()
            if existing:
                # Update timestamp on existing finding instead of creating a duplicate
                cursor.execute("UPDATE findings SET created_at = ? WHERE id = ?", (now, existing[0]))
            cursor.execute('''
                INSERT INTO findings (target_id, content, finding_type, created_at, owasp, mitre, severity, status, campaign_id, proof, cvss_score, cvss_vector, remediation_fix, impact_desc, patch_priority, evidence_url, secret_type, secret_value, poc_link, raw_request, raw_response)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                target_id, content_str, finding_type, now,
                getattr(content, 'get', lambda k: 'A00:2021-Unknown')('owasp') if isinstance(content, dict) else 'A00:2021-Unknown',
                getattr(content, 'get', lambda k: 'T1592')('mitre') if isinstance(content, dict) else 'T1592',
                getattr(content, 'get', lambda k: 'MEDIUM')('severity') if isinstance(content, dict) else 'MEDIUM',
                "UNREVIEWED",
                campaign_id,
                proof,
                getattr(content, 'get', lambda k: None)('cvss_score') if isinstance(content, dict) else None,
                getattr(content, 'get', lambda k: None)('cvss_vector') if isinstance(content, dict) else None,
                getattr(content, 'get', lambda k: None)('remediation_fix') if isinstance(content, dict) else None,
                getattr(content, 'get', lambda k: None)('impact_desc') if isinstance(content, dict) else None,
                getattr(content, 'get', lambda k: None)('patch_priority') if isinstance(content, dict) else None,
                getattr(content, 'get', lambda k: None)('evidence_url') if isinstance(content, dict) else None,
                getattr(content, 'get', lambda k: None)('secret_type') if isinstance(content, dict) else None,
                getattr(content, 'get', lambda k: None)('secret_value') if isinstance(content, dict) else None,
                getattr(content, 'get', lambda k: None)('poc_link') if isinstance(content, dict) else None,
                getattr(content, 'get', lambda k: None)('raw_request') if isinstance(content, dict) else None,
                getattr(content, 'get', lambda k: None)('raw_response') if isinstance(content, dict) else None
            ))
            
            # v17.0 The Zero-Rejection Engine: Automated PoC Synthesis
            if isinstance(content, dict) and 'url' in content and finding_type.lower() not in ['info disclosure', 'informative']:
                try:
                    from aura.core.poc_generator import PoCSynthesizer
                    poc_synth = PoCSynthesizer()
                    poc_synth.save_poc(content)
                except Exception as e:
                    pass
            
            conn.commit()

    def update_finding_metadata(self, target_value, content, severity):
        """Updates the severity of a specific finding."""
        content_str = content if isinstance(content, str) else __import__("json").dumps(content)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE findings 
                SET severity = ? 
                WHERE target_id = (SELECT id FROM targets WHERE value = ?) 
                AND content = ?
            ''', (severity, target_value, content_str))
            conn.commit()

    def get_audit_logs(self, campaign_id: int = None):
        """Retrieves audit logs, optionally filtered by campaign."""
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            if campaign_id:
                cursor.execute("SELECT * FROM audit_log WHERE campaign_id = ? ORDER BY timestamp DESC", (campaign_id,))
            else:
                cursor.execute("SELECT * FROM audit_log ORDER BY timestamp DESC")
            return [dict(row) for row in cursor.fetchall()]

    def update_finding_status(self, finding_id: int, status: str):
        """Updates the triage status of a specific finding."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE findings SET status = ? WHERE id = ?", (status, finding_id))
            conn.commit()
            return cursor.rowcount > 0

    def get_battle_plan(self):
        """Retrieves high-risk targets for the Battle Plan."""
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM targets WHERE risk_score > 0 ORDER BY risk_score DESC")
            return [dict(row) for row in cursor.fetchall()]

    def get_target_by_id(self, target_id):
        """Retrieves a single target by its DB ID."""
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM targets WHERE id = ?", (target_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_all_targets(self):
        """Retrieves all targets for the Nexus Intelligence Feed."""
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM targets ORDER BY id DESC")
            return [dict(row) for row in cursor.fetchall()]

    def is_target_scanned(self, target_value: str) -> bool:
        """v14.2: Checks if a target has already been scanned (COMPLETED status)."""
        norm_val = self.normalize_target(target_value)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT status FROM targets WHERE value = ?", (norm_val,))
            row = cursor.fetchone()
            if row and row[0] == 'COMPLETED':
                return True
            return False

    def get_all_findings(self):
        """Retrieves all findings for the Nexus overview."""
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM findings")
            return [dict(row) for row in cursor.fetchall()]
    def get_findings_by_target(self, target_value: str):
        """Retrieves all findings for a specific target value."""
        with self._get_connection() as conn:
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
        with self._get_connection() as conn:
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

    def save_mission_state(self, target_value: str, current_step: str, stats: dict, full_state: dict):
        """v20.0: Persist the current state of a mission for self-healing/resuming."""
        now = datetime.now().isoformat()
        norm_val = self.normalize_target(target_value)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO mission_states (target_value, current_step, findings_count, urls_discovered, last_update, state_json)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(target_value) DO UPDATE SET
                    current_step = excluded.current_step,
                    findings_count = excluded.findings_count,
                    urls_discovered = excluded.urls_discovered,
                    last_update = excluded.last_update,
                    state_json = excluded.state_json
            ''', (norm_val, current_step, stats.get("findings", 0), stats.get("urls", 0), now, json.dumps(full_state)))
            conn.commit()

    def get_mission_state(self, target_value: str) -> dict | None:
        """v20.0: Retrieve the persisted state for a target."""
        norm_val = self.normalize_target(target_value)
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM mission_states WHERE target_value = ?", (norm_val,))
            row = cursor.fetchone()
            if row:
                res = dict(row)
                res["state_json"] = json.loads(res["state_json"])
                return res
        return None

    def save_sovereign_intel(self, tech_stack: str, vuln_type: str, payload: str):
        """v20.0: Index a successful attack pattern for cross-domain reuse."""
        now = datetime.now().isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO sovereign_intelligence (tech_stack, vulnerability_type, successful_payload, first_discovery, last_applied)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(tech_stack, vulnerability_type, successful_payload) DO UPDATE SET
                    success_rate = success_rate + 0.1,
                    last_applied = excluded.last_applied
            ''', (tech_stack, vuln_type, payload, now, now))
            conn.commit()

    def get_sovereign_intel(self, tech_stack: str) -> list:
        """v20.0: Retrieve high-probability payloads for a detected tech stack."""
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            # Find intelligence that matches any part of the tech stack (e.g. "IIS" in "IIS/10.0")
            cursor.execute('''
                SELECT successful_payload, vulnerability_type, success_rate 
                FROM sovereign_intelligence 
                WHERE ? LIKE '%' || tech_stack || '%'
                ORDER BY success_rate DESC LIMIT 20
            ''', (tech_stack,))
            return [dict(row) for row in cursor.fetchall()]

    def sync_nexus_intel(self, peer_payload: dict):
        """
        v24.0: Nexus Synchronization (Infinisync).
        Merges intelligent findings from other swarms into the local database.
        """
        intel = peer_payload.get("sovereign_intelligence", [])
        for item in intel:
            self.save_sovereign_intel(
                item.get("tech_stack"),
                item.get("vulnerability_type"),
                item.get("successful_payload")
            )
        
        findings = peer_payload.get("findings", [])
        for f in findings:
            # Sync findings without re-triggering verification (confirmed=True)
            self.add_finding(
                f.get("target"),
                f.get("content"),
                f.get("finding_type"),
                proof=f.get("proof")
            )
        return True

    # v23.0: Alias — many modules call save_finding, which is add_finding
    save_finding = add_finding
