import sqlite3
import os
import json
from datetime import datetime
from aura.core.poc_generator import PoCSynthesizer

from sqlalchemy import create_engine, MetaData
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

class AuraStorage:
    """Persistent storage engine for Aura using SQLite or PostgreSQL (Swarm Mode)."""
    
    def __init__(self, db_path=None):
        self.db_url = os.getenv("DATABASE_URL")
        self.is_postgres = self.db_url and self.db_url.startswith("postgres")
        
        if self.is_postgres:
            # Swarm Mode: Connect to centralized PostgreSQL DB
            self.engine = create_engine(self.db_url, pool_size=20, max_overflow=0)
        else:
            # Standalone Mode: Fall back to local SQLite
            if db_path is None:
                project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                self.db_path = os.path.join(project_root, "aura_intel.db")
            else:
                self.db_path = os.path.abspath(db_path)
            self.engine = create_engine(f"sqlite:///{self.db_path}", poolclass=NullPool)
            
        self._init_db()

    def _get_connection(self):
        """v27.0: Returns a configured raw DBAPI connection tailored for extreme concurrency."""
        conn = self.engine.raw_connection()
        if not self.is_postgres:
            # WAL mode permits concurrent read/write operations on SQLite
            conn.execute('PRAGMA journal_mode=WAL;')
            conn.execute('PRAGMA synchronous=NORMAL;')
        return conn

    def _execute(self, cursor, query, params=None):
        """Abstraction for query parameters (? for sqlite, %s for postgres)."""
        if self.is_postgres and params:
            query = query.replace("?", "%s")
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)

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
            cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY {"" if self.is_postgres else "AUTOINCREMENT"},
                    timestamp TIMESTAMP,
                    action TEXT,
                    target TEXT,
                    details TEXT,
                    campaign_id INTEGER,
                    FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
                )
            ''')
            
            # Table for v12.0 Operation Logs
            cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS operation_logs (
                    id INTEGER PRIMARY KEY {"" if self.is_postgres else "AUTOINCREMENT"},
                    timestamp TIMESTAMP,
                    path TEXT,
                    payload TEXT,
                    status_code INTEGER
                )
            ''')

            # Table for v20.0 Sovereign Intelligence (Cross-Domain)
            self._execute(cursor, f'''
                CREATE TABLE IF NOT EXISTS sovereign_intelligence (
                    id INTEGER PRIMARY KEY {"" if self.is_postgres else "AUTOINCREMENT"},
                    tech_stack TEXT,
                    vulnerability_type TEXT,
                    successful_payload TEXT,
                    success_rate REAL DEFAULT 1.0,
                    first_discovery TIMESTAMP,
                    last_applied TIMESTAMP,
                    UNIQUE(tech_stack, vulnerability_type, successful_payload)
                )
            ''')

            # Table for v20.0 Mission State (Self-Healing)
            self._execute(cursor, '''
                CREATE TABLE IF NOT EXISTS mission_states (
                    target_value TEXT PRIMARY KEY,
                    current_step TEXT,
                    findings_count INTEGER DEFAULT 0,
                    urls_discovered INTEGER DEFAULT 0,
                    last_update TIMESTAMP,
                    state_json TEXT
                )
            ''')
            
            # Migration logic for findings table
            if not self.is_postgres:
                self._execute(cursor, "PRAGMA table_info(findings)")
                findings_cols = [column[1] for column in cursor.fetchall()]
            else:
                self._execute(cursor, "SELECT column_name FROM information_schema.columns WHERE table_name='findings'")
                findings_cols = [column[0] for column in cursor.fetchall()]

            findings_migrations = [
                ("finding_type", "TEXT"),
                ("created_at", "TIMESTAMP"),
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
                        self._execute(cursor, f"ALTER TABLE findings ADD COLUMN {col_name} {col_type}")
                    except Exception:
                        pass # Safety

            # Migration logic for targets table (Fix for status column crash)
            if not self.is_postgres:
                self._execute(cursor, "PRAGMA table_info(targets)")
                targets_cols = [column[1] for column in cursor.fetchall()]
            else:
                self._execute(cursor, "SELECT column_name FROM information_schema.columns WHERE table_name='targets'")
                targets_cols = [column[0] for column in cursor.fetchall()]
            
            if "status" not in targets_cols:
                try:
                    self._execute(cursor, "ALTER TABLE targets ADD COLUMN status TEXT DEFAULT 'ACTIVE'")
                except Exception:
                    pass
            
            conn.commit()

    def vacuum(self):
        """v32.0 Titan Memory Optimizer: Forces SQLite VACUUM to free disk space and memory locks."""
        if self.is_postgres:
            return  # Autovacuum handles Postgres
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
            self._execute(cursor, '''
                INSERT INTO targets (value, type, source, risk_score, priority, first_seen, last_seen, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(value) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    risk_score = CASE 
                        WHEN excluded.status = 'BLOCKED' THEN MAX(targets.risk_score, 15)
                        ELSE MAX(targets.risk_score, excluded.risk_score)
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
            if not self.is_postgres:
                return cursor.lastrowid
            else:
                self._execute(cursor, "SELECT id FROM targets WHERE value = ?", (val,))
                return cursor.fetchone()[0]

    def log_action(self, action: str, target: str, details: str = "", campaign_id: int = None):
        """Logs an operational action for audit compliance."""
        now = datetime.now().isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            self._execute(cursor, '''
                INSERT INTO audit_log (timestamp, action, target, details, campaign_id)
                VALUES (?, ?, ?, ?, ?)
            ''', (now, action, target, details, campaign_id))
            conn.commit()

    def get_stats(self) -> dict:
        """v17.0: Quick stats for the Omni-Hub dashboard."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                self._execute(cursor, "SELECT COUNT(*) FROM findings")
                findings_count = cursor.fetchone()[0]
                
                # Postgres vs SQLite distinction for JSON matching
                if self.is_postgres:
                    # In postgres, content isn't a direct domain map usually extracted like this, but 
                    # we can fallback safely to simple count.
                    targets_count = 0 
                else:
                    self._execute(cursor, "SELECT COUNT(DISTINCT 1) FROM findings")
                    targets_count = cursor.fetchone()[0]
                return {"findings": findings_count, "targets": targets_count}
        except:
            return {"findings": 0, "targets": 0}

    def log_operation(self, path: str, payload: str, status_code: int):
        """v12.0 Hardcoded Execution: Logs a raw operation directly to the Operation Logs table."""
        now = datetime.now().isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            self._execute(cursor, '''
                INSERT INTO operation_logs (timestamp, path, payload, status_code)
                VALUES (?, ?, ?, ?)
            ''', (now, path, payload, status_code))
            conn.commit()

    def _to_dict(self, cursor, row):
        """v25.0 OMEGA: Centrally converts a database row to a dictionary using column/row zipping."""
        if row is None: return None
        columns = [col[0] for col in cursor.description]
        return dict(zip(columns, row))

    def _to_list(self, cursor):
        """v25.0 OMEGA: Centrally converts all database rows to a list of dictionaries."""
        columns = [col[0] for col in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def get_operation_logs(self):
        """Fetches all operation logs."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                self._execute(cursor, 'SELECT * FROM operation_logs ORDER BY id DESC LIMIT 500')
                return self._to_list(cursor)
        except:
            return []

    def create_campaign(self, name: str, target_config: dict = None):
        """Creates a new mission campaign."""
        now = datetime.now().isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            self._execute(cursor, '''
                INSERT INTO campaigns (name, target_config, created_at)
                VALUES (?, ?, ?)
            ''', (name, json.dumps(target_config or {}), now))
            conn.commit()
            if not self.is_postgres:
                return cursor.lastrowid
            else:
                self._execute(cursor, "SELECT id FROM campaigns WHERE name = ? ORDER BY id DESC LIMIT 1", (name,))
                return cursor.fetchone()[0]

    def add_finding(self, target_value, content, finding_type="Vulnerability", campaign_id=None, proof=None, **kwargs):
        """
        Adds a finding linked to a target value, preventing duplicates and normalizing targets.
        v33.0 Zenith Update: Added **kwargs and default finding_type for extreme stability.
        """
        now = datetime.now().isoformat()
        
        # If finding_type was passed as a kwarg or shifted, try to recover it
        if not finding_type and "type" in kwargs:
            finding_type = kwargs["type"]
        elif not finding_type:
            finding_type = "Vulnerability"

        # Universal Normalization
        norm_val = self.normalize_target(target_value)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Find target ID - use normalized value
            self._execute(cursor, "SELECT id FROM targets WHERE value = ?", (norm_val,))
            row = cursor.fetchone()
            if not row:
                # If target doesn't exist, create it using normalized value
                target_id = self.save_target({"target": norm_val, "type": "Domain", "risk_score": 0})
            else:
                target_id = row[0]
            
            content_str = content if isinstance(content, str) else __import__("json").dumps(content)
            
            # Check for existing identical finding in this campaign to prevent inflation
            if campaign_id:
                self._execute(cursor, '''
                    SELECT id FROM findings 
                    WHERE target_id = ? AND content = ? AND finding_type = ? AND campaign_id = ?
                ''', (target_id, content_str, finding_type, campaign_id))
            else:
                if self.is_postgres:
                    self._execute(cursor, '''
                        SELECT id FROM findings 
                        WHERE target_id = ? AND content = ? AND finding_type = ? AND campaign_id IS NULL
                    ''', (target_id, content_str, finding_type))
                else:
                    self._execute(cursor, '''
                        SELECT id FROM findings 
                        WHERE target_id = ? AND content = ? AND finding_type = ? AND campaign_id IS NULL
                    ''', (target_id, content_str, finding_type))
            
            existing = cursor.fetchone()
            if existing:
                # Update timestamp on existing finding instead of creating a duplicate
                self._execute(cursor, "UPDATE findings SET created_at = ? WHERE id = ?", (now, existing[0]))
                conn.commit()
                return

            # Prepare metadata from content or kwargs
            owasp = kwargs.get("owasp") or (content.get("owasp") if isinstance(content, dict) else "A00:2021-Unknown")
            mitre = kwargs.get("mitre") or (content.get("mitre") if isinstance(content, dict) else "T1592")
            severity = kwargs.get("severity") or (content.get("severity") if isinstance(content, dict) else "MEDIUM")
            
            self._execute(cursor, '''
                INSERT INTO findings (
                    target_id, content, finding_type, created_at, owasp, mitre, severity, status, 
                    campaign_id, proof, cvss_score, cvss_vector, remediation_fix, impact_desc, 
                    patch_priority, evidence_url, secret_type, secret_value, poc_link, raw_request, raw_response
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                target_id, content_str, finding_type, now,
                owasp, mitre, severity,
                "UNREVIEWED",
                campaign_id,
                proof or kwargs.get("proof"),
                kwargs.get("cvss_score") or (content.get("cvss_score") if isinstance(content, dict) else None),
                kwargs.get("cvss_vector") or (content.get("cvss_vector") if isinstance(content, dict) else None),
                kwargs.get("remediation_fix") or (content.get("remediation_fix") if isinstance(content, dict) else None),
                kwargs.get("impact_desc") or (content.get("impact_desc") if isinstance(content, dict) else None),
                kwargs.get("patch_priority") or (content.get("patch_priority") if isinstance(content, dict) else None),
                kwargs.get("evidence_url") or (content.get("evidence_url") if isinstance(content, dict) else None),
                kwargs.get("secret_type") or (content.get("secret_type") if isinstance(content, dict) else None),
                kwargs.get("secret_value") or (content.get("secret_value") if isinstance(content, dict) else None),
                kwargs.get("poc_link") or (content.get("poc_link") if isinstance(content, dict) else None),
                kwargs.get("raw_request") or (content.get("raw_request") if isinstance(content, dict) else None),
                kwargs.get("raw_response") or (content.get("raw_response") if isinstance(content, dict) else None)
            ))
            
            # v17.0 The Zero-Rejection Engine: Automated PoC Synthesis
            if isinstance(content, dict) and 'url' in content and finding_type.lower() not in ['info disclosure', 'informative']:
                try:
                    from aura.core.poc_generator import PoCSynthesizer
                    poc_synth = PoCSynthesizer()
                    poc_synth.save_poc(content)
                except Exception:
                    pass
            
            conn.commit()

    def update_finding_metadata(self, target_value, content, severity):
        """Updates the severity of a specific finding."""
        content_str = content if isinstance(content, str) else __import__("json").dumps(content)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            self._execute(cursor, '''
                UPDATE findings 
                SET severity = ? 
                WHERE target_id = (SELECT id FROM targets WHERE value = ?) 
                AND content = ?
            ''', (severity, target_value, content_str))
            conn.commit()

    def get_audit_logs(self, campaign_id: int = None):
        """Retrieves audit logs, optionally filtered by campaign."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if campaign_id:
                self._execute(cursor, "SELECT * FROM audit_log WHERE campaign_id = ? ORDER BY timestamp DESC", (campaign_id,))
            else:
                self._execute(cursor, "SELECT * FROM audit_log ORDER BY timestamp DESC")
            return self._to_list(cursor)

    def update_finding_status(self, finding_id: int, status: str):
        """Updates the triage status of a specific finding."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            self._execute(cursor, "UPDATE findings SET status = ? WHERE id = ?", (status, finding_id))
            conn.commit()
            return cursor.rowcount > 0

    def get_battle_plan(self):
        """Retrieves high-risk targets for the Battle Plan."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            self._execute(cursor, "SELECT * FROM targets WHERE risk_score > 0 ORDER BY risk_score DESC")
            return self._to_list(cursor)

    def get_target_by_id(self, target_id):
        """Retrieves a single target by its DB ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            self._execute(cursor, "SELECT * FROM targets WHERE id = ?", (target_id,))
            return self._to_dict(cursor, cursor.fetchone())

    def get_all_targets(self):
        """Retrieves all targets for the Nexus Intelligence Feed."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            self._execute(cursor, "SELECT * FROM targets ORDER BY id DESC")
            return self._to_list(cursor)

    def is_target_scanned(self, target_value: str) -> bool:
        """v14.2: Checks if a target has already been scanned (COMPLETED status)."""
        norm_val = self.normalize_target(target_value)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            self._execute(cursor, "SELECT status FROM targets WHERE value = ?", (norm_val,))
            row = cursor.fetchone()
            if row and row[0] == 'COMPLETED':
                return True
            return False

    def get_all_findings(self):
        """Retrieves all findings for the Nexus overview."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            self._execute(cursor, "SELECT * FROM findings")
            return self._to_list(cursor)
            
    def get_findings_by_target(self, target_value: str):
        """Retrieves all findings for a specific target value."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Find target ID first
            self._execute(cursor, "SELECT id FROM targets WHERE value = ?", (target_value,))
            row = cursor.fetchone()
            if not row: return []
            
            target_id = row[0]
            
            self._execute(cursor, "SELECT * FROM findings WHERE target_id = ?", (target_id,))
            return self._to_list(cursor)

    def get_osint_for_target(self, target_value: str):
        """Retrieves aggregated OSINT data from audit logs for a target."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Look for INTEL_GATHERED or similar intel-related actions
            self._execute(cursor, '''
                SELECT details FROM audit_log 
                WHERE (target = ? OR target LIKE ?) 
                AND action = 'INTEL_GATHERED' 
                ORDER BY timestamp DESC
            ''', (target_value, f"%.{target_value}"))
            
            rows = cursor.fetchall()
            intel_summary = {}
            for row in rows:
                try:
                    # Handle Tuple accessing after removing Row factory
                    details = row[0]
                    if details.startswith("{"):
                        data = json.loads(details)
                        intel_summary.update(data)
                except:
                    pass
            return intel_summary

    def save_mission_state(self, target_value: str, current_step: str, stats: dict, full_state: dict):
        """v20.0: Persist the current state of a mission for self-healing/resuming."""
        now = datetime.now().isoformat()
        norm_val = self.normalize_target(target_value)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            self._execute(cursor, '''
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
            cursor = conn.cursor()
            self._execute(cursor, "SELECT * FROM mission_states WHERE target_value = ?", (norm_val,))
            row = cursor.fetchone()
            if row:
                res = self._to_dict(cursor, row)
                res["state_json"] = json.loads(res["state_json"])
                return res
        return None

    def save_sovereign_intel(self, tech_stack: str, vuln_type: str, payload: str):
        """v20.0: Index a successful attack pattern for cross-domain reuse."""
        now = datetime.now().isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            self._execute(cursor, '''
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
            cursor = conn.cursor()
            # Find intelligence that matches any part of the tech stack (e.g. "IIS" in "IIS/10.0")
            
            # PostgreSQL requires slightly different LIKE syntax mapping vs SQLite mapped params
            if self.is_postgres:
                self._execute(cursor, '''
                    SELECT successful_payload, vulnerability_type, success_rate 
                    FROM sovereign_intelligence 
                    WHERE tech_stack LIKE '%%' || %s || '%%'
                    ORDER BY success_rate DESC LIMIT 20
                ''', (tech_stack,))
            else:
                self._execute(cursor, '''
                    SELECT successful_payload, vulnerability_type, success_rate 
                    FROM sovereign_intelligence 
                    WHERE ? LIKE '%' || tech_stack || '%'
                    ORDER BY success_rate DESC LIMIT 20
                ''', (tech_stack,))
            
            return self._to_list(cursor)


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
