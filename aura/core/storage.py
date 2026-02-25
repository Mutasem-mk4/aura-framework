import sqlite3
import os
import json
from datetime import datetime

class AuraStorage:
    """Persistent storage engine for Aura using SQLite."""
    
    def __init__(self, db_path="aura_intel.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initializes the database schema."""
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
                    priority TEXT,
                    first_seen DATETIME,
                    last_seen DATETIME
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
                    FOREIGN KEY (target_id) REFERENCES targets(id)
                )
            ''')
            
            conn.commit()

    def save_target(self, target_data):
        """Saves or updates a target in the database."""
        now = datetime.now().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO targets (value, type, source, risk_score, priority, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(value) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    risk_score = excluded.risk_score,
                    priority = excluded.priority
            ''', (
                target_data["target"], 
                target_data.get("type", "unknown"),
                target_data.get("source", "manual"),
                target_data.get("risk_score", 0),
                target_data.get("priority", "LOW"),
                now, now
            ))
            conn.commit()
            return cursor.lastrowid

    def add_finding(self, target_value, content, finding_type):
        """Adds a finding linked to a target value."""
        now = datetime.now().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            # Find target ID
            cursor.execute("SELECT id FROM targets WHERE value = ?", (target_value,))
            row = cursor.fetchone()
            if not row:
                target_id = self.save_target({"target": target_value})
            else:
                target_id = row[0]
                
            cursor.execute('''
                INSERT INTO findings (target_id, content, finding_type, created_at)
                VALUES (?, ?, ?, ?)
            ''', (target_id, content, finding_type, now))
            conn.commit()

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

    def get_findings_by_target(self, target_value):
        """Retrieves findings associated with a specific target value."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            # Join with targets table to be sure
            cursor.execute('''
                SELECT findings.* FROM findings
                JOIN targets ON findings.target_id = targets.id
                WHERE targets.value = ?
            ''', (target_value,))
            return [dict(row) for row in cursor.fetchall()]
