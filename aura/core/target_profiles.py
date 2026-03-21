"""
Aura v22.0 — Target Profiles (UX Supercharge Step 4)
Save and load named hunting configurations.

Usage:
    aura target save ubisoft --url ubisoft.com --platform intigriti --program ubisoft
    aura target list
    aura hunt @ubisoft       # loads all saved settings

Profiles are stored in the Aura SQLite DB.
"""
import json
import os
import sqlite3
from datetime import datetime, timezone
from rich.console import Console
from rich.table import Table

from aura.ui.formatter import console

# Profile DB — stored alongside Aura's main DB
PROFILES_DB = os.path.join(os.path.expanduser("~"), ".aura_profiles.db")


class TargetProfiles:
    """Manages named target + platform + program + option profiles."""

    def __init__(self):
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(PROFILES_DB)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS profiles (
                name        TEXT PRIMARY KEY,
                url         TEXT NOT NULL,
                platform    TEXT NOT NULL DEFAULT 'intigriti',
                program     TEXT NOT NULL DEFAULT '',
                concurrency INTEGER DEFAULT 5,
                auto_submit INTEGER DEFAULT 0,
                options     TEXT DEFAULT '{}',
                created_at  TEXT,
                last_used   TEXT
            )
        """)
        conn.commit()
        conn.close()

    def save(self, name: str, url: str, platform: str = "intigriti",
             program: str = "", concurrency: int = 5, auto_submit: bool = False,
             **extra_options) -> None:
        """Saves or updates a named profile."""
        name = name.lstrip("@")
        now  = datetime.now(timezone.utc).isoformat()
        opts = json.dumps(extra_options)
        conn = sqlite3.connect(PROFILES_DB)
        conn.execute("""
            INSERT INTO profiles (name, url, platform, program, concurrency, auto_submit, options, created_at, last_used)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                url=excluded.url, platform=excluded.platform,
                program=excluded.program, concurrency=excluded.concurrency,
                auto_submit=excluded.auto_submit, options=excluded.options,
                last_used=excluded.last_used
        """, (name, url, platform, program, concurrency, int(auto_submit), opts, now, now))
        conn.commit()
        conn.close()
        console.print(f"[green][Profiles] Saved profile '@{name}' -> {url} [{platform}][/green]")

    def get(self, name: str) -> dict | None:
        """Returns a profile dict or None if not found."""
        name = name.lstrip("@")
        conn = sqlite3.connect(PROFILES_DB)
        row  = conn.execute(
            "SELECT name,url,platform,program,concurrency,auto_submit,options FROM profiles WHERE name=?",
            (name,)
        ).fetchone()
        # Update last_used
        if row:
            conn.execute("UPDATE profiles SET last_used=? WHERE name=?",
                         (datetime.now(timezone.utc).isoformat(), name))
            conn.commit()
        conn.close()
        if not row:
            return None
        extra = json.loads(row[6] or "{}")
        return {
            "name":         row[0],
            "url":          row[1],
            "platform":     row[2],
            "program":      row[3],
            "concurrency":  row[4],
            "auto_submit":  bool(row[5]),
            **extra,
        }

    def list_all(self) -> list[dict]:
        """Returns all saved profiles."""
        conn = sqlite3.connect(PROFILES_DB)
        rows = conn.execute(
            "SELECT name,url,platform,program,concurrency,auto_submit,last_used FROM profiles ORDER BY last_used DESC"
        ).fetchall()
        conn.close()
        return [
            {"name": r[0], "url": r[1], "platform": r[2],
             "program": r[3], "concurrency": r[4], "auto_submit": bool(r[5]),
             "last_used": r[6]}
            for r in rows
        ]

    def delete(self, name: str) -> bool:
        """Deletes a profile. Returns True if found and deleted."""
        name = name.lstrip("@")
        conn = sqlite3.connect(PROFILES_DB)
        cur  = conn.execute("DELETE FROM profiles WHERE name=?", (name,))
        conn.commit()
        conn.close()
        if cur.rowcount > 0:
            console.print(f"[yellow][Profiles] Deleted profile '@{name}'[/yellow]")
            return True
        console.print(f"[red][Profiles] Profile '@{name}' not found[/red]")
        return False

    def print_table(self):
        """Prints all profiles as a Rich table."""
        profiles = self.list_all()
        if not profiles:
            console.print("[yellow][Profiles] No saved profiles. Use: aura target save <name> --url <url>[/yellow]")
            return

        table = Table(title="🎯 Saved Target Profiles", header_style="bold cyan", show_lines=True)
        table.add_column("Name",        style="bold yellow", width=14)
        table.add_column("URL",         width=25)
        table.add_column("Platform",    width=12)
        table.add_column("Program",     width=14)
        table.add_column("Concurrency", width=5, justify="center")
        table.add_column("Auto-Submit", width=7, justify="center")
        table.add_column("Last Used",   width=18)

        for p in profiles:
            sub_str = "[green]ON[/green]" if p["auto_submit"] else "[dim]OFF[/dim]"
            last    = (p.get("last_used") or "")[:16]
            table.add_row(
                f"@{p['name']}", p["url"], p["platform"],
                p["program"] or "[dim]—[/dim]",
                str(p["concurrency"]), sub_str, last,
            )
        console.print(table)
        console.print("[dim]Use: aura hunt @name  to run a saved profile[/dim]")
