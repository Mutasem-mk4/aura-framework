"""
Aura v21.0 — Earnings Dashboard & Submission Tracker (D6)
Tracks every bug bounty submission lifecycle and calculates ROI.

Status flow: SUBMITTED → TRIAGED → ACCEPTED → PAID | REJECTED | DUPLICATE

Commands:
    aura earnings                  # See full dashboard
    aura earnings --program h1     # Filter by platform
    aura earnings log              # Log a new submission manually
"""
import os
import json
import sqlite3
from datetime import datetime, timezone
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console()

EARNINGS_DB = os.path.join(os.path.expanduser("~"), ".aura", "earnings.db")
os.makedirs(os.path.dirname(EARNINGS_DB), exist_ok=True)


class EarningsTracker:
    """
    D6: Financial tracking for bug bounty submissions.
    Maintains a SQLite database of submissions with full lifecycle tracking.
    """

    VALID_STATUSES = ["SUBMITTED", "TRIAGED", "ACCEPTED", "PAID", "REJECTED", "DUPLICATE", "NEEDS_MORE_INFO"]

    def __init__(self, db_path: str = None):
        self.db_path = db_path or EARNINGS_DB
        self._init_db()

    def _init_db(self):
        """Initialize the earnings database."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS submissions (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                program         TEXT NOT NULL,
                platform        TEXT NOT NULL DEFAULT 'intigriti',
                title           TEXT NOT NULL,
                finding_type    TEXT,
                severity        TEXT,
                cvss_score      REAL,
                target          TEXT,
                submitted_at    TEXT NOT NULL,
                status          TEXT NOT NULL DEFAULT 'SUBMITTED',
                triaged_at      TEXT,
                accepted_at     TEXT,
                paid_at         TEXT,
                amount_paid     REAL DEFAULT 0,
                currency        TEXT DEFAULT 'EUR',
                notes           TEXT,
                report_url      TEXT,
                hours_spent     REAL DEFAULT 0,
                scan_id         TEXT
            )
        """)
        conn.commit()
        conn.close()

    def log_submission(self, program: str, title: str, platform: str = "intigriti",
                       finding_type: str = "", severity: str = "MEDIUM",
                       cvss_score: float = 5.0, target: str = "",
                       hours_spent: float = 0.0, report_url: str = "",
                       notes: str = "", scan_id: str = "") -> int:
        """Logs a new submission. Returns the submission ID."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.execute("""
            INSERT INTO submissions
            (program, platform, title, finding_type, severity, cvss_score, target,
             submitted_at, status, hours_spent, report_url, notes, scan_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'SUBMITTED', ?, ?, ?, ?)
        """, (
            program, platform, title, finding_type, severity, cvss_score, target,
            datetime.now(timezone.utc).isoformat(),
            hours_spent, report_url, notes, scan_id
        ))
        sub_id = cur.lastrowid
        conn.commit()
        conn.close()
        console.print(f"[green][Earnings] Submission #{sub_id} logged: [{severity}] {title}[/green]")
        return sub_id

    def update_status(self, sub_id: int, status: str, amount: float = 0, currency: str = "EUR", notes: str = ""):
        """Updates the status of a submission."""
        if status not in self.VALID_STATUSES:
            console.print(f"[red]Invalid status: {status}. Must be one of {self.VALID_STATUSES}[/red]")
            return

        conn = sqlite3.connect(self.db_path)
        now = datetime.now(timezone.utc).isoformat()

        # Timestamp for each transition
        extra = {}
        if status == "TRIAGED":
            extra["triaged_at"] = now
        elif status == "ACCEPTED":
            extra["accepted_at"] = now
        elif status == "PAID":
            extra["paid_at"] = now
            extra["amount_paid"] = amount
            extra["currency"] = currency

        set_clause = ", ".join([f"{k} = ?" for k in extra.keys()])
        set_clause = f"status = ?, {set_clause}" if set_clause else "status = ?"
        values = [status] + list(extra.values())
        if notes:
            set_clause += ", notes = ?"
            values.append(notes)
        values.append(sub_id)

        conn.execute(f"UPDATE submissions SET {set_clause} WHERE id = ?", values)
        conn.commit()
        conn.close()
        console.print(f"[green][Earnings] Submission #{sub_id} updated to {status}[/green]")

    def get_all(self, platform: str = None) -> list[dict]:
        """Returns all submissions, optionally filtered by platform."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        query = "SELECT * FROM submissions"
        params = []
        if platform:
            query += " WHERE platform = ?"
            params.append(platform.lower())
        query += " ORDER BY submitted_at DESC"
        rows = conn.execute(query, params).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_stats(self) -> dict:
        """Returns aggregated financial statistics."""
        subs = self.get_all()
        total_paid = sum(s["amount_paid"] for s in subs if s["status"] == "PAID")
        total_hours = sum(s["hours_spent"] for s in subs if s["hours_spent"])
        accepted = [s for s in subs if s["status"] in ("ACCEPTED", "PAID")]
        paid = [s for s in subs if s["status"] == "PAID"]

        return {
            "total_submissions": len(subs),
            "accepted": len(accepted),
            "paid": len(paid),
            "rejected": len([s for s in subs if s["status"] == "REJECTED"]),
            "duplicate": len([s for s in subs if s["status"] == "DUPLICATE"]),
            "pending": len([s for s in subs if s["status"] in ("SUBMITTED", "TRIAGED", "NEEDS_MORE_INFO")]),
            "total_earned": total_paid,
            "total_hours": total_hours,
            "hourly_rate": round(total_paid / total_hours, 2) if total_hours > 0 else 0,
            "acceptance_rate": round(len(accepted) / max(len(subs), 1) * 100, 1),
            "avg_payout": round(total_paid / max(len(paid), 1), 2),
        }

    def print_dashboard(self, platform: str = None):
        """Prints the full earnings dashboard to the console."""
        stats = self.get_stats()
        subs = self.get_all(platform)

        # ── Stats Panel ──
        earned_str = f"€{stats['total_earned']:,.2f}"
        rate_str = f"€{stats['hourly_rate']}/hr" if stats['hourly_rate'] > 0 else "N/A"

        summary = (
            f"[bold green]Total Earned:[/bold green] {earned_str}  |  "
            f"[cyan]Submissions:[/cyan] {stats['total_submissions']}  |  "
            f"[green]Accepted:[/green] {stats['accepted']}  |  "
            f"[red]Rejected:[/red] {stats['rejected']}  |  "
            f"[yellow]Pending:[/yellow] {stats['pending']}\n"
            f"[bold cyan]Acceptance Rate:[/bold cyan] {stats['acceptance_rate']}%  |  "
            f"[bold]Avg Payout:[/bold] €{stats['avg_payout']}  |  "
            f"[bold]Hourly Rate:[/bold] {rate_str}"
        )
        console.print(Panel(summary, title="[bold yellow]AURA Earnings Dashboard[/bold yellow]", border_style="yellow"))

        if not subs:
            console.print("[dim]No submissions on record. Use `aura earnings log` to add one.[/dim]")
            return

        # ── Submissions Table ──
        table = Table(title="Submissions", show_header=True, header_style="bold cyan")
        table.add_column("#", style="dim", width=4)
        table.add_column("Program", width=16)
        table.add_column("Title", width=30)
        table.add_column("Sev", width=8)
        table.add_column("Status", width=12)
        table.add_column("Paid", width=10)
        table.add_column("Date", width=12)

        status_colors = {
            "PAID": "bold green", "ACCEPTED": "green",
            "TRIAGED": "cyan", "SUBMITTED": "white",
            "REJECTED": "red", "DUPLICATE": "dim red",
            "NEEDS_MORE_INFO": "yellow",
        }

        for s in subs[:30]:  # Show latest 30
            status = s["status"]
            color = status_colors.get(status, "white")
            paid_str = f"€{s['amount_paid']:,.0f}" if s["amount_paid"] > 0 else "-"
            date_str = s["submitted_at"][:10] if s["submitted_at"] else "-"
            title_short = s["title"][:28] + ".." if len(s["title"]) > 30 else s["title"]

            table.add_row(
                str(s["id"]),
                s["program"][:14],
                title_short,
                s.get("severity", "")[:6],
                f"[{color}]{status}[/{color}]",
                paid_str,
                date_str,
            )

        console.print(table)
