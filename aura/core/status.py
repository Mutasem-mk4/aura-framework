"""
Aura v22.0 — Status Dashboard (UX Supercharge Step 3)
One-panel view of everything: last scan, earnings, API health, queue.

Usage:
    aura status
"""
import os
import sqlite3
from datetime import datetime, timezone
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.columns import Columns

from aura.ui.formatter import console


def _check_token(token: str, service: str) -> str:
    """Quick check — does the token exist?"""
    if not token or token.strip() == "":
        return "[red]❌ Not configured[/red]"
    return "[green]✅ Configured[/green]"


def get_db_path() -> str:
    """Finds the Aura DB path."""
    try:
        from aura.core.storage import AuraStorage
        return AuraStorage().db_path
    except Exception:
        return os.path.join(os.getcwd(), "aura_db.sqlite")


def get_last_scan_info(db_path: str) -> dict:
    """Returns info about the most recent scan target."""
    info = {"target": None, "time": None, "findings": 0, "status": ""}
    try:
        conn = sqlite3.connect(db_path)
        row = conn.execute(
            "SELECT value, last_seen FROM targets ORDER BY last_seen DESC LIMIT 1"
        ).fetchone()
        if row:
            info["target"] = row[0]
            info["time"]   = row[1]

        # Count findings for that target
        if info["target"]:
            count = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE target = ?",
                (info["target"],)
            ).fetchone()
            info["findings"] = count[0] if count else 0
        conn.close()
    except Exception:
        pass
    return info


def get_earnings_summary(db_path: str) -> dict:
    """Returns MTD earnings summary from earnings.db."""
    summary = {"total_paid": 0.0, "pending": 0, "accepted": 0, "total_submitted": 0}
    earnings_db = os.path.join(os.path.dirname(db_path), "earnings.db")
    if not os.path.exists(earnings_db):
        return summary
    try:
        conn = sqlite3.connect(earnings_db)
        # MTD paid
        now   = datetime.now(timezone.utc)
        month = now.strftime("%Y-%m")
        row   = conn.execute(
            "SELECT SUM(amount_paid) FROM submissions WHERE status='PAID' AND submitted_at LIKE ?",
            (f"{month}%",)
        ).fetchone()
        summary["total_paid"] = round(row[0] or 0.0, 2)

        # Counts
        for status, key in [("SUBMITTED", "pending"), ("TRIAGED", "pending"),
                             ("ACCEPTED", "accepted")]:
            r = conn.execute("SELECT COUNT(*) FROM submissions WHERE status=?", (status,)).fetchone()
            summary[key] += (r[0] or 0)

        # Total ever submitted
        r = conn.execute("SELECT COUNT(*) FROM submissions").fetchone()
        summary["total_submitted"] = r[0] or 0
        conn.close()
    except Exception:
        pass
    return summary


def show_status():
    """Renders the full Aura Status Dashboard."""
    try:
        from aura.core.config import cfg
    except Exception:
        class _Cfg:
            intigriti_token = ""
            hackerone_token = ""
            default_platform = "intigriti"
            notify_telegram = False
        cfg = _Cfg()

    db_path  = get_db_path()
    scan     = get_last_scan_info(db_path)
    earnings = get_earnings_summary(db_path)
    now      = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # ── Last Scan ──
    if scan["target"]:
        scan_line = f"[bold]{scan['target']}[/bold] — {scan['findings']} finding(s)"
        if scan["time"]:
            scan_line += f" | [dim]{scan['time'][:16]}[/dim]"
    else:
        scan_line = "[dim]No scans yet — run: aura hunt target.com[/dim]"

    # ── Earnings ──
    paid_line = (
        f"[bold green]${earnings['total_paid']:,.2f}[/bold green] this month  "
        f"| {earnings['pending']} pending | {earnings['accepted']} accepted "
        f"| {earnings['total_submitted']} total submitted"
    )

    # ── API Status ──
    inti_status = _check_token(cfg.intigriti_token, "Intigriti")
    h1_status   = _check_token(cfg.hackerone_token, "HackerOne")
    tg_status   = "[green]✅ Enabled[/green]" if cfg.notify_telegram else "[dim]Disabled[/dim]"

    # ── Config line ──
    config_line = (
        f"Platform: [cyan]{cfg.default_platform}[/cyan]  "
        f"| Auto-submit: {'[green]ON[/green]' if cfg.auto_submit else '[dim]OFF[/dim]'}  "
        f"| Screenshot: {'[green]ON[/green]' if cfg.auto_screenshot else '[dim]OFF[/dim]'}"
    )

    body = (
        f"[bold yellow]⏱  Last Scan:[/bold yellow]  {scan_line}\n"
        f"[bold yellow]💰 Earnings:[/bold yellow]   {paid_line}\n\n"
        f"[bold yellow]🔐 Intigriti:[/bold yellow]  {inti_status}\n"
        f"[bold yellow]🔐 HackerOne:[/bold yellow]  {h1_status}\n"
        f"[bold yellow]🔔 Telegram:[/bold yellow]   {tg_status}\n\n"
        f"[bold yellow]⚙️  Config:[/bold yellow]    {config_line}\n"
    )

    console.print(Panel(
        body,
        title=f"[bold cyan]AURA STATUS — {now}[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    ))

    # ── Quick Commands ──
    console.print(
        "[dim]Run [cyan]aura setup[/cyan] to configure  "
        "| [cyan]aura programs[/cyan] to find targets  "
        "| [cyan]aura earnings[/cyan] for full dashboard[/dim]"
    )
