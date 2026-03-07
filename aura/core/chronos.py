"""
Aura v27.0 — The Chronos Protocol ⏳🛰️
=========================================
Transforms Aura from a one-shot scanner into a persistent, autonomous
monitoring entity. Chronos continuously watches the attack surface of a target,
detects changes (new subdomains, new JS, new endpoints), and automatically
triggers a Turbine deep scan when changes are found.

Usage:
    aura chronos <target>              — Start monitoring a target
    aura chronos <target> --interval 3600   — Custom check interval (seconds)
"""
import asyncio
import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Optional

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

console = Console()

# --- Chronos State Storage ---
CHRONOS_STATE_FILE = "chronos_state.json"

def _load_state() -> dict:
    if os.path.exists(CHRONOS_STATE_FILE):
        try:
            with open(CHRONOS_STATE_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def _save_state(state: dict):
    with open(CHRONOS_STATE_FILE, "w") as f:
        json.dump(state, f, indent=2, default=str)


class ChronosMonitor:
    """
    v27.0 Chronos Protocol: The Eternal Guardian.
    Performs lightweight delta-hunting at configurable intervals and
    triggers deep Turbine scans on surface changes.
    """

    def __init__(self, target: str, interval: int = 3600, deep_scan: bool = True):
        self.target = target
        self.interval = interval  # seconds between checks
        self.deep_scan = deep_scan
        self.state = _load_state()
        self._running = False

    # ── Lightweight surface snapshot ──────────────────────────────────────────
    async def _take_snapshot(self) -> dict:
        """
        Performs a lightweight reconnaissance to get a snapshot of the target surface:
        - Subdomain fingerprints
        - Robots.txt & sitemap changes
        - JS file hashes
        - HTTP response header fingerprints
        """
        import httpx
        snapshot = {"subdomains": [], "js_hashes": {}, "headers": {}, "robots": ""}

        async with httpx.AsyncClient(timeout=15, follow_redirects=True, verify=False) as client:
            # 1. Top-level response headers
            try:
                r = await client.get(f"https://{self.target}")
                snapshot["headers"] = {
                    "server": r.headers.get("server", ""),
                    "x-powered-by": r.headers.get("x-powered-by", ""),
                    "status": r.status_code
                }
            except Exception:
                pass

            # 2. Robots.txt hash
            try:
                r = await client.get(f"https://{self.target}/robots.txt")
                snapshot["robots"] = hashlib.md5(r.text.encode()).hexdigest()
            except Exception:
                pass

            # 3. Sitemap for endpoint discovery
            try:
                r = await client.get(f"https://{self.target}/sitemap.xml")
                snapshot["sitemap_hash"] = hashlib.md5(r.text.encode()).hexdigest()
            except Exception:
                snapshot["sitemap_hash"] = ""

            # 4. Common JS bundles
            js_paths = ["/main.js", "/app.js", "/bundle.js", "/static/js/main.chunk.js"]
            for path in js_paths:
                try:
                    r = await client.get(f"https://{self.target}{path}", timeout=8)
                    if r.status_code == 200:
                        snapshot["js_hashes"][path] = hashlib.sha256(r.content).hexdigest()
                except Exception:
                    pass

        return snapshot

    # ── Delta Detection ───────────────────────────────────────────────────────
    def _detect_deltas(self, old_snap: dict, new_snap: dict) -> list:
        """Compares two snapshots and returns a list of detected changes."""
        deltas = []

        # Header changes
        for key in ["server", "x-powered-by", "status"]:
            old_val = old_snap.get("headers", {}).get(key)
            new_val = new_snap.get("headers", {}).get(key)
            if old_val != new_val:
                deltas.append(f"Header change: `{key}` changed from `{old_val}` → `{new_val}`")

        # Robots.txt change
        if old_snap.get("robots") != new_snap.get("robots") and new_snap.get("robots"):
            deltas.append("robots.txt changed — new paths may be exposed!")

        # Sitemap change
        if old_snap.get("sitemap_hash") != new_snap.get("sitemap_hash") and new_snap.get("sitemap_hash"):
            deltas.append("sitemap.xml changed — new endpoints discovered!")

        # JS bundle changes
        old_js = old_snap.get("js_hashes", {})
        new_js = new_snap.get("js_hashes", {})
        for path, new_hash in new_js.items():
            old_hash = old_js.get(path)
            if old_hash is None:
                deltas.append(f"NEW JS bundle detected: `{path}`")
            elif old_hash != new_hash:
                deltas.append(f"JS modified: `{path}` — new secrets or endpoints may exist!")
        # Removed JS files
        for path in old_js:
            if path not in new_js:
                deltas.append(f"JS file removed: `{path}` (possibly replaced — check for leaks)")

        return deltas

    # ── Deep Scan Trigger ────────────────────────────────────────────────────
    async def _trigger_deep_scan(self, deltas: list):
        """Fires a Turbine-powered deep scan when surface changes are detected."""
        console.print(f"\n[bold red][[⚡ CHRONOS]] 🚨 SURFACE CHANGE DETECTED! Triggering Turbine Deep Scan...[/bold red]")
        for d in deltas:
            console.print(f"  [yellow]↳ {d}[/yellow]")

        if not self.deep_scan:
            console.print("[dim]  [Chronos] Deep scan disabled. Set deep_scan=True to auto-exploit.[/dim]")
            return

        try:
            from aura.core.orchestrator import NeuralOrchestrator
            orc = NeuralOrchestrator()
            console.print(f"[bold cyan][[⚡ TURBINE]] Launching autonomous deep scan on {self.target}...[/bold cyan]")
            result = await orc.execute_advanced_chain(self.target)
            console.print(f"[bold green][[SUCCESS]] Deep scan complete: {result.get('findings', 0)} findings.[/bold green]")
        except Exception as e:
            console.print(f"[red][!] Deep scan failed: {e}[/red]")

    # ── Main Monitor Loop ────────────────────────────────────────────────────
    async def run(self):
        """Main monitoring loop — runs indefinitely until stopped."""
        self._running = True
        t_state = self.state.get(self.target, {})
        check_count = 0

        console.print(Panel(
            f"[bold cyan]⏳ CHRONOS PROTOCOL ACTIVATED[/bold cyan]\n"
            f"Target: [bold]{self.target}[/bold]\n"
            f"Interval: [bold]{self.interval}s[/bold]  |  Deep Scans: [bold]{'YES' if self.deep_scan else 'NO'}[/bold]\n"
            f"Started: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            title="[bold magenta]Aura v27.0 — The Eternal Guardian[/bold magenta]",
            border_style="magenta"
        ))

        while self._running:
            check_count += 1
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            console.print(f"\n[cyan][[⏳ Chronos #{check_count}]] Surface check at {ts}...[/cyan]")

            try:
                new_snap = await self._take_snapshot()
            except Exception as e:
                console.print(f"[red][!] Snapshot failed: {e}[/red]")
                await asyncio.sleep(self.interval)
                continue

            old_snap = t_state.get("last_snapshot", {})
            deltas = self._detect_deltas(old_snap, new_snap) if old_snap else []

            if deltas:
                await self._trigger_deep_scan(deltas)
            else:
                console.print(f"[dim green]  ✓ No surface changes detected. Target surface is stable.[/dim green]")

            # Persist state
            t_state["last_snapshot"] = new_snap
            t_state["last_check"] = ts
            t_state["check_count"] = check_count
            self.state[self.target] = t_state
            _save_state(self.state)

            console.print(f"[dim]  Next check in {self.interval}s... (Ctrl+C to stop)[/dim]")
            await asyncio.sleep(self.interval)

    def stop(self):
        self._running = False
        console.print("[bold yellow][[⏳ CHRONOS]] Guardian deactivated.[/bold yellow]")


async def _main(target: str, interval: int = 3600, deep: bool = True):
    monitor = ChronosMonitor(target=target, interval=interval, deep_scan=deep)
    try:
        await monitor.run()
    except KeyboardInterrupt:
        monitor.stop()


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "intel.com"
    interval = int(sys.argv[2]) if len(sys.argv) > 2 else 3600
    asyncio.run(_main(target, interval))
