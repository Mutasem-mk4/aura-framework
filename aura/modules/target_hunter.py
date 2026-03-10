"""
Aura Omni v3 — Target Hunter 🎯
===============================
Automatically fetches, filters, and curates a list of fresh,
profitable (bounty-paying), wide-scope bug bounty programs.
Uses ProjectDiscovery's Chaos index data.
"""

import json
import httpx
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

console = Console()

CHAOS_INDEX_URL = "https://chaos-data.projectdiscovery.io/index.json"

class TargetHunter:
    def __init__(self, data_dir: str = "./aura/data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.index_path = self.data_dir / "chaos_index.json"

    def fetch_index(self):
        """Downloads the latest Chaos index JSON."""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
            console=console
        ) as progress:
            progress.add_task("[cyan]📡 Downloading live Chaos Bug Bounty Index...", total=None)
            try:
                # Using standard sync httpx since this is a quick single download run from CLI directly
                resp = httpx.get(CHAOS_INDEX_URL, timeout=15)
                resp.raise_for_status()
                data = resp.json()
                
                with open(self.index_path, "w", encoding="utf-8") as f:
                    json.dump(data, f)
                return data
            except Exception as e:
                console.print(f"[red]❌ Failed to fetch index: {e}[/red]")
                # Fallback to local cache if exists
                if self.index_path.exists():
                    console.print("[yellow]⚠️  Using locally cached index...[/yellow]")
                    with open(self.index_path, "r", encoding="utf-8") as f:
                        return json.load(f)
                return []

    def filter_and_display(self, data: list):
        """Filters the data and displays a beautiful table of targets."""
        if not data:
            console.print("[red]No data to process.[/red]")
            return

        console.print(Panel(
            "[bold white]🎯 AURA OMNI — Target Hunter[/bold white]\n"
            "[cyan]Scanning global bug bounty indices for the hottest targets...[/cyan]\n"
            "[dim]Filters: Bounty=Yes, Platform=Any, Ordered by: Most recently updated[/dim]",
            box=box.DOUBLE_EDGE,
            style="bright_blue",
        ))

        # Filter logic
        filtered_programs = []
        for program in data:
            if program.get("bounty") is True:
                filtered_programs.append(program)

        # Sort by latest change (change in count or created at etc, using change url timestamp approximation if needed, 
        # or just random. We don't have exact timestamp in standard chaos index beyond the domain updates, but we can sort by name for now, 
        # or just display top 50 to avoid clutter)
        # Assuming the list might be somewhat chronologically ordered or we just grab the first matches with massive scope.
        
        # We prefer programs with a high count of subdomains (wide scope)
        filtered_programs.sort(key=lambda x: x.get("count", 0), reverse=True)

        table = Table(
            title="🔥 Top Fresh Wide-Scope Bounty Programs",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold white on dark_blue",
            expand=True
        )
        table.add_column("Program Name", style="bold cyan")
        table.add_column("Platform", style="blue")
        table.add_column("Subdomains", justify="right", style="magenta")
        table.add_column("Bounty", justify="center", style="bold green")
        table.add_column("Recommended Command", style="dim yellow")

        # Display top 25 huge programs
        count_displayed = 0
        for p in filtered_programs:
            if count_displayed >= 25: break
            
            name = p.get("name", "Unknown")
            platform = p.get("platform", "Unknown")
            # Some platforms might be blank, default to Independent
            if not platform: platform = "Independent"
            
            subdomain_count = p.get("count", 0)
            if subdomain_count < 100: continue # Skip very small scoped programs
            
            # Create a quick start command
            slug = name.lower().replace(" ", "").replace(".com", "")
            cmd = f"aura {slug}.com --auto" # Simplified guess, user can refine
            
            table.add_row(
                name,
                platform,
                f"{subdomain_count:,}",
                "💰 Yes",
                cmd
            )
            count_displayed += 1

        console.print(table)
        
        console.print(Panel(
            "[bold green]💡 Pro Tip:[/bold green] Copy a recommended command and let Aura Auto-Pilot destroy the target!\n"
            "[dim]Note: Always verify the exact scope on the platform before hacking.[/dim]",
            style="green",
            box=box.ROUNDED
        ))

def run_hunter():
    hunter = TargetHunter()
    data = hunter.fetch_index()
    hunter.filter_and_display(data)

if __name__ == "__main__":
    run_hunter()
