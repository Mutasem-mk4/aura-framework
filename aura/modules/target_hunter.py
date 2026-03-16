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
from rich import box
from aura.ui.zenith_ui import ZenithUI

console = Console()

CHAOS_INDEX_URL = "https://chaos-data.projectdiscovery.io/index.json"

class TargetHunter:
    def __init__(self, data_dir: str = "./aura/data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.index_path = self.data_dir / "chaos_index.json"

    def fetch_index(self):
        """Downloads the latest Chaos index JSON and merges local targets."""
        all_data = []
        
        # 1. Fetch live data
        with ZenithUI.create_progress() as progress:
            progress.add_task("[cyan]📡 Downloading live Chaos Bug Bounty Index...", total=None)
            try:
                resp = httpx.get(CHAOS_INDEX_URL, timeout=15)
                resp.raise_for_status()
                all_data = resp.json()
                
                with open(self.index_path, "w", encoding="utf-8") as f:
                    json.dump(all_data, f)
            except Exception as e:
                console.print(f"[red]❌ Failed to fetch index: {e}[/red]")
                if self.index_path.exists():
                    console.print("[yellow]⚠️  Using locally cached index...[/yellow]")
                    with open(self.index_path, "r", encoding="utf-8") as f:
                        all_data = json.load(f)

        # 2. Merge local overrides/targets
        local_path = self.data_dir / "local_targets.json"
        if local_path.exists():
            try:
                with open(local_path, "r", encoding="utf-8") as f:
                    local_data = json.load(f)
                    # Merge local data at the beginning so they show up first or are prioritized
                    all_data = local_data + all_data
            except Exception as e:
                console.print(f"[red]❌ Failed to read local_targets.json: {e}[/red]")
        
        return all_data


    def filter_and_display(self, data: list):
        """Filters the data and displays a beautiful table of targets."""
        if not data:
            console.print("[red]No data to process.[/red]")
            return

        ZenithUI.banner("AURA OMNI — Target Hunter", "Scanning global bug bounty indices for the hottest targets...")

        console.print("[dim]Press Enter to see all platforms, or type part of the platform name.[/dim]")
        platform_filter_input = console.input("[bold yellow]Filter by Platform (e.g., hackerone, intigriti, yeswehack, bugcrowd, independent): [/bold yellow]").strip().lower()

        # Filter logic
        filtered_programs = []
        for program in data:
            if program.get("bounty") is True:
                prog_platform = str(program.get("platform", "independent")).lower()
                if platform_filter_input and platform_filter_input not in prog_platform:
                    continue
                filtered_programs.append(program)

        console.print("[dim]Press Enter for Fresh/New targets, or type 'massive' for huge saturated targets.[/dim]")
        sort_preference = console.input("[bold yellow]Sort Preference (fresh/massive): [/bold yellow]").strip().lower()

        # Sort logic
        if sort_preference == "massive":
            # We prefer programs with a high count of subdomains (wide scope)
            filtered_programs.sort(key=lambda x: x.get("count", 0), reverse=True)
            sort_title = "Massive Scope"
        else:
            # Sort primarily by `change` descending (number of new subdomains discovered today).
            # If changes are equal, favor smaller scopes (-count descending = smaller count first).
            # Also filter out programs with 0 subdomains UNLESS it's a known Web3 platform.
            filtered_programs = [
                p for p in filtered_programs 
                if p.get("count", 0) > 0 or p.get("platform", "").lower() in ["hackenproof", "immunefi"]
            ]
            
            filtered_programs.sort(key=lambda x: (
                x.get("change", 0),
                -x.get("count", 0)
            ), reverse=True)
            sort_title = "Fresh Changes & New"

        table = Table(
            title=f"🔥 Top {sort_title} Bounty Programs {'(Platform: ' + platform_filter_input.capitalize() + ')' if platform_filter_input else ''}",
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
            if p.get("is_new"):
                name = f"[bold green][NEW][/bold green] {name}"
                
            platform = p.get("platform", "Unknown")
            # Some platforms might be blank, default to Independent
            if not platform: platform = "Independent"
            
            subdomain_count = p.get("count", 0)
            # For Fresh sorting, we don't skip small scopes. For massive, we skip < 100
            if sort_preference == "massive" and subdomain_count < 100: continue 
            
            # Create a quick start command
            slug = name.replace(" ", "").replace(".com", "").replace("'", "")
            slug_lower = slug.lower()
            
            # If Web3 platform, recommend --web3. Otherwise, regular --auto domain
            if platform.lower() in ["hackenproof", "immunefi"] and subdomain_count == 0:
                cmd = f"aura --web3 {slug_lower}"
            else:
                cmd = f"aura {slug_lower}.com --auto" # Simplified guess, user can refine
            
            table.add_row(
                name,
                platform.capitalize(),
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
