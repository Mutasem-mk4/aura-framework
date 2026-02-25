from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
import time

console = Console()

def render_results_table(results):
    """Renders ingested results in a professional table."""
    table = Table(title="[bold magenta]AURA - Intelligence Feed[/bold magenta]", border_style="bright_blue", expand=True)
    table.add_column("ID", justify="center", style="cyan", no_wrap=True)
    table.add_column("Source", style="green")
    table.add_column("Type", style="yellow")
    table.add_column("Value", style="white")
    
    for i, res in enumerate(results):
        source = res.get("source", "Unknown")
        item_type = res.get("type", "Raw")
        value = res.get("value", res.get("raw", "N/A"))
        table.add_row(str(i+1), source, item_type, value)
        
    return table

def render_battle_plan(paths):
    """Renders the identified attack paths as a Battle Plan."""
    table = Table(title="[bold red]AURA - RECOMMENDED BATTLE PLAN[/bold red]", border_style="red", expand=True)
    table.add_column("Priority", justify="center", style="bold white", no_wrap=True)
    table.add_column("Risk", justify="center")
    table.add_column("Target", style="yellow")
    table.add_column("Strategic Insight", style="white")
    
    for path in paths:
        priority_style = "on red" if path["priority"] == "CRITICAL" else "on yellow" if path["priority"] == "HIGH" else "on blue"
        table.add_row(
            f"[{priority_style}] {path['priority']} [/{priority_style}]",
            f"[bold]{path['risk_score']}[/bold]",
            path["target"],
            path["insight"]
        )
        
    return table

def show_banner():
    """Displays the signature AURA holographic banner."""
    banner_text = """
    [bold magenta]
    █████╗ ██╗   ██╗██████╗  █████╗ 
    ██╔══██╗██║   ██║██╔══██╗██╔══██╗
    ███████║██║   ██║██████╔╝███████║
    ██╔══██║██║   ██║██╔══██╗██╔══██║
    ██║  ██║╚██████╔╝██║  ██║██║  ██║ [v3.0 ZENITH]
    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
    [/bold magenta]
    [italic cyan]Autonomous Offensive Intelligence Framework[/italic cyan]
    [grey62]Created by Mutasem Kharma | Built for Cyber Dominance[/grey62]
    """
    from rich.align import Align
    console.print(Align.center(Panel(banner_text, border_style="magenta", padding=(1, 4))))

def simulate_analysis_flow(results):
    """Simulates a sophisticated analysis process with progress bars."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task(description="[cyan]Connecting to AURA Core...", total=None)
        time.sleep(1)
        progress.add_task(description="[magenta]Analyzing attack paths...", total=None)
        time.sleep(1.5)
        progress.add_task(description="[green]Generating battle plan...", total=None)
        time.sleep(0.5)
        
    console.print(render_results_table(results))
