from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.status import Status
from rich import box
import asyncio

console = Console()

class ZenithUI:
    """The visual soul of Aura: Gemini-style high-fidelity UI components."""
    
    @staticmethod
    def banner(title: str, subtitle: str = "Sentient Offensive Engine"):
        """Displays the main mission header."""
        console.print(Panel(
            f"[bold cyan]{title}[/bold cyan]\n[dim]{subtitle}[/dim]",
            box=box.DOUBLE_EDGE,
            border_style="bright_magenta",
            padding=(1, 2),
            expand=False
        ))

    @staticmethod
    def status(text: str):
        """Creates a pulsing Gemini-style status spinner."""
        return console.status(f"[bold white]{text}[/bold white]", spinner="dots", spinner_style="bright_cyan")

    @staticmethod
    def create_progress():
        """Returns a pre-configured multi-module progress bar system."""
        return Progress(
            SpinnerColumn(spinner_name="dots", style="bright_cyan"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=30, style="dim", complete_style="bright_magenta"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
            transient=True
        )

    @staticmethod
    def finding(vuln_type: str, severity: str, target: str):
        """Prints a high-visibility discovery alert."""
        color = "red" if severity.upper() == "CRITICAL" else "yellow"
        console.print(f"[bold {color}]🚨 {severity.upper()} DISCOVERED: {vuln_type} on {target}![/bold {color}]")
