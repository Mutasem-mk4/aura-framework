import os
import sys
import io

# Fix Windows Unicode issues FIRST before any rich imports
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except AttributeError:
        pass
    
os.environ['TERM'] = 'dumb'
os.environ['NO_COLOR'] = '1'
os.environ['RICH_DISABLE_JUPYTER'] = '1'

# Patch Windows console before rich imports
import rich._windows_renderer
rich._windows_renderer.LegacyWindowsTerm = None

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.status import Status
from rich.align import Align
from rich.text import Text
from rich import box

# Use non-terminal console to avoid Windows encoding issues
console = Console(file=sys.stdout, force_terminal=False)

class ZenithUI:
    """The visual soul of Aura: Gemini-style high-fidelity UI components."""
    
    @staticmethod
    def show_startup_banner():
        """Displays the massive, cool AURA ASCII banner."""
        banner_text = """
    █████╗ ██╗   ██╗██████╗  █████╗ 
   ██╔══██╗██║   ██║██╔══██╗██╔══██╗
   ███████║██║   ██║██████╔╝███████║
   ██╔══██║██║   ██║██╔══██╗██╔══██║
   ██║  ██║╚██████╔╝██║  ██║██║  ██║
   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
        """
        
        banner_panel = Panel(
            Align.center(
                Text(banner_text, style="bold cyan") + 
                Text("\nTHE SENTIENT OFFENSIVE ENGINE", style="bold magenta") +
                Text("\n\n[ v25.2 - OMEGA PROTOCOL ACTIVE ]", style="dim white")
            ),
            box=box.HEAVY,
            border_style="blue",
            padding=(1, 4)
        )
        console.print(banner_panel)
        console.print()

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
    def phase_banner(phase_name: str, target: str, icon: str = "⚡"):
        """Displays a beautiful, wide banner for each new phase."""
        console.print(Panel(
            f"[bold white]{icon} {phase_name}[/bold white]  [dim]⯈[/dim]  [bold cyan]{target}[/bold cyan]",
            box=box.MINIMAL_DOUBLE_HEAD,
            border_style="blue",
            padding=(0, 2),
            expand=True
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
        console.print(Panel(
            f"[bold {color}]🚨 {severity.upper()} DISCOVERED![/bold {color}]\n"
            f"[white]Vulnerability:[/white] [cyan]{vuln_type}[/cyan]\n"
            f"[white]Target:[/white] [dim]{target}[/dim]",
            box=box.ROUNDED,
            border_style=color,
            padding=(0, 2),
            expand=False
        ))
    @staticmethod
    def clinic_info(topic: str, content: str):
        """v4.0 Clinic Mode: Displays educational tooltips for beginners."""
        console.print(Panel(
            f"[bold cyan]📚 Topic: {topic}[/bold cyan]\n[white]{content}[/white]",
            title="[bold yellow]CLINIC TIP[/bold yellow]",
            border_style="yellow",
            padding=(0, 2),
            expand=False
        ))
