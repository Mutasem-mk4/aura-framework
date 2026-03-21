"""
Aura ZenithFormatter
=====================
Professional CLI output system using Rich library.
Implements ZenithTheme for visually stunning, organized output.

Theme Colors:
- Headers: bold magenta
- Success/Live: spring_green3
- Warning: gold1
- Errors/Fatal: deep_pink3
- Info/Recon: cyan1
- Borders: grey37
"""

import sys
import os

# Windows compatibility
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except AttributeError:
        pass
    
    # Patch Windows console before rich imports
    try:
        import rich._windows_renderer
        rich._windows_renderer.LegacyWindowsTerm = None
    except ImportError:
        pass

os.environ['RICH_DISABLE_JUPYTER'] = '1'

from rich.console import Console, ConsoleRenderable
from rich.theme import Theme
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TimeRemainingColumn, TaskProgressColumn
from rich.status import Status
from rich.align import Align
from rich.text import Text
from rich.live import Live
from rich.layout import Layout
from rich.columns import Columns
from rich.console import Group
from rich import box
from rich.style import Style
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

# ============================================================
# ZENITH THEME DEFINITION
# ============================================================

class ZenithTheme:
    """Color palette and style definitions for Aura v25.2"""
    
    # Primary Colors
    HEADER = "bold magenta"
    SUCCESS = "spring_green3"
    WARNING = "gold1"
    ERROR = "deep_pink3"
    INFO = "cyan1"
    BORDER = "grey37"
    
    # Additional Semantic Colors
    CRITICAL = "bold deep_pink3"
    HIGH = "bold red1"
    MEDIUM = "bold yellow1"
    LOW = "dim white"
    
    # Component Styles
    BANNER_TEXT = "bold cyan"
    BANNER_SUBTEXT = "bold magenta"
    PHASE_HEADER = "bold white"
    FINDING_TITLE = "bold"
    
    @classmethod
    def get_theme(cls) -> Theme:
        """Returns Rich Theme object"""
        return Theme({
            "header": cls.HEADER,
            "success": cls.SUCCESS,
            "warning": cls.WARNING,
            "error": cls.ERROR,
            "info": cls.INFO,
            "border": cls.BORDER,
            "critical": cls.CRITICAL,
            "high": cls.HIGH,
            "medium": cls.MEDIUM,
            "low": cls.LOW,
        })


# ============================================================
# CENTRAL LOGGER
# ============================================================

# Global Shared Console to act as the rendering anchor for the Dashboard
shared_console = Console(
    theme=ZenithTheme.get_theme(),
    file=sys.stdout,
    force_terminal=True,
    width=120
)

# ============================================================
# CENTRAL LOGGER
# ============================================================

class ZenithLogger:
    """
    Centralized logging with ZenithTheme styling.
    Replaces all print() calls throughout Aura.
    """
    
    def __init__(self):
        self.console = shared_console
        self._log_history: List[Dict[str, Any]] = []
    
    # --------------------------------------------------------
    # Core Logging Methods
    # --------------------------------------------------------
    
    def header(self, message: str):
        """Bold magenta headers"""
        self.console.print(f"[{ZenithTheme.HEADER}]{message}[/{ZenithTheme.HEADER}]")
        self._log("HEADER", message)
    
    def success(self, message: str):
        """Spring green3 for success/live"""
        self.console.print(f"[{ZenithTheme.SUCCESS}]✓ {message}[/{ZenithTheme.SUCCESS}]")
        self._log("SUCCESS", message)
    
    def warning(self, message: str):
        """Gold1 for warnings"""
        self.console.print(f"[{ZenithTheme.WARNING}]⚠ {message}[/{ZenithTheme.WARNING}]")
        self._log("WARNING", message)
    
    def error(self, message: str):
        """Deep pink3 for errors/fatal"""
        self.console.print(f"[{ZenithTheme.ERROR}]✗ {message}[/{ZenithTheme.ERROR}]")
        self._log("ERROR", message)
    
    def info(self, message: str):
        """Cyan1 for info/recon"""
        self.console.print(f"[{ZenithTheme.INFO}]ℹ {message}[/{ZenithTheme.INFO}]")
        self._log("INFO", message)
    
    def debug(self, message: str):
        """Dim white for debug"""
        self.console.print(f"[dim]{message}[/dim]")
        self._log("DEBUG", message)
    
    def raw(self, message: str):
        """Raw output without styling"""
        self.console.print(message)
    
    # --------------------------------------------------------
    # Panel Wrappers
    # --------------------------------------------------------
    
    def panel(self, content: str, title: str = "", border_color: str = None):
        """Create a styled panel"""
        color = border_color or ZenithTheme.BORDER
        self.console.print(Panel(
            content,
            title=title,
            border_style=color,
            box=box.ROUNDED,
            padding=(0, 1)
        ))
    
    def alert(self, title: str, content: str, severity: str = "info"):
        """High-visibility alert panel"""
        colors = {
            "critical": ZenithTheme.CRITICAL,
            "high": ZenithTheme.HIGH,
            "medium": ZenithTheme.MEDIUM,
            "warning": ZenithTheme.WARNING,
            "success": ZenithTheme.SUCCESS,
            "info": ZenithTheme.INFO
        }
        color = colors.get(severity.lower(), ZenithTheme.INFO)
        
        icon = {
            "critical": "🚨",
            "high": "🔥",
            "medium": "⚠️",
            "warning": "⚠",
            "success": "✓",
            "info": "ℹ"
        }.get(severity.lower(), "ℹ")
        
        self.console.print(Panel(
            f"[{color}]{icon} {content}[/{color}]",
            title=f"[{color}]{title}[/{color}]",
            border_style=color,
            box=box.ROUNDED,
            padding=(0, 2)
        ))
    
    # --------------------------------------------------------
    # Internal
    # --------------------------------------------------------
    
    def _log(self, level: str, message: str):
        self._log_history.append({
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "message": message
        })
    
    def get_history(self) -> List[Dict[str, Any]]:
        return self._log_history


# Global logger instance
logger = ZenithLogger()


# ============================================================
# UI COMPONENTS
# ============================================================

class ZenithFormatter:
    """Formatter factory for Aura components"""
    
    def __init__(self):
        self.console = shared_console
    
    # --------------------------------------------------------
    # ASCII Banner
    # --------------------------------------------------------
    
    def show_banner(self, version: str = "v25.2", protocol: str = "OMEGA PROTOCOL"):
        """Display ASCII banner in magenta-bordered panel"""
        
        banner_art = r"""
    █████╗ ██╗   ██╗██████╗  █████╗ 
   ██╔══██╗██║   ██║██╔══██╗██╔══██╗
   ███████║██║   ██║██████╔╝███████║
   ██╔══██║██║   ██║██╔══██╗██╔══██║
   ██║  ██║╚██████╔╝██║  ██║██║  ██║
   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
        """
        
        content = Text()
        content.append(banner_art, style=ZenithTheme.BANNER_TEXT)
        content.append(f"\n\nTHE SENTIENT OFFENSIVE ENGINE", style=ZenithTheme.BANNER_SUBTEXT)
        content.append(f"\n\n[ {version} - {protocol} ACTIVE ]", style="dim white")
        
        panel = Panel(
            Align.center(content),
            border_style="magenta",
            box=box.HEAVY,
            padding=(1, 4),
            subtitle="[dim]Aura Security Framework[/dim]",
            subtitle_align="right"
        )
        
        self.console.print(panel)
        self.console.print()

    def banner(self, title: str, subtitle: str = "Sentient Offensive Engine"):
        """Displays a primary mission header (Legacy compatibility)"""
        self.console.print(Panel(
            f"[bold cyan]{title}[/bold cyan]\n[dim]{subtitle}[/dim]",
            box=box.DOUBLE_EDGE,
            border_style="bright_magenta",
            padding=(1, 2),
            expand=False
        ))
    
    # --------------------------------------------------------
    # Engine Initialization Table
    # --------------------------------------------------------
    
    def show_engine_table(self, engines: List[Dict[str, str]]):
        """
        Display engine initialization as a formatted table.
        
        Args:
            engines: List of dicts with keys: 'name', 'status', 'provider'
        """
        table = Table(
            title="[bold magenta]⚡ ENGINE INITIALIZATION[/bold magenta]",
            box=box.ROUNDED,
            border_style=ZenithTheme.BORDER,
            header_style=f"bold {ZenithTheme.HEADER}",
            show_lines=True
        )
        
        # Add columns
        table.add_column("Engine Name", style=ZenithTheme.INFO, no_wrap=True)
        table.add_column("Status", style=ZenithTheme.SUCCESS, no_wrap=True)
        table.add_column("Provider", style="dim white")
        
        # Add rows
        for engine in engines:
            status = engine.get("status", "initialized")
            status_style = ZenithTheme.SUCCESS if status == "loaded" else ZenithTheme.WARNING
            
            table.add_row(
                engine.get("name", "unknown"),
                f"[{status_style}]{status}[/{status_style}]",
                engine.get("provider", "aura.core")
            )
        
        if dashboard.live and dashboard.live.is_started:
            dashboard.update_engines(table)
        else:
            self.console.print(table)
            self.console.print()
    
    # --------------------------------------------------------
    # Live Progress Bars
    # --------------------------------------------------------
    
    def create_progress(self) -> Progress:
        """Create a pre-configured progress bar system"""
        prog = Progress(
            SpinnerColumn(spinner_name="dots", style=ZenithTheme.INFO),
            TextColumn("[progress.description]{task.description}", style=ZenithTheme.INFO),
            BarColumn(
                bar_width=40,
                style=ZenithTheme.BORDER,
                complete_style=ZenithTheme.SUCCESS,
                finished_style=ZenithTheme.HEADER
            ),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=self.console,
            transient=False,
            expand=True
        )
        return DashboardProgressWrapper(prog)
    
    def create_recon_progress(self) -> Progress:
        """Specialized progress for Recon Pipeline"""
        prog = Progress(
            SpinnerColumn(spinner_name="earth", style=ZenithTheme.INFO),
            TextColumn("[bold cyan]{task.description}[/bold cyan]"),
            BarColumn(
                bar_width=50,
                style="dim",
                complete_style=ZenithTheme.SUCCESS,
            ),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=self.console,
            transient=True
        )
        return DashboardProgressWrapper(prog)
    
    # --------------------------------------------------------
    # Phase Banner
    # --------------------------------------------------------
    
    def phase_banner(self, phase_name: str, target: str, icon: str = "⚡"):
        """Display phase header"""
        content = f"[bold white]{icon} {phase_name}[/bold white]  [dim]⯈[/dim]  [cyan1]{target}[/cyan1]"
        
        panel = Panel(
            content,
            border_style=ZenithTheme.BORDER,
            box=box.MINIMAL_DOUBLE_HEAD,
            padding=(0, 2),
            expand=True
        )
        self.console.print(panel)
    
    # --------------------------------------------------------
    # Status Spinner
    # --------------------------------------------------------
    
    def status(self, message: str) -> Any:
        """Create a status spinner"""
        if dashboard.live and dashboard.live.is_started:
            dashboard.update_logs(f"[bold cyan]STATUS:[/bold cyan] {message}")
            class DummyStatus:
                def __enter__(self): return self
                def __exit__(self, *args): pass
                def update(self, msg, **kwargs):
                    dashboard.update_logs(f"[bold cyan]STATUS UPDATE:[/bold cyan] {msg}")
            return DummyStatus()
            
        return self.console.status(
            f"[bold white]{message}[/bold white]",
            spinner="dots",
            spinner_style=ZenithTheme.INFO
        )
    
    # --------------------------------------------------------
    # Findings Display
    # --------------------------------------------------------
    
    def show_finding(self, vuln_type: str, severity: str, target: str, evidence: str = ""):
        """Display a vulnerability finding"""
        severity_lower = severity.lower()
        
        colors = {
            "critical": ZenithTheme.CRITICAL,
            "high": ZenithTheme.HIGH,
            "medium": ZenithTheme.MEDIUM,
            "low": ZenithTheme.LOW,
            "info": ZenithTheme.INFO
        }
        
        color = colors.get(severity_lower, ZenithTheme.INFO)
        
        icons = {
            "critical": "🚨",
            "high": "🔥",
            "medium": "⚠️",
            "low": "ℹ",
            "info": "ℹ"
        }
        
        icon = icons.get(severity_lower, "⚠")
        
        content = f"[{color}]{icon} {severity.upper()} DISCOVERED![/{color}]\n"
        content += f"[white]Vulnerability:[/white] [cyan]{vuln_type}[/cyan]\n"
        content += f"[white]Target:[/white] [dim]{target}[/dim]"
        
        if evidence:
            content += f"\n[white]Evidence:[/white] [dim]{evidence[:100]}...[/dim]"
        
        panel = Panel(
            content,
            border_style=color,
            box=box.ROUNDED,
            padding=(0, 2),
            expand=False
        )
        self.console.print(panel)

    def clinic_info(self, topic: str, content: str):
        """v4.0 Clinic Mode: Displays educational tooltips for beginners."""
        self.console.print(Panel(
            f"[bold cyan]📚 Topic: {topic}[/bold cyan]\n[white]{content}[/white]",
            title="[bold yellow]CLINIC TIP[/bold yellow]",
            border_style=ZenithTheme.WARNING,
            padding=(0, 2),
            expand=False
        ))

    def render_results_table(self, results: List[Dict[str, Any]]) -> Table:
        """Renders ingested results in a professional table."""
        table = Table(
            title="[bold magenta]AURA - Intelligence Feed[/bold magenta]", 
            box=box.ROUNDED,
            border_style=ZenithTheme.BORDER,
            header_style=f"bold {ZenithTheme.HEADER}",
            expand=True
        )
        table.add_column("ID", justify="center", style=ZenithTheme.INFO, no_wrap=True)
        table.add_column("Source", style=ZenithTheme.SUCCESS)
        table.add_column("Type", style=ZenithTheme.WARNING)
        table.add_column("Value", style="white")
        
        for i, res in enumerate(results):
            source = res.get("source", "Unknown")
            item_type = res.get("type", "Raw")
            value = res.get("value", res.get("raw", "N/A"))
            table.add_row(str(i+1), source, item_type, value)
            
        return table

    def render_battle_plan(self, paths: List[Dict[str, Any]]) -> Table:
        """Renders the identified attack paths as a Battle Plan."""
        table = Table(
            title="[bold red]AURA - RECOMMENDED BATTLE PLAN[/bold red]", 
            box=box.ROUNDED,
            border_style=ZenithTheme.ERROR,
            expand=True
        )
        table.add_column("Priority", justify="center", style="bold white", no_wrap=True)
        table.add_column("Risk", justify="center")
        table.add_column("Target", style=ZenithTheme.WARNING)
        table.add_column("Strategic Insight", style="white")
        
        for path in paths:
            priority = path.get("priority", "LOW").upper()
            priority_style = "on red" if priority == "CRITICAL" else "on yellow" if priority == "HIGH" else "on blue"
            table.add_row(
                f"[{priority_style}] {priority} [/{priority_style}]",
                f"[bold]{path.get('risk_score', 0)}[/bold]",
                path.get("target", path.get("value", "unknown")),
                path.get("insight", "No details")
            )
            
        return table

    # --------------------------------------------------------
    # Static Accessors for ZenithUI compatibility
    # --------------------------------------------------------
    
    @staticmethod
    def show_startup_banner():
        ui.show_banner()
        
    @staticmethod
    def phase_banner_static(phase_name: str, target: str, icon: str = "⚡"):
        ui.phase_banner(phase_name, target, icon)
        
    @staticmethod
    def status_static(message: str) -> Status:
        return ui.status(message)
    
    @staticmethod
    def finding(vuln_type: str, severity: str, target: str):
        ui.show_finding(vuln_type, severity, target)
        
    @staticmethod
    def clinic_info_static(topic: str, content: str):
        ui.clinic_info(topic, content)


# ============================================================
# ORCHESTRATOR WRAPPER
# ============================================================

class OrchestratorUI:
    """
    Wraps NeuralOrchestrator output with Zenith formatting.
    Use this to wrap the orchestrator's main execution.
    """
    
    def __init__(self):
        self.formatter = ZenithFormatter()
        self.logger = logger
    
    def wrap_initialization(self, engines: Dict[str, Any]):
        """Display engine initialization status"""
        engine_list = []
        
        for name, engine in engines.items():
            status = "loaded" if hasattr(engine, '_status') else "initialized"
            provider = getattr(engine, '__module__', 'aura.core')
            
            engine_list.append({
                "name": name,
                "status": status,
                "provider": provider
            })
        
        self.formatter.show_banner()
        self.formatter.show_engine_table(engine_list)
    
    def wrap_phase(self, phase_name: str, target: str):
        """Wrap a mission phase"""
        self.formatter.phase_banner(phase_name, target)
    
    def wrap_progress(self, description: str):
        """Create a progress bar for a task"""
        return self.formatter.create_progress()
    
    def wrap_finding(self, finding: Dict[str, Any]):
        """Display a finding with styling"""
        self.formatter.show_finding(
            vuln_type=finding.get("type", "Unknown"),
            severity=finding.get("severity", "info"),
            target=finding.get("target_value", "unknown"),
            evidence=finding.get("evidence_url", "")
        )


# ============================================================
# USAGE EXAMPLE
# ============================================================

# ============================================================
# SINGLETON INSTANCE
# ============================================================

# Global formatter instance
ui = ZenithFormatter()

# Legacy alias for ZenithUI compatibility
class ZenithUI:
    """Compatibility wrapper for legacy ZenithUI calls"""
    show_startup_banner = staticmethod(ui.show_banner)
    banner = staticmethod(ui.banner)
    phase_banner = staticmethod(ui.phase_banner)
    status = staticmethod(ui.status)
    create_progress = staticmethod(ui.create_progress)
    finding = staticmethod(ui.show_finding)
    clinic_info = staticmethod(ui.clinic_info)
    render_results_table = staticmethod(ui.render_results_table)
    render_battle_plan = staticmethod(ui.render_battle_plan)

# global console reference
console = shared_console

# ============================================================
# DASHBOARD MANAGER SYSTEM
# ============================================================

class DashboardProgressWrapper:
    def __init__(self, prog):
        self.prog = prog
    def __enter__(self):
        if dashboard.live and dashboard.live.is_started:
            dashboard.update_progress(self.prog)
            return self.prog
        else:
            return self.prog.__enter__()
    def __exit__(self, exc_type, exc_val, exc_tb):
        if dashboard.live and dashboard.live.is_started:
            return
        else:
            return self.prog.__exit__(exc_type, exc_val, exc_tb)

class DashboardManager:
    """Orchestrates the Live Terminal UI Dashboard."""
    
    def __init__(self, target_console):
        self.console = target_console
        self.layout = Layout()
        self.live = None
        self.logs = []
        self._original_print = self.console.print
        self._patch_console()
        
    def _patch_console(self):
        def patched_print(*args, **kwargs):
            if self.live and self.live.is_started:
                if args:
                    item = args[0]
                    self.logs.append(item)
                    if len(self.logs) > 20:
                        self.logs.pop(0)
                    try:
                        self.layout["logs"].update(
                            Panel(Group(*self.logs), title="[bold cyan]Live Mission Logs[/bold cyan]", border_style="cyan")
                        )
                    except Exception: pass
            else:
                self._original_print(*args, **kwargs)
        self.console.print = patched_print

    def start(self, target="Global"):
        self.layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="progress", size=4)
        )
        self.layout["body"].split_row(
            Layout(name="engines", ratio=1),
            Layout(name="logs", ratio=3)
        )
        self.layout["header"].update(Panel(f"[bold cyan]AURA v25.2 OMEGA PROTOCOL[/bold cyan] | Target: [bold white]{target}[/bold white]", style="on dark_blue", border_style="blue"))
        self.layout["engines"].update(Panel("[dim]Initializing engines...[/dim]", title="[bold magenta]Active Engines[/bold magenta]", border_style="magenta"))
        self.layout["logs"].update(Panel("[dim]Waiting for telemetry...[/dim]", title="[bold cyan]Live Mission Logs[/bold cyan]", border_style="cyan"))
        self.layout["progress"].update(Panel("[dim]Idle... Waiting for scan tasks[/dim]", title="[bold green]Mission Progress / Subtasks[/bold green]", border_style="green"))
        
        self.live = Live(self.layout, console=self.console, refresh_per_second=6, screen=False)
        self.live.start()
        
    def stop(self):
        if self.live:
            self.live.stop()
            self.live = None

    def update_engines(self, renderable):
        if self.live and self.live.is_started:
            self.layout["engines"].update(Panel(renderable, title="[bold magenta]Active Engines[/bold magenta]", border_style="magenta"))

    def update_progress(self, renderable):
        if self.live and self.live.is_started:
            self.layout["progress"].update(Panel(renderable, title="[bold green]Scan Progress Matrix[/bold green]", border_style="green"))
            
    def update_logs(self, msg):
        self.console.print(msg)

dashboard = DashboardManager(shared_console)
