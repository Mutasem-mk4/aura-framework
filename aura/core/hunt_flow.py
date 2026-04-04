"""
Aura v22.X — HuntFlow: Learn-While-You-Hunt Orchestrator
Guides beginners through Recon -> Learn -> Exploit flow.

Usage:
    from aura.core.hunt_flow import HuntFlow
    asyncio.run(HuntFlow.start_hunt("target.com"))
"""
import asyncio
from datetime import datetime
from typing import Optional, Callable, List, Dict
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()


class HuntFlow:
    """
    Beginner-friendly hunt orchestrator that guides through:
    Phase 1: Recon (scan/analyze) - Discover attack surface
    Phase 2: Learn (clinic tips) - Understand vulnerabilities found
    Phase 3: Exploit (suggestions) - Validate and escalate findings
    """

    def __init__(self, target: str, practice_mode: bool = False):
        self.target = target
        self.practice_mode = practice_mode
        self.findings: List[Dict] = []
        self.attack_paths: List[Dict] = []
        self.db = None  # Will be initialized lazily

        # Check beginner mode
        try:
            from aura.core import state
            self.beginner_mode = getattr(state, 'BEGINNER_MODE', True)
            self.show_clinic_tips = state.FEATURE_FLAGS.get('show_clinic_tips', True)
            self.plain_english_reports = state.FEATURE_FLAGS.get('plain_english_reports', True)
        except Exception:
            self.beginner_mode = True
            self.show_clinic_tips = True
            self.plain_english_reports = True

    def _init_storage(self):
        """Lazy initialization of storage."""
        if self.db is None:
            try:
                from aura.core.storage import AuraStorage
                practice_db = None
                if self.practice_mode:
                    from aura.core.practice_config import PRACTICE_DB
                    practice_db = PRACTICE_DB
                self.db = AuraStorage(db_path=practice_db)
            except Exception as e:
                console.print(f"[dim]Storage init warning: {e}[/dim]")
                self.db = None

    async def run_recon_phase(self) -> List[Dict]:
        """Phase 1: Run reconnaissance."""
        console.print(Panel(
            "[bold cyan]🔍 Phase 1: Reconnaissance[/bold cyan]\n"
            f"Discovering attack surface for: [yellow]{self.target}[/yellow]\n"
            "This may take a few minutes...",
            border_style="cyan",
            padding=(1, 2)
        ))

        findings = []

        try:
            # Import required modules
            from aura.core.orchestrator import NeuralOrchestrator
            from aura.core.analyzer import CorrelationEngine

            orchestrator = NeuralOrchestrator()
            analyzer = CorrelationEngine()

            # Run scan with progress indication
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True
            ) as progress:
                task = progress.add_task("[cyan]Scanning target...", total=None)

                # Run reconnaissance
                try:
                    recon_results = await orchestrator.recon(self.target)

                    if recon_results:
                        findings = analyzer.correlate(recon_results)
                    else:
                        # Fallback - try basic scan
                        findings = await self._basic_scan()
                except Exception as e:
                    console.print(f"[yellow]Recon error: {e}[/yellow]")
                    findings = await self._basic_scan()

                progress.update(task, completed=True)

        except ImportError as e:
            console.print(f"[yellow]Advanced modules not available, using basic scan: {e}[/yellow]")
            findings = await self._basic_scan()
        except Exception as e:
            console.print(f"[red]Recon error: {e}[/red]")
            findings = await self._basic_scan()

        console.print(f"\n[green]✅ Recon complete. Found {len(findings)} initial findings.[/green]\n")
        self.findings = findings
        return findings

    async def _basic_scan(self) -> List[Dict]:
        """Basic fallback scan if NeuralOrchestrator is not available."""
        from aura.modules.scanner import AuraScanner

        scanner = AuraScanner()
        findings = []

        try:
            # Basic subdomain discovery
            subs = await scanner.discover_subdomains(self.target)
            for sub in subs:
                findings.append({
                    "finding_type": "Subdomain Discovery",
                    "severity": "INFO",
                    "url": sub.get("value", ""),
                    "description": f"Found subdomain: {sub.get('value', '')}"
                })
        except Exception as e:
            console.print(f"[dim]Basic scan note: {e}[/dim]")

        return findings

    def run_learn_phase(self, findings: List[Dict]) -> None:
        """Phase 2: Present findings with educational tips."""
        if not findings:
            console.print("[dim]No findings to learn from.[/dim]")
            return

        console.print(Panel(
            "[bold yellow]📚 Phase 2: Learn[/bold yellow]\n"
            "Understanding your findings...\n"
            "Each vulnerability is explained below.",
            border_style="yellow",
            padding=(1, 2)
        ))

        # Show clinic tips
        if self.beginner_mode and self.show_clinic_tips:
            try:
                from aura.modules.clinic import VulnClinic
                VulnClinic.show_phase_tips(findings)
            except Exception as e:
                console.print(f"[dim]Clinic tips unavailable: {e}[/dim]")

        # Print plain-English summary
        if self.beginner_mode and self.plain_english_reports:
            try:
                from aura.core.learning_reporter import LearningReporter
                LearningReporter.print_learning_summary(findings)
            except Exception as e:
                console.print(f"[dim]Learning reporter unavailable: {e}[/dim]")

        console.print("\n[cyan]💡 Run 'aura learn <vuln_type>' for detailed remediation steps.[/cyan]\n")

    async def run_exploit_phase(self, findings: List[Dict]) -> None:
        """Phase 3: Suggest and run exploitation steps."""
        if not findings:
            console.print("[dim]No findings to exploit.[/dim]")
            return

        # Filter exploitable findings
        exploitable = [
            f for f in findings
            if f.get("severity") in ("CRITICAL", "HIGH", "MEDIUM")
        ]

        if not exploitable:
            console.print("[dim]No high-confidence findings to exploit.[/dim]")
            return

        console.print(Panel(
            f"[bold red]⚔️ Phase 3: Exploitation[/bold red]\n"
            f"Validating and escalating {len(exploitable)} potential vulnerabilities...",
            border_style="red",
            padding=(1, 2)
        ))

        # Show top findings with next steps
        for i, finding in enumerate(exploitable[:5], 1):  # Top 5
            vuln_type = finding.get("finding_type", "Unknown")
            severity = finding.get("severity", "MEDIUM")
            url = finding.get("url", "N/A")

            console.print(f"\n[bold][{i}] {vuln_type}[/bold] ({severity})")
            console.print(f"    URL: {url}")

            # Get remediation steps
            try:
                from aura.core.learning_reporter import LearningReporter
                steps = LearningReporter._get_remediation_steps(vuln_type)
                console.print(f"    Next step: {steps[0]}")
            except Exception:
                console.print(f"    Run 'aura exploit {vuln_type}' to test this vulnerability")

        console.print("\n[cyan]💡 Use 'aura exploit' to run exploitation modules on these findings.[/cyan]\n")

    async def run_full_flow(self) -> None:
        """Execute the complete Hunt -> Learn -> Exploit flow."""
        from aura.core import state

        mode_label = "[green]PRACTICE[/green]" if self.practice_mode else "[yellow]PRODUCTION[/yellow]"

        console.print(Panel(
            f"[bold magenta]🎯 AURA Hunt Flow[/bold magenta]\n"
            f"Target: [cyan]{self.target}[/cyan]\n"
            f"Mode: {mode_label}\n"
            f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            border_style="magenta",
            padding=(1, 2)
        ))

        # Safety warning for production
        if not self.practice_mode:
            console.print("\n[bold yellow]⚠️ Production Mode[/bold yellow]")
            console.print("You are about to scan a production target.")
            console.print("Ensure you have authorization before proceeding.\n")

        # Phase 1: Recon
        findings = await self.run_recon_phase()

        # Phase 2: Learn
        self.run_learn_phase(findings)

        # Phase 3: Exploit
        await self.run_exploit_phase(findings)

        # Summary
        self._print_summary(findings)

    def _print_summary(self, findings: List[Dict]) -> None:
        """Print final summary."""
        critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high = sum(1 for f in findings if f.get("severity") == "HIGH")
        medium = sum(1 for f in findings if f.get("severity") == "MEDIUM")
        low = sum(1 for f in findings if f.get("severity") == "LOW")
        info = sum(1 for f in findings if f.get("severity") == "INFO")

        summary_content = f"""[bold]Hunt Summary:[/bold]
Total Findings: {len(findings)}

[red]CRITICAL:[/red] {critical}
[yellow]HIGH:[/yellow] {high}
[cyan]MEDIUM:[/cyan] {medium}
[green]LOW:[/green] {low}
[grey]INFO:[/grey] {info}

[bold]Next Steps:[/bold]
1. Run 'aura learn <type>' to understand any finding
2. Run 'aura exploit <type>' to validate vulnerabilities
3. Run 'aura report' to generate a professional report
4. Submit findings to the bug bounty program"""

        console.print(Panel(
            summary_content,
            title="[bold green]✅ Hunt Flow Complete![/bold green]",
            border_style="green",
            padding=(1, 2)
        ))

    @classmethod
    async def start_hunt(cls, target: str, practice_mode: bool = False) -> None:
        """Start a complete Hunt -> Learn -> Exploit flow."""
        flow = cls(target, practice_mode)

        # Set state flags
        try:
            from aura.core import state
            state.BEGINNER_MODE = True
            if practice_mode:
                state.PRACTICE_MODE = True
                state.FEATURE_FLAGS['practice_mode'] = True
        except Exception:
            pass

        await flow.run_full_flow()
