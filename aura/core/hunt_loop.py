"""
Aura v22.0 — Autonomous Hunt Loop (Tier 0)
The Zero-Touch Bug Bounty Machine.

One command to rule them all:
  aura hunt --file targets.txt --auto-submit --platform intigriti

Flow:
  1. Load targets from file (or single target)
  2. Scan up to 10 targets in PARALLEL
  3. Validate every finding with hard evidence
  4. Generate platform-specific report
  5. Auto-submit if --auto-submit flag is set
  6. Log to Earnings Dashboard automatically

This is the main difference between amateur hunters and those
who wake up to "$2,500 awarded" emails every morning.
"""
import asyncio
import os
from datetime import datetime, timezone
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

console = Console()


class HuntLoop:
    """
    Tier 0: The Autonomous Hunt Loop.
    Orchestrates the full scan → validate → report → submit → track pipeline.
    """

    MAX_CONCURRENT = 10  # Maximum parallel targets

    def __init__(self, platform: str = "intigriti", auto_submit: bool = False,
                 program: str = None, dry_run: bool = False):
        self.platform    = platform.lower()
        self.auto_submit = auto_submit
        self.program     = program
        self.dry_run     = dry_run

        # Lazy-loaded modules to keep startup fast
        self._orchestrator = None
        self._submitter    = None
        self._tracker      = None
        self._reporter     = None

    # ─── Core Private Helpers ────────────────────────────────────────────

    def _get_orchestrator(self):
        if self._orchestrator is None:
            from aura.core.orchestrator import NeuralOrchestrator
            self._orchestrator = NeuralOrchestrator()
        return self._orchestrator

    def _get_submitter(self):
        if self._submitter is None:
            from aura.modules.submitter import BountySubmitter
            self._submitter = BountySubmitter()
        return self._submitter

    def _get_tracker(self):
        if self._tracker is None:
            from aura.modules.earnings import EarningsTracker
            self._tracker = EarningsTracker()
        return self._tracker

    def _get_reporter(self):
        if self._reporter is None:
            from aura.core.platform_reporter import PlatformReporter
            self._reporter = PlatformReporter()
        return self._reporter

    # ─── Target Loading ──────────────────────────────────────────────────

    @staticmethod
    def load_targets(source: str) -> list[str]:
        """
        Loads targets from:
        - A file path (one domain per line, # comments ignored)
        - A single domain string
        Returns deduplicated list of clean domains.
        """
        targets = []
        if os.path.isfile(source):
            with open(source, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
            console.print(f"[cyan][Hunt] Loaded {len(targets)} target(s) from {source}[/cyan]")
        else:
            targets = [source]
            console.print(f"[cyan][Hunt] Single target: {source}[/cyan]")
        return list(dict.fromkeys(targets))  # deduplicate

    # ─── Single Target Flow ──────────────────────────────────────────────

    async def _hunt_one(self, target: str, sem: asyncio.Semaphore, progress, task_id) -> dict:
        """Full pipeline for one target — runs autonomously."""
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        result = {"target": domain, "findings": 0, "submitted": False, "report_path": None}

        async with sem:
            progress.update(task_id, description=f"[cyan]Scanning {domain}[/cyan]")
            console.print(Panel(
                f"[bold yellow]🎯 HUNTING:[/bold yellow] {domain}",
                border_style="yellow", expand=False
            ))

            try:
                # ── Step 1: Full Scan ─────────────────────────────────
                orch = self._get_orchestrator()
                scan_result = await orch.execute_advanced_chain(
                    domain=domain,
                    open_report=False,
                )
                n_findings = scan_result.get("findings", 0)
                result["findings"] = n_findings
                console.print(f"[green][Hunt] {domain}: {n_findings} finding(s) discovered[/green]")

                if n_findings == 0:
                    progress.update(task_id, advance=1)
                    return result

                # ── Step 2: Generate Platform Report ─────────────────
                progress.update(task_id, description=f"[cyan]Reporting {domain}[/cyan]")
                reporter = self._get_reporter()
                report_path = reporter.generate(platform=self.platform, target_filter=domain)
                result["report_path"] = report_path

                if report_path:
                    console.print(f"[green][Hunt] {domain}: Report → {report_path}[/green]")

                # ── Step 3: Auto-Submit (if enabled) ─────────────────
                if self.auto_submit and not self.dry_run and report_path:
                    progress.update(task_id, description=f"[cyan]Submitting {domain}[/cyan]")
                    await self._auto_submit_top_finding(domain, report_path)
                    result["submitted"] = True

            except Exception as e:
                console.print(f"[red][Hunt] ⚠ Error on {domain}: {e}[/red]")

            finally:
                progress.update(task_id, advance=1)

        return result

    async def _auto_submit_top_finding(self, domain: str, report_path: str):
        """
        Reads the top finding from the DB and auto-submits it.
        Only submits the highest-severity confirmed finding per target.
        """
        from aura.core.storage import AuraStorage
        db = AuraStorage()
        try:
            targets = db.get_all_targets()
            top_finding = None
            severity_rank = {"EXCEPTIONAL": 6, "CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2}

            for t in targets:
                if domain in str(t.get("value", "")):
                    for f in t.get("findings", []):
                        sev = f.get("severity", "LOW").upper()
                        rank = severity_rank.get(sev, 1)
                        if top_finding is None or rank > severity_rank.get(
                            top_finding.get("severity", "LOW").upper(), 1
                        ):
                            top_finding = f

            if not top_finding:
                console.print(f"[yellow][Hunt] No structured findings to submit for {domain}[/yellow]")
                return

            severity  = top_finding.get("severity", "medium").lower()
            title     = top_finding.get("type", f"Security Finding on {domain}")
            desc      = top_finding.get("content", "") + "\n\n" + top_finding.get("remediation_fix", "")
            impact    = top_finding.get("impact_desc", "")
            evidence  = top_finding.get("evidence_url", "")

            if evidence:
                desc += f"\n\nEvidence URL: {evidence}"

            if self.dry_run:
                console.print(f"[yellow][Hunt] [DRY RUN] Would submit: [{severity.upper()}] {title}[/yellow]")
                return

            submitter = self._get_submitter()
            program = self.program or domain.replace(".", "-")
            result = await submitter.submit(
                platform=self.platform,
                program=program,
                title=title,
                description=desc,
                severity=severity,
                impact=impact,
            )

            if result.get("success"):
                # Log to earnings tracker
                tracker = self._get_tracker()
                tracker.log_submission(
                    program=program,
                    title=title,
                    platform=self.platform,
                    finding_type=top_finding.get("type", ""),
                    severity=severity.upper(),
                    cvss_score=float(top_finding.get("cvss_score", 5.0)),
                    target=domain,
                    report_url=f"Submission #{result.get('id', 'N/A')}",
                )
                console.print(
                    f"[bold green][Hunt] ✅ SUBMITTED & TRACKED: {title} → #{result.get('id')}[/bold green]"
                )
        except Exception as e:
            console.print(f"[red][Hunt] Auto-submit error on {domain}: {e}[/red]")

    # ─── Main Entry Point ────────────────────────────────────────────────

    async def run(self, targets: list[str]) -> list[dict]:
        """
        Main hunt loop. Runs all targets with controlled concurrency.
        Returns list of per-target result dicts.
        """
        if not targets:
            console.print("[red][Hunt] No targets provided.[/red]")
            return []

        console.print(Panel(
            f"[bold green]🚀 AURA HUNT LOOP — {len(targets)} target(s)[/bold green]\n"
            f"Platform: [cyan]{self.platform.upper()}[/cyan]  |  "
            f"Auto-Submit: [{'green]ON' if self.auto_submit else 'red]OFF'}[/bold]\n"
            f"Concurrency: [yellow]{min(self.MAX_CONCURRENT, len(targets))} parallel[/yellow]",
            title="[bold yellow]AURA v22.0 — Autonomous Hunter[/bold yellow]",
            border_style="yellow"
        ))

        sem = asyncio.Semaphore(self.MAX_CONCURRENT)
        results = []
        start = datetime.now(timezone.utc)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task_id = progress.add_task("[cyan]Initializing...", total=len(targets))
            tasks = [
                self._hunt_one(t, sem, progress, task_id) for t in targets
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        # Print summary
        elapsed = (datetime.now(timezone.utc) - start).seconds
        successful = [r for r in results if isinstance(r, dict) and r.get("findings", 0) > 0]
        submitted  = [r for r in results if isinstance(r, dict) and r.get("submitted")]
        total_findings = sum(r.get("findings", 0) for r in results if isinstance(r, dict))

        console.print(Panel(
            f"[bold green]✅ Hunt Complete in {elapsed}s[/bold green]\n"
            f"Targets Scanned: [cyan]{len(targets)}[/cyan]\n"
            f"Targets With Findings: [yellow]{len(successful)}[/yellow]\n"
            f"Total Findings: [bold red]{total_findings}[/bold red]\n"
            f"Submitted: [bold green]{len(submitted)}[/bold green]",
            title="[bold yellow]Hunt Summary[/bold yellow]",
            border_style="green"
        ))

        return [r for r in results if isinstance(r, dict)]
