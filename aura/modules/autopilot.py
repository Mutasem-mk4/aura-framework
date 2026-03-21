"""
Aura v2 — AUTOPILOT ENGINE
============================
One command to scan everything, find real bugs, and write a ready-to-submit report.

  aura www.target.com --auto

What it does automatically:
  Phase 1 — Recon:       Subdomains, open ports, JS secrets, cloud buckets
  Phase 2 — Auth:        Sensitive files, JWT, password reset, 2FA, email ATO
  Phase 3 — CSRF:        Form discovery + cross-origin test
  Phase 4 — XSS:         HTTP reflection check + Playwright confirmation
  Phase 5 — Hunt(IDOR):  Single-account probe + blind API sweep
  Phase 6 — API:         GraphQL introspection, PII leak, broken access
  Phase 7 — SQLi:        Error/Boolean/Time-based injection scan
  Phase 8 — Report:      Professional report + Submission Coach for each finding

The autopilot skips failed/hanging engines and continues to the next one.
At the end it shows a beautiful summary dashboard with everything found.
"""

import asyncio
import json
import os
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.rule import Rule
from rich import box

from aura.ui.formatter import console

# ─── Phase Registry ──────────────────────────────────────────────────────────

PHASES = [
    {"id": 1, "name": "Recon & JS Secrets",   "icon": "🔍", "flag": "recon",  "color": "cyan"},
    {"id": 2, "name": "Web Security",          "icon": "🌐", "flag": "web",    "color": "bright_blue"},
    {"id": 3, "name": "SSRF Detection",        "icon": "📡", "flag": "ssrf",   "color": "red"},
    {"id": 4, "name": "Path Traversal (LFI)",  "icon": "📂", "flag": "lfi",    "color": "yellow"},
    {"id": 5, "name": "Auth Logic",            "icon": "🔐", "flag": "auth",   "color": "bright_red"},
    {"id": 6, "name": "CSRF",                  "icon": "🔴", "flag": "csrf",   "color": "red"},
    {"id": 7, "name": "XSS",                   "icon": "🟡", "flag": "xss",    "color": "yellow"},
    {"id": 8, "name": "BOLA / IDOR Hunt",      "icon": "🎯", "flag": "hunt",   "color": "magenta"},
    {"id": 9, "name": "API & GraphQL",         "icon": "🔮", "flag": "api",    "color": "bright_magenta"},
    {"id": 10, "name": "SQL Injection",        "icon": "🟠", "flag": "sqli",   "color": "orange1"},
    {"id": 11, "name": "Race Conditions",      "icon": "⚡", "flag": "race",   "color": "red_violet"},
    {"id": 12, "name": "JWT & ATO",            "icon": "🎟",  "flag": "jwt",    "color": "bright_cyan"},
    {"id": 13, "name": "HTTP Smuggling",       "icon": "📦", "flag": "smuggle","color": "orange3"},
    {"id": 14, "name": "Template Injection",   "icon": "🧨", "flag": "ssti",   "color": "red1"},
    {"id": 15, "name": "Prototype Pollution",  "icon": "🧬", "flag": "prototype","color":"bright_magenta"},
    {"id": 16, "name": "Report Generation",    "icon": "📋", "flag": "report", "color": "green"},
]


class AuraAutopilot:
    """
    Full-autopilot bug bounty scanner.
    Chains all Aura engines sequentially, collects ALL findings,
    generates professional reports for each, and shows a unified dashboard.
    """

    def __init__(self, target: str, skip_phases: list[int] = None, output_dir: str = "./reports", proxy_file: Optional[str] = None):
        if not target.startswith("http"):
            self.target = "https://" + target
        else:
            self.target = target
        self.target_domain = target.replace("https://", "").replace("http://", "").rstrip("/")
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.skip_phases = skip_phases or []
        self.proxy_file = proxy_file

        # Results
        self.all_findings: list[dict] = []
        self.phase_results: dict[str, dict] = {}
        self.discovery_map_path: Optional[str] = None

        # Load env
        try:
            from dotenv import load_dotenv
            load_dotenv()
        except ImportError:
            pass

        self.attacker_cookies = os.getenv("AUTH_TOKEN_ATTACKER", "")
        self.victim_cookies = os.getenv("AUTH_TOKEN_VICTIM", "")

    def _print_banner(self):
        console.print()
        console.print(Panel.fit(
            f"[bold white]⚡  A U R A  —  A U T O P I L O T  M O D E  ⚡[/bold white]\n"
            f"[cyan]Target: {self.target}[/cyan]\n"
            f"[dim]Running {len(PHASES)} attack phases automatically...[/dim]",
            box=box.DOUBLE_EDGE,
            style="bold bright_blue",
            padding=(1, 4),
        ))
        console.print()

    def _print_phase_header(self, phase: dict):
        console.print()
        console.print(Rule(
            f"[bold {phase['color']}]{phase['icon']} Phase {phase['id']}: {phase['name']}[/bold {phase['color']}]",
            style=phase["color"]
        ))
        console.print()

    def _record_phase(self, flag: str, findings: list, elapsed: float, error: str = ""):
        self.phase_results[flag] = {
            "findings": findings,
            "count": len(findings),
            "elapsed": elapsed,
            "error": error,
        }
        self.all_findings.extend(findings)

    # ─── Phase Runners ────────────────────────────────────────────────────────

    def _run_phase_recon(self) -> list:
        try:
            from aura.modules.recon_engine import ReconEngine
            engine = ReconEngine(self.target_domain, output_dir=str(self.output_dir), proxy_file=self.proxy_file)
            report = engine.run()
            # Recon findings are informational — collect any secrets and takeovers found
            secrets = report.get("secrets", [])
            takeovers = report.get("takeover_findings", [])
            findings = [{"type": "JS Secret", "url": s.get("source", self.target), **s} for s in secrets] if secrets else []
            for t in takeovers:
                if "url" not in t: t["url"] = t.get("subdomain", self.target)
            findings.extend(takeovers)
            return findings
        except Exception as e:
            raise RuntimeError(f"Recon: {e}")

    def _run_phase_web(self) -> list:
        try:
            from aura.modules.web_engine import WebSecurityEngine
            from aura.modules.frontend_deconstructor import FrontendDeconstructor
            findings = []
            
            # Professional Tier: Frontend Deconstructor
            fe_deconstructor = FrontendDeconstructor(target=self.target)
            fe_findings = asyncio.run(fe_deconstructor.run()) or []
            findings.extend(fe_findings)
            
            engine = WebSecurityEngine(
                target=self.target,
                cookies_str=self.attacker_cookies,
                output_dir=str(self.output_dir),
                proxy_file=self.proxy_file
            )
            findings.extend(engine.run() or [])
            return findings
        except Exception as e:
            raise RuntimeError(f"Web: {e}")

    def _run_phase_ssrf(self) -> list:
        try:
            from aura.modules.ssrf_engine import SSRFEngine
            map_data = {}
            if self.discovery_map_path and Path(self.discovery_map_path).exists():
                with open(self.discovery_map_path, "r", encoding="utf-8-sig") as f:
                    map_data = json.load(f)
            
            engine = SSRFEngine(
                target=self.target,
                cookies_str=self.attacker_cookies,
                output_dir=str(self.output_dir),
            )
            return engine.run(map_data)
        except Exception as e:
            raise RuntimeError(f"SSRF: {e}")

    def _run_phase_lfi(self) -> list:
        try:
            from aura.modules.lfi_engine import LFIEngine
            map_data = {}
            if self.discovery_map_path and Path(self.discovery_map_path).exists():
                with open(self.discovery_map_path, "r", encoding="utf-8-sig") as f:
                    map_data = json.load(f)
            
            engine = LFIEngine(
                target=self.target,
                cookies_str=self.attacker_cookies,
                output_dir=str(self.output_dir),
            )
            return engine.run(map_data)
        except Exception as e:
            raise RuntimeError(f"LFI: {e}")

    def _run_phase_auth(self) -> list:
        try:
            from aura.modules.auth_engine import AuthLogicEngine
            engine = AuthLogicEngine(
                target=self.target,
                cookies_str=self.attacker_cookies,
                output_dir=str(self.output_dir),
            )
            return engine.run()
        except Exception as e:
            raise RuntimeError(f"Auth: {e}")

    def _run_phase_csrf(self) -> list:
        try:
            from aura.modules.csrf_engine import CSRFEngine
            engine = CSRFEngine(
                target=self.target,
                cookies_str=self.attacker_cookies,
                output_dir=str(self.output_dir),
            )
            return engine.run_from_discovery_map(self.discovery_map_path)
        except Exception as e:
            raise RuntimeError(f"CSRF: {e}")

    def _run_phase_xss(self) -> list:
        try:
            from aura.modules.xss_engine import XSSEngine
            discovery_map = None
            if self.discovery_map_path and Path(self.discovery_map_path).exists():
                with open(self.discovery_map_path, encoding="utf-8-sig") as f:
                    discovery_map = json.load(f)
            engine = XSSEngine(
                target=self.target,
                cookies_str=self.attacker_cookies,
                output_dir=str(self.output_dir),
            )
            return asyncio.run(engine.run(discovery_map))
        except Exception as e:
            raise RuntimeError(f"XSS: {e}")

    def _run_phase_hunt(self) -> list:
        try:
            from aura.modules.idor_engine_v2 import BolaTester
            tester = BolaTester(
                target=self.target,
                attacker_cookies=self.attacker_cookies,
                victim_cookies=self.victim_cookies,
            )
            if self.discovery_map_path and Path(self.discovery_map_path).exists():
                return tester.run_from_discovery_map(self.discovery_map_path)
            else:
                return tester._run_blind_probe()
        except Exception as e:
            raise RuntimeError(f"IDOR Hunt: {e}")

    def _run_phase_api(self) -> list:
        try:
            from aura.modules.api_engine import APIEngine
            from aura.modules.graphql_engine import GraphQLBreaker
            from aura.modules.api_reaper import APIReaper
            from aura.modules.graphql_reaper import GraphQLReaper
            from aura.modules.stateful_logic_fuzzer import StatefulLogicFuzzer
            findings = []
            
            # 1. Professional Tier: API Reaper
            api_reaper = APIReaper(target=self.target)
            reaper_findings = asyncio.run(api_reaper.run()) or []
            findings.extend(reaper_findings)
            
            # 2. Professional Tier: GraphQL Reaper
            gql_reaper = GraphQLReaper(target=self.target)
            gql_reaper_findings = asyncio.run(gql_reaper.run()) or []
            findings.extend(gql_reaper_findings)
            
            # 3. Standard API Engine
            api_engine = APIEngine(
                target=self.target,
                discovery_map_path=self.discovery_map_path,
            )
            api_findings = asyncio.run(api_engine.run()) or []
            findings.extend(api_findings)
            
            # 4. Standard GraphQL Breaker
            gql_engine = GraphQLBreaker(target=self.target)
            gql_findings = asyncio.run(gql_engine.run()) or []
            findings.extend(gql_findings)
            
            # 5. Stateful Logic Fuzzer targeting found API endpoints
            endpoints_to_fuzz = []
            for ep in getattr(api_reaper, 'endpoints', []):
                params_dict = {str(k): 1 for k in ep.get("params", {}).keys()}
                fuzz_param_names = list(params_dict.keys())
                if fuzz_param_names or ep.get("method") in ["POST", "PUT"]:
                    endpoints_to_fuzz.append({
                        "method": ep.get("method", "GET"),
                        "path": ep.get("path", "/"),
                        "params": params_dict,
                        "data": params_dict if ep.get("method") != "GET" else {},
                        "fuzz_params": fuzz_param_names,
                        "fuzz_types": ["sqli", "xss", "path_traversal", "negative", "boolean_toggle"]
                    })
                    
            if endpoints_to_fuzz:
                console.print(f"  [⚡] Initiating Stateful Logic Fuzzer on {len(endpoints_to_fuzz)} endpoints...")
                fuzzer = StatefulLogicFuzzer(base_url=self.target)
                workflow = fuzzer.define_workflow("API_Fuzzing_Workflow", endpoints_to_fuzz)
                asyncio.run(fuzzer.execute_workflow(workflow, mutate_only=True))
                for finding in fuzzer.findings:
                    findings.append({
                        "type": finding.vuln_type, 
                        "severity": finding.severity,
                        "url": finding.evidence.get("path", self.target),
                        "content": finding.description,
                        "evidence": finding.evidence
                    })
            
            return findings
        except Exception as e:
            raise RuntimeError(f"API: {e}")

    def _run_phase_sqli(self) -> list:
        try:
            from aura.modules.sqli_engine import SQLiEngine
            engine = SQLiEngine(
                target=self.target,
                cookies_str=self.attacker_cookies,
                output_dir=str(self.output_dir),
            )
            discovery_map = None
            if self.discovery_map_path and Path(self.discovery_map_path).exists():
                with open(self.discovery_map_path, encoding="utf-8-sig") as f:
                    discovery_map = json.load(f)
            return engine.run(discovery_map or {})
        except Exception as e:
            raise RuntimeError(f"SQLi: {e}")

    def _run_phase_race(self) -> list:
        try:
            from aura.modules.race_hunter import RaceConditionHunter
            engine = RaceConditionHunter()
            
            # RaceHunter needs URLs. We'll extract them from the discovery map.
            targets = []
            if self.discovery_map_path and Path(self.discovery_map_path).exists():
                with open(self.discovery_map_path, encoding="utf-8-sig") as f:
                    discovery_map = json.load(f)
                    
                # Extract URLs from the discovery map (which is usually a dict of endpoints or list)
                if isinstance(discovery_map, dict):
                    if "endpoints" in discovery_map:
                        targets = [ep.get("url") for ep in discovery_map["endpoints"] if ep.get("url")]
                    elif "spider_links" in discovery_map:
                        targets = discovery_map["spider_links"]
                elif isinstance(discovery_map, list):
                    targets = discovery_map
            
            if not targets:
                # Fallback to base URL
                targets = [self.target]
                
            return asyncio.run(engine.scan_urls(targets))
        except Exception as e:
            raise RuntimeError(f"Race: {e}")

    def _run_phase_jwt(self) -> list:
        try:
            from aura.modules.jwt_engine import TokenBreaker
            token = os.getenv("AUTH_TOKEN_ATTACKER", "")
            if not token:
                return []
                
            engine = TokenBreaker(target=self.target, token=token)
            
            # Extract endpoints from discovery map
            targets = []
            if self.discovery_map_path and Path(self.discovery_map_path).exists():
                with open(self.discovery_map_path, encoding="utf-8-sig") as f:
                    discovery_map = json.load(f)
                    
                if isinstance(discovery_map, dict):
                    eps = discovery_map.get("mutating_endpoints", []) + discovery_map.get("idor_candidates", [])
                    targets = [ep for ep in eps if "url" in ep]
            
            if not targets:
                targets = [{"url": f"{self.target}/api/v1/profile", "method": "GET"}]
                
            return asyncio.run(engine.scan_urls(targets))
        except Exception as e:
            raise RuntimeError(f"JWT: {e}")

    def _run_phase_smuggle(self) -> list:
        try:
            from aura.modules.smuggle_engine import SmuggleHunter
            engine = SmuggleHunter(
                target=self.target,
                output_dir=str(self.output_dir),
            )
            return asyncio.run(engine.run()) or []
        except Exception as e:
            raise RuntimeError(f"Smuggle: {e}")

    def _run_phase_ssti(self) -> list:
        try:
            from aura.modules.ssti_engine import SSTIReaper
            engine = SSTIReaper(
                target=self.target,
                output_dir=str(self.output_dir),
            )
            
            # Extract endpoints from discovery map
            targets = []
            if self.discovery_map_path and Path(self.discovery_map_path).exists():
                with open(self.discovery_map_path, encoding="utf-8-sig") as f:
                    discovery_map = json.load(f)
                    
                if isinstance(discovery_map, dict):
                    return asyncio.run(engine.run(discovery_map)) or []
                    
            # Fallback
            dummy_map = {"all_api_calls": [{"url": self.target, "method": "GET"}]}
            return asyncio.run(engine.run(dummy_map)) or []
        except Exception as e:
            raise RuntimeError(f"SSTI: {e}")

    def _run_phase_prototype(self) -> list:
        try:
            from aura.modules.prototype_engine import PrototypeEngine
            engine = PrototypeEngine(
                target=self.target,
                output_dir=str(self.output_dir),
            )
            
            targets = []
            if self.discovery_map_path and Path(self.discovery_map_path).exists():
                with open(self.discovery_map_path, encoding="utf-8-sig") as f:
                    discovery_map = json.load(f)
                if isinstance(discovery_map, dict):
                    return asyncio.run(engine.run(discovery_map)) or []
                    
            dummy_map = {"all_api_calls": [{"url": self.target, "method": "GET"}]}
            return asyncio.run(engine.run(dummy_map)) or []
        except Exception as e:
            raise RuntimeError(f"Prototype: {e}")

    def _run_phase_report(self, findings: list) -> list:
        """Generates professional reports AND PoCs for all confirmed findings."""
        if not findings:
            console.print("  [dim]No findings to report — all clean![/dim]")
            return []
        try:
            from aura.modules.ai_analyst import ProfessionalReportGenerator
            from aura.core.brain import AuraBrain
            
            gen = ProfessionalReportGenerator(output_dir=str(self.output_dir))
            brain = AuraBrain()
            generated = []
            for finding in findings:
                try:
                    report_md, title, severity = gen.generate_report(finding, platform="intigriti")
                    import re
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    slug = re.sub(r'[^a-z0-9]', '_', title.lower())[:45]
                    out_path = self.output_dir / f"SUBMIT_{slug}_{ts}.md"
                    out_path.write_text(report_md, encoding="utf-8")
                    console.print(f"  ✅ [green]Report:{severity}[/green] {title[:65]}")
                    console.print(f"     💾 {out_path}")
                    generated.append({"title": title, "severity": severity, "path": str(out_path)})
                    
                    # Autonomous PoC Generation for HIGH/CRITICAL
                    if severity.upper() in ["CRITICAL", "HIGH", "MEDIUM"]:
                        try:
                            console.print(f"  [⚡] Generating Autonomous PoC script for {title}...")
                            script = brain.generate_exploit_script(finding.get("type", "vuln"), finding.get("content", ""), self.target_domain)
                            poc_path = self.output_dir / f"poc_{slug}_{ts}.py"
                            poc_path.write_text(script, encoding="utf-8")
                            console.print(f"     🔥 PoC Extracted: {poc_path}")
                        except Exception as p_e:
                            console.print(f"     [dim red]PoC generation failed: {p_e}[/dim red]")
                except Exception:
                    continue
            return generated
        except Exception as e:
            raise RuntimeError(f"Report: {e}")

    # ─── Auto-detect discovery map ────────────────────────────────────────────

    def _find_discovery_map(self):
        slug = self.target_domain.replace("www.", "").replace(".", "_")
        candidates = list(Path("./reports").glob(f"discovery_map_{slug}*.json"))
        if candidates:
            self.discovery_map_path = str(sorted(candidates)[-1])
            console.print(f"  📋 Discovery map: [cyan]{self.discovery_map_path}[/cyan]")
        else:
            console.print("  [dim]No discovery map found — engines will use active discovery mode[/dim]")

    # ─── Main Runner ──────────────────────────────────────────────────────────

    def run(self):
        """Runs the full autopilot chain."""
        start_total = time.time()
        self._print_banner()
        self._find_discovery_map()

        phase_runners = {
            "recon":  self._run_phase_recon,
            "web":    self._run_phase_web,
            "ssrf":   self._run_phase_ssrf,
            "lfi":    self._run_phase_lfi,
            "auth":   self._run_phase_auth,
            "csrf":   self._run_phase_csrf,
            "xss":    self._run_phase_xss,
            "hunt":   self._run_phase_hunt,
            "api":    self._run_phase_api,
            "sqli":   self._run_phase_sqli,
            "race":   self._run_phase_race,
            "jwt":    self._run_phase_jwt,
            "smuggle": self._run_phase_smuggle,
            "ssti":   self._run_phase_ssti,
            "prototype": self._run_phase_prototype,
        }

        all_collected_findings = []

        for phase in PHASES:
            flag = phase["flag"]
            if phase["id"] in self.skip_phases:
                console.print(f"\n[dim]⏭  Phase {phase['id']}: {phase['name']} — SKIPPED[/dim]")
                self._record_phase(flag, [], 0, "skipped")
                continue

            if flag == "report":
                self._print_phase_header(phase)
                t0 = time.time()
                try:
                    reports = self._run_phase_report(all_collected_findings)
                    self._record_phase("report", reports, time.time() - t0)
                except Exception as e:
                    self._record_phase("report", [], time.time() - t0, str(e))
                continue

            self._print_phase_header(phase)
            t0 = time.time()
            try:
                findings = phase_runners[flag]()
                findings = findings or []
                elapsed = time.time() - t0
                self._record_phase(flag, findings, elapsed)
                all_collected_findings.extend(findings)
                status = f"[bold green]✅ {len(findings)} finding(s)[/bold green]" if findings else "[dim]✅ Clean[/dim]"
                console.print(f"\n  {status} — [{elapsed:.1f}s]")
            except Exception as e:
                elapsed = time.time() - t0
                err = str(e)[:100]
                self._record_phase(flag, [], elapsed, err)
                console.print(f"\n  [bold yellow]⚠️  Phase skipped: {err}[/bold yellow]")
                console.print(f"  [dim]Continuing to next phase...[/dim]")

        total_time = time.time() - start_total
        self._print_final_dashboard(total_time)

    def _print_final_dashboard(self, total_time: float):
        """Prints the final summary dashboard."""
        console.print()
        console.print(Rule("[bold white]⚡ AUTOPILOT COMPLETE[/bold white]", style="bright_blue"))
        console.print()

        # Summary table
        table = Table(
            title=f"🎯 Scan Results — {self.target_domain}",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold white on dark_blue",
        )
        table.add_column("Phase",        style="bold", width=22)
        table.add_column("Status",       width=12)
        table.add_column("Findings",     justify="center", width=10)
        table.add_column("Time",         justify="right", width=8)

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        total_findings = 0

        for phase in PHASES:
            flag = phase["flag"]
            result = self.phase_results.get(flag, {})
            count  = result.get("count", 0)
            error  = result.get("error", "")
            elapsed = result.get("elapsed", 0)

            if error == "skipped":
                status = "[dim]─ Skipped[/dim]"
                count_str = "[dim]─[/dim]"
            elif error:
                status = f"[yellow]⚠ Error[/yellow]"
                count_str = "[dim]─[/dim]"
            elif count > 0:
                status = f"[bold red]🚨 Found[/bold red]"
                count_str = f"[bold red]{count}[/bold red]"
                total_findings += count
                # Count severities
                for f in result.get("findings", []):
                    sev = f.get("severity", "").upper()
                    if sev in severity_counts:
                        severity_counts[sev] += 1
            else:
                status = "[green]✅ Clean[/green]"
                count_str = "[green]0[/green]"

            table.add_row(
                f"{phase['icon']} {phase['name']}",
                status,
                count_str,
                f"{elapsed:.0f}s" if elapsed else "─",
            )

        console.print(table)
        console.print()

        # Severity summary
        if total_findings > 0:
            sev_table = Table(box=box.SIMPLE, show_header=False)
            sev_table.add_column(width=12)
            sev_table.add_column(width=8)
            if severity_counts["CRITICAL"]: sev_table.add_row("[bold red]🔴 CRITICAL[/bold red]", f"[bold red]{severity_counts['CRITICAL']}[/bold red]")
            if severity_counts["HIGH"]:     sev_table.add_row("[bold orange1]🟠 HIGH[/bold orange1]", f"[bold orange1]{severity_counts['HIGH']}[/bold orange1]")
            if severity_counts["MEDIUM"]:   sev_table.add_row("[yellow]🟡 MEDIUM[/yellow]", f"[yellow]{severity_counts['MEDIUM']}[/yellow]")
            if severity_counts["LOW"]:      sev_table.add_row("[dim]🟢 LOW[/dim]", f"[dim]{severity_counts['LOW']}[/dim]")
            console.print(sev_table)

        console.print(f"  ⏱  Total time: [cyan]{total_time:.1f}s[/cyan] | 🎯 Total findings: [bold {'red' if total_findings else 'green'}]{total_findings}[/bold {'red' if total_findings else 'green'}]")

        if total_findings > 0:
            console.print()
            console.print(Panel(
                "[bold green]📋 Reports saved to:[/bold green] [cyan]./reports/SUBMIT_*.md[/cyan]\n"
                "[bold]Next steps:[/bold]\n"
                "  1️⃣  Open each [cyan]SUBMIT_*.md[/cyan] report\n"
                "  2️⃣  Follow the [bold]Submission Coach[/bold] section in the report\n"
                "  3️⃣  Record a [bold yellow]PoC video[/bold yellow] (biggest bounty multiplier!)\n"
                "  4️⃣  Submit to [bold cyan]Intigriti[/bold cyan] or [bold cyan]HackerOne[/bold cyan]",
                title="🚀 What To Do Next",
                style="bold green",
                box=box.ROUNDED,
            ))
        else:
            console.print()
            console.print(Panel(
                "[bold yellow]💡 No confirmed findings on this run.[/bold yellow]\n\n"
                "This could mean:\n"
                "  - The target has good security (common for mature programs)\n"
                "  - You need session cookies in .env for deeper authenticated scanning\n"
                "  - Run [cyan]aura www.target.com --crawl[/cyan] first for a richer attack surface\n"
                "  - Try [cyan]aura www.target.com --recon[/cyan] to discover subdomains first",
                title="💡 Tips to Find More",
                style="yellow",
                box=box.ROUNDED,
            ))

        console.print()


def run_autopilot(target: str, skip_phases: list[int] = None, proxy_file: Optional[str] = None):
    """CLI runner for `aura <target> --auto`."""
    pilot = AuraAutopilot(target=target, skip_phases=skip_phases, proxy_file=proxy_file)
    pilot.run()


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "www.iciparisxl.nl"
    run_autopilot(target)
