"""
Aura v2 — Main Entry Point (Root)
=================================
This script acts as the primary runner for the Aura framework.
It dispatches commands to the specialized modules in the `aura/` package.
"""

import os
import asyncio
import argparse
import socket
import subprocess
import sys
import time
import webbrowser

# v33: Fix Windows Unicode/Encoding issues for Rich/CMD
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except AttributeError:
        # Fallback for older Python versions
        import codecs
        sys.stdout = codecs.getwriter("utf-8")(sys.stdout.detach())
        sys.stderr = codecs.getwriter("utf-8")(sys.stderr.detach())
os.environ["TERM"] = "dumb"
os.environ["NO_COLOR"] = "1"
os.environ["RICH_DISABLE_JUPYTER"] = "1"
try:
    import colorama

    colorama.just_fix_windows_console()
except ImportError:
    pass

try:
    import rich._windows_renderer

    rich._windows_renderer.LegacyWindowsTerm = None
except (AttributeError, ImportError):
    pass

from rich.panel import Panel
from rich.table import Table

from aura.ui.formatter import console

async def _run_mission(target: str, args: argparse.Namespace = None):
    use_new_pipeline = True  # v40.0 Nuclear Mode Force Enabled

    if use_new_pipeline:
        console.print("[bold green][v40.0 BETA] Engaging Decoupled Mission Pipeline...[/bold green]")
        from aura.core.context import MissionContext, FeatureFlags
        from aura.core.injector import get_container
        from aura.core.pipeline import MissionPipeline
        from aura.phases.recon import ReconPhase
        from aura.phases.deconstruction import DeconstructionPhase
        from aura.phases.audit import AuditPhase
        
        flags = FeatureFlags(
            fast_mode=getattr(args, 'fast', False) if args else False,
            beginner_mode=getattr(args, 'clinic', True) if args else True,
            clinic_mode=getattr(args, 'clinic', False) if args else False,
            auto_submit=getattr(args, 'auto_submit', False) if args else False
        )
        context = MissionContext(target_url=target, flags=flags)
        pipeline = MissionPipeline(context)
        container = get_container()

        pipeline.add_phase(
            ReconPhase(
                recon_pipeline=container.build_engine("recon_pipeline"),
                secret_hunter=container.build_engine("secret_hunter"),
                takeover_hunter=container.build_engine("subdomain_takeover"),
            )
        )
        pipeline.add_phase(
            DeconstructionPhase(
                ssti_engine=container.build_engine("ssti_engine"),
                smuggling_engine=container.build_engine("smuggling_engine"),
                ws_oauth_engine=container.build_engine("ws_oauth_engine"),
                logic_fuzzer=container.build_engine("logic_fuzzer"),
                brain=container.brain,
            )
        )
        pipeline.add_phase(
            AuditPhase(
                power_stack=container.build_engine("power_stack"),
                nuclei_engine=container.build_engine("nuclei_engine"),
                singularity=container.build_engine("aura_singularity"),
                dast=container.build_engine("aura_dast"),
                fleet_manager=container.build_engine("fleet_manager"),
                apex=container.build_engine("apex_sentinel"),
                bounty_reporter=container.build_engine("bounty_reporter"),
            )
        )

        _t0 = time.time()
        result = await pipeline.execute_all()
        elapsed = time.time() - _t0
        
        if result.get("status") == "COMPLETE":
            console.print(f"\n[bold green][MISSION SUCCESS][/bold green] Target: {target} | Findings: {result.get('findings', 0)} | Time: {elapsed:.2f}s")
        else:
            console.print(f"\n[bold red][MISSION FAILED][/bold red] Target: {target} | Error: {result.get('error')}")
            
    else:
        from aura.core.orchestrator import NeuralOrchestrator
        orchestrator = NeuralOrchestrator()
        console.print(f"[bold cyan][MISSION] Initializing Omni-Sovereign Mission on: {target}[/bold cyan]")
        await orchestrator.execute_advanced_chain(target)

def _launch_nexus_background():
    # v45.0: Kill any stale server on port 8000
    try:
        # Windows specific find-and-kill on port 8000
        if sys.platform == "win32":
            output = subprocess.check_output('netstat -ano | findstr :8000', shell=True).decode()
            for line in output.splitlines():
                if "LISTENING" in line:
                    pid = line.strip().split()[-1]
                    subprocess.run(['taskkill', '/F', '/PID', pid], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        console.print("[dim yellow][SERVER] Skipping stale-port cleanup; port inspection unavailable.[/dim yellow]")

    console.print("[bold green][SERVER] Starting Nexus API Server...[/bold green]")
    api_path = os.path.join(os.getcwd(), "aura", "api", "server.py")
    subprocess.Popen(
        [sys.executable, api_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
    )
    
    # Robust port check
    success = False
    for i in range(15):
        try:
            with socket.create_connection(("127.0.0.1", 8000), timeout=1):
                success = True
                break
        except OSError:
            time.sleep(1)
            
    if success:
        console.print("[bold cyan][DASHBOARD] Opening Nexus Dashboard at http://localhost:8000[/bold cyan]")
        webbrowser.open("http://localhost:8000")
    else:
        console.print("[bold red][!] Server took too long to start. Please open manually: http://localhost:8000[/bold red]")

def _launch_zenith_ui():
    """v3.0: Launch the React-based Nexus Zenith Dashboard."""
    ui_path = os.path.join(os.getcwd(), "nexus_zenith")
    if not os.path.exists(ui_path):
        console.print("[bold red][!] Nexus Zenith UI directory not found![/bold red]")
        return
        
    console.print("[bold magenta][ZENITH] Initializing Tactical UI...[/bold magenta]")
    
    # Launch Vite dev server in background
    subprocess.Popen(
        ["npm", "run", "dev", "--", "--host"],
        cwd=ui_path,
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
    )
    
    time.sleep(3)
    console.print("[bold cyan][DASHBOARD] Opening Nexus Zenith at http://localhost:5173[/bold cyan]")
    webbrowser.open("http://localhost:5173")

async def _run_crawl(target: str, victim: bool = False):
    from dotenv import load_dotenv
    load_dotenv()
    from aura.modules.auth_crawler import run_crawler
    cookie_key = "AUTH_TOKEN_VICTIM" if victim else "AUTH_TOKEN_ATTACKER"
    cookies = os.getenv(cookie_key, "")
    if not cookies:
        console.print(f"[bold red][!] {cookie_key} not found in .env![/bold red]")
        return
    account_type = "VICTIM" if victim else "ATTACKER"
    console.print(f"[bold cyan][CRAWL] Starting Authenticated Crawl: {target} [{account_type} session][/bold cyan]")
    await run_crawler(target, cookies)

def main():
    parser = argparse.ArgumentParser(
        prog="aura",
        description="AURA v2 — Professional Bug Bounty & Pentest Framework"
    )
    # v1 legacy support
    parser.add_argument("target", nargs="?", help="Target domain")
    parser.add_argument("--profit", action="store_true", help="Calculate ROI for a target")
    parser.add_argument("--earnings", action="store_true", help="Show cumulative projected earnings")
    parser.add_argument("--submit", metavar="FILE", help="Submit a report to a bounty platform")
    parser.add_argument("--setup", action="store_true", help="Initialize and check Zenith OS environment")
    parser.add_argument("--status", action="store_true", help="Show Zenith system pulse and metrics")
    parser.add_argument("--aggressive", action="store_true", help="Engage high-impact heavy weapons scanning")
    parser.add_argument("--nexus", action="store_true", help="Launch the Nexus C2 Dashboard")
    parser.add_argument("--auto-submit", action="store_true", help="Enable autonomous submission")
    parser.add_argument("--free-ai", action="store_true", help="Use local AI (Ollama)")
    parser.add_argument("--fast", action="store_true", help="Enable stealth & speed optimization")
    
    # v2 new flags
    parser.add_argument("--crawl", action="store_true", help="Authenticated API crawler")
    parser.add_argument("--hunt", action="store_true", help="BOLA/IDOR hunt")
    parser.add_argument("--report", metavar="FILE", help="AI-analyze findings")
    parser.add_argument("--burp", metavar="FILE", help="Import Burp XML")
    parser.add_argument("--dry-run", action="store_true", help="Preview submission")
    parser.add_argument("--csrf", action="store_true", help="Scan for CSRF")
    parser.add_argument("--xss", action="store_true", help="Scan for XSS")
    parser.add_argument("--auth", action="store_true", help="Auth logic scan")
    parser.add_argument("--sqli", action="store_true", help="SQL Injection scan")
    parser.add_argument("--web", action="store_true", help="[v2] Web Security: CORS + Open Redirect + Rate Limiting + Headers")
    parser.add_argument("--ssrf", action="store_true", help="[v2] SSRF Engine — OOB, Localhost, Cloud Metadata")
    parser.add_argument("--lfi", action="store_true", help="[v2] Path Traversal / LFI Engine")
    parser.add_argument("--recon", action="store_true", help="[v2] Recon & JS Scraper")
    parser.add_argument("--api", action="store_true", help="API & GraphQL Fuzzer")
    parser.add_argument("--web3", action="store_true", help="[v3] Web3 Smart Contract Auditing Engine")
    parser.add_argument("--ast", action="store_true", help="[v38] Semantic AST Taint Analysis (Zero-FP JS auditing)")
    parser.add_argument("--logic-fuzz", action="store_true", help="[v38] Stateful Logic Fuzzer (DAG-based API testing)")
    parser.add_argument("--workflow", default=None, metavar="JSON_FILE", help="[v38] Load workflow from JSON file for the Logic Fuzzer")
    
    parser.add_argument("--auto", action="store_true", help="AUTOPILOT: run ALL engines automatically")
    parser.add_argument("--skip", default="", metavar="PHASES", help="Skip phases by number (e.g. --skip 1,6)")
    parser.add_argument("--victim", action="store_true", help="Use victim session")
    parser.add_argument("--map", help="Path to discovery map")
    parser.add_argument("--model", default="llama3.1", help="Ollama model")
    parser.add_argument("--proxy-file", default=None, help="[v3] Path to a list of proxies for Phantom Routing (WAF evasion)")
    parser.add_argument("--targets", action="store_true", help="[v3] Target Hunter: Fetch and display fresh, profitable bug bounty programs")
    parser.add_argument("--experimental-orchestrator", action="store_true", help="[Dev] Run the new decoupled Mission Pipeline")
    parser.add_argument("--clinic", action="store_true", help="[v4] CLINIC MODE: Educational tooltips for beginners")
    parser.add_argument("--ui", action="store_true", help="[v3] Launch the Nexus Zenith Tactical Dashboard (React v3.0)")

    args = parser.parse_args()

    # Legacy support mappings for state
    if args.free_ai: os.environ["OPENROUTER_FREE_MODE"] = "1"
    if args.auto_submit: os.environ["AUTO_SUBMIT"] = "1"
    if args.clinic: os.environ["CLINIC_MODE"] = "1"
    if args.fast: os.environ["FAST_MODE"] = "1"

    if args.setup:
        console.print(Panel("[bold cyan]Zenith OS: Global Environment Initialization[/bold cyan]"))
        checks = [
            ("Brain Engine (Gemini)", os.getenv("GEMINI_API_KEY")),
            ("HackerOne API", os.getenv("H1_API_TOKEN")),
            ("Intigriti API", os.getenv("INTIGRITI_API_TOKEN")),
            ("Ollama (Local AI)", os.getenv("OLLAMA_HOST"))
        ]
        table = Table(title="Dependency Status")
        table.add_column("Component", style="cyan")
        table.add_column("Status", style="bold")
        for name, key in checks:
            status = "[green]ONLINE[/green]" if key else "[red]OFFLINE[/red]"
            table.add_row(name, status)
        console.print(table)
        console.print("[yellow]Initial setup complete. Ready for the hunt.[/yellow]")
        return

    if args.status:
        from aura.core.storage import AuraStorage
        storage = AuraStorage()
        stats = storage.get_stats()
        console.print(Panel(
            f"Aura v33 Zenith [Pulse: STABLE]\n"
            f"Findings Captured: {stats['findings']}\n"
            f"Targets Mapped: {stats['targets']}\n"
            f"Autopilot: {'ENABLED' if args.auto else 'DISABLED'}\n"
            f"AI Validation: {'ACTIVE' if os.getenv('GEMINI_API_KEY') or os.getenv('OLLAMA_HOST') else 'OFFLINE'}",
            title="Zenith System Status"
        ))
        return

    if args.earnings:
        from aura.core.storage import AuraStorage
        from aura.core.profit_engine import profit_engine
        storage = AuraStorage()
        findings = storage.get_all_findings()
        total = 0.0
        for f in findings:
            # Finding: (id, target, content, type, severity, ts, campaign_id)
            total += profit_engine.calculate_roi(f[3], f[4]) * 100 # Rough USD estimation
        console.print(Panel(f"[bold green]💰 Total Global Earnings (Projected): ${total:,.2f}[/bold green]", title="Zenith Profit Engine"))
        return

    if args.submit:
        from aura.modules.submitter_v2 import run_submit
        run_submit(args.submit, dry_run=True)
        return

    if args.profit and args.target:
        from aura.core.profit_engine import profit_engine
        from aura.core.storage import AuraStorage
        storage = AuraStorage()
        findings = storage.get_all_findings()
        target_findings = [f for f in findings if f[1] == args.target]
        score = profit_engine.get_priority_score(args.target, [{"type": f[3], "severity": f[4]} for f in target_findings])
        payout = profit_engine.estimate_payout("RCE", "CRITICAL") # Example top tier
        console.print(Panel(f"Target: {args.target}\nROI Score: {score}\nMax Potential: {payout}", title="Zenith ROI Analysis"))
        return

    if args.ui:
        _launch_zenith_ui()
        return

    if args.nexus:
        _launch_nexus_background()
        if not args.target and not args.hunt and not args.targets:
            from aura.core.orchestrator import NeuralOrchestrator
            from aura.core.nexus import launch_nexus
            launch_nexus(NeuralOrchestrator())
            return

    if args.auto and args.target:
        console.print(f"[bold red][!] AUTO FLAG DETECTED - ENGAGING ZENITH PROTOCOL[/bold red]")
        asyncio.run(_run_mission(args.target, args))
    elif args.targets:
        from aura.modules.target_hunter import run_hunter
        run_hunter()
    elif args.crawl and args.target:
        asyncio.run(_run_crawl(args.target, victim=args.victim))
    elif args.hunt:
        from aura.core.orchestrator import NeuralOrchestrator
        orchestrator = NeuralOrchestrator()
        if args.target:
            # Targeted Hunt
            from aura.modules.idor_engine_v2 import run_hunt
            run_hunt(args.target, discovery_map_path=args.map)
        else:
            # Autonomous Eternal Hunt
            asyncio.run(orchestrator.execute_hunt())
    elif args.report:
        from aura.modules.ai_analyst import run_report
        run_report(args.report, model=args.model)
    elif args.burp:
        from aura.modules.burp_reader import run_burp_import
        run_burp_import(args.burp, target=args.target)
    elif args.submit:
        from aura.modules.submitter_v2 import run_submit
        run_submit(args.submit, dry_run=args.dry_run)
    elif args.csrf and args.target:
        from aura.modules.csrf_engine import run_csrf_scan
        run_csrf_scan(args.target, discovery_map_path=args.map)
    elif args.xss and args.target:
        from aura.modules.xss_engine import run_xss_scan
        run_xss_scan(args.target, discovery_map_path=args.map)
    elif args.auth and args.target:
        from aura.modules.auth_engine import run_auth_scan
        run_auth_scan(args.target)
    elif args.sqli and args.target:
        from aura.modules.sqli_engine import run_sqli_scan
        run_sqli_scan(args.target, discovery_map_path=args.map)
    elif args.web and args.target:
        from aura.modules.web_engine import run_web_scan
        console.print(f"[bold bright_blue][WEB] Web Security Scan: {args.target}[/bold bright_blue]")
        run_web_scan(args.target)
    elif args.ssrf and args.target:
        from aura.modules.ssrf_engine import run_ssrf_scan
        console.print(f"[bold red][SSRF] SSRF Scan: {args.target}[/bold red]")
        run_ssrf_scan(args.target, discovery_map_path=args.map)
    elif args.lfi and args.target:
        from aura.modules.lfi_engine import run_lfi_scan
        console.print(f"[bold yellow][LFI] Path Traversal (LFI) Scan: {args.target}[/bold yellow]")
        run_lfi_scan(args.target, discovery_map_path=args.map)
    elif args.recon and args.target:
        from aura.modules.recon_engine import run_recon
        run_recon(args.target)
    elif args.api and args.target:
        from aura.modules.api_engine import run_api_scan
        asyncio.run(run_api_scan(args.target, discovery_map_path=args.map))
    elif args.web3 and args.target:
        from aura.modules.web3_engine import run_web3_audit
        asyncio.run(run_web3_audit(args.target))
    elif args.logic_fuzz and args.target:
        from aura.modules.stateful_logic_fuzzer import run_logic_fuzz
        asyncio.run(run_logic_fuzz(args.target, workflow_path=args.workflow))
    elif args.ast and args.target:
        from aura.modules.semantic_ast_engine import run_ast_audit
        asyncio.run(run_ast_audit(args.target))
    elif args.target:
        asyncio.run(_run_mission(args.target, args))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
