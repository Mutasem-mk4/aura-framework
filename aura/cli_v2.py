"""
Aura v2 — Main CLI Entry Point
This file lives inside the `aura` package so pip can find it via pyproject.toml entry_points.
Route: `aura` command -> aura.cli_v2:main -> dispatches to correct engine.
"""

import asyncio
import sys
import argparse
import os
from aura.ui.formatter import Panel, Table, ZenithUI, console


async def _run_mission(target: str, swarm: bool = False):
    from aura.ui.formatter import dashboard
    from aura.core.orchestrator import NeuralOrchestrator
    try:
        dashboard.start(target)
        orchestrator = NeuralOrchestrator()
        ZenithUI.banner(f"OMNI-SOVEREIGN MISSION", f"Target: {target} | Swarm Mode: {swarm}")
        await orchestrator.execute_advanced_chain(target, swarm_mode=swarm)
    finally:
        dashboard.stop()


async def _run_crawl(target: str, victim: bool = False):
    """Runs authenticated crawler with attacker or victim cookies."""
    from dotenv import load_dotenv
    load_dotenv()
    from aura.modules.auth_crawler import run_crawler

    cookie_key = "AUTH_TOKEN_VICTIM" if victim else "AUTH_TOKEN_ATTACKER"
    cookies = os.getenv(cookie_key, "")

    if not cookies:
        console.print(f"[bold red]❌ {cookie_key} not found in .env![/bold red]")
        console.print("[yellow]Hint: Add your session cookies to the .env file.[/yellow]")
        return

    account_type = "VICTIM" if victim else "ATTACKER"
    console.print(f"[bold cyan]🕷️  Starting Authenticated Crawl: {target} [{account_type} session][/bold cyan]")
    await run_crawler(target, cookies)


def main():
    try:
        if (sys.stdout.encoding or "").lower() != "utf-8":
            sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        pass

    parser = argparse.ArgumentParser(
        prog="aura",
        description="AURA v2 — Professional Bug Bounty & Pentest Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  aura example.com --auto                  # 🚀 Full autopilot: all engines + auto report
  aura example.com --crawl               # Authenticated API crawler (attacker session)
  aura example.com --crawl --victim      # Authenticated API crawler (victim session)
  aura example.com --hunt               # BOLA/IDOR scan only
  aura example.com --auth               # Auth logic scan only
  aura example.com --csrf               # CSRF scan only  
  aura example.com --xss                # XSS scan only
  aura example.com --auto --skip 1,6    # Autopilot but skip Recon (1) and API (6)
  aura --nexus                          # Launch interactive war room
        """
    )

    parser.add_argument("target", nargs="?", help="Target domain (e.g. example.com)")
    parser.add_argument("--auto", action="store_true", help="[v2] 🚀 AUTOPILOT: run ALL engines (recon+auth+csrf+xss+hunt+api+sqli+report)")
    parser.add_argument("--skip", default="", metavar="PHASES", help="[v2] Skip specific autopilot phases by number (e.g. --skip 1,6)")
    parser.add_argument("--profit", action="store_true", help="Calculate ROI for a target")
    parser.add_argument("--earnings", action="store_true", help="Show cumulative projected earnings")
    parser.add_argument("--setup", action="store_true", help="Initialize and check Zenith OS environment")
    parser.add_argument("--status", action="store_true", help="Show Zenith system pulse and metrics")
    parser.add_argument("--aggressive", action="store_true", help="Engage high-impact heavy weapons scanning")
    parser.add_argument("--nexus", action="store_true", help="Launch interactive Nexus War Room")
    parser.add_argument("--auto-submit", action="store_true", help="Enable autonomous bounty submission")
    parser.add_argument("--free-ai", action="store_true", help="Use local Ollama AI (zero cost)")
    parser.add_argument("--crawl", action="store_true", help="[v2] Authenticated crawler — maps all API endpoints")
    parser.add_argument("--hunt", action="store_true", help="[v2] Cross-tenant BOLA/IDOR hunt using attacker+victim sessions")
    parser.add_argument("--report", metavar="FINDINGS_JSON", default=None, help="[v2] AI-analyze a findings JSON and generate Intigriti reports")
    parser.add_argument("--burp", metavar="BURP_XML", default=None, help="[v2] Import Burp Suite HTTP history XML export as discovery map")
    parser.add_argument("--submit", metavar="REPORT_MD", default=None, help="[v2] Auto-submit report to Intigriti/HackerOne")
    parser.add_argument("--dry-run", action="store_true", help="[v2] Preview submission payload without sending (use with --submit)")
    parser.add_argument("--platform", default="intigriti", choices=["intigriti", "h1", "hackerone"], help="[v2] Target platform (default: intigriti)")
    parser.add_argument("--csrf", action="store_true", help="[v2] Scan for CSRF vulnerabilities on discovered mutating endpoints")
    parser.add_argument("--xss", action="store_true", help="[v2] Scan for XSS — Reflected, DOM, and Stored")
    parser.add_argument("--no-headless", action="store_true", help="[v2] Show browser window during XSS scan (debug mode)")
    parser.add_argument("--auth", action="store_true", help="[v2] Auth Logic scan — JWT, password reset, ATO, 2FA bypass, file exposure")
    parser.add_argument("--sqli", action="store_true", help="[v2] SQL Injection scan — Error, Boolean, and Time-based blind")
    parser.add_argument("--web", action="store_true", help="[v2] 🌐 Web Security: CORS + Open Redirect + Rate Limiting + Security Headers")
    parser.add_argument("--ssrf", action="store_true", help="[v2] 📡 SSRF Scan: OOB, Localhost bypass, Cloud Metadata (AWS/GCP/Azure)")
    parser.add_argument("--lfi", action="store_true", help="[v2] 📂 Path Traversal (LFI) Scan: Arbitrary file read on Linux/Windows")
    parser.add_argument("--recon", action="store_true", help="[v2] Recon & JS Secret Scraper — Subdomains, JS keys, Cloud buckets, Ports")
    parser.add_argument("--api", action="store_true", help="[v2] API & GraphQL Fuzzer — Introspection, leaks, unauthorized access")
    parser.add_argument("--victim", action="store_true", help="[v2] Use VICTIM session token for crawl/attack")
    parser.add_argument("--map", default=None, help="[v2] Path to discovery_map.json (auto-detected if omitted)")
    parser.add_argument("--model", default="llama3.1", help="[v2] Ollama model name (default: llama3.1)")
    parser.add_argument("--proxy-file", default=None, help="[v3] Path to a list of proxies for Phantom Routing (WAF evasion)")
    parser.add_argument("--targets", action="store_true", help="[v3] 🎯 Target Hunter: Fetch and display fresh, profitable bug bounty programs")
    parser.add_argument("--web3", action="store_true", help="[v4] 🕸️ Web3 Engine: Audit Smart Contracts (Solidity/Rust) via AI and SAST tools")
    parser.add_argument("--ast", action="store_true", help="[v38] 🔬 Semantic AST Taint Analysis (Zero-FP JS auditing)")
    parser.add_argument("--logic-fuzz", action="store_true", help="[v38] 🧠 Stateful Logic Fuzzer (DAG-based API testing)")
    parser.add_argument("--clinic", action="store_true", help="[v4] 🎓 CLINIC MODE: Educational tooltips for beginners")
    parser.add_argument("--swarm", action="store_true", help="[Phase 7] 🌩️ DISTRIBUTED SWARM: Dispatch tasks to RabbitMQ/Celery cluster")

    args = parser.parse_args()

    ZenithUI.show_startup_banner()

    if args.setup:
        # from rich.panel import Panel
        # from rich.table import Table
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
        total_payout = 0
        for f in findings:
            payout_str = profit_engine.estimate_payout(f.get('finding_type', 'Vulnerability'), f.get('severity', 'MEDIUM'))
            try:
                # Basic extraction of the first number in the range, e.g., "$500 - $1000" -> 500
                payout = int(payout_str.split('$')[1].split('-')[0].strip().replace(',', ''))
                total_payout += payout
            except (IndexError, ValueError):
                continue
        console.print(f"[bold green]💰 Total Cumulative Projected Earnings: ${total_payout:,}[/bold green]")
        return

    if args.profit and args.target:
        from aura.core.profit_engine import profit_engine
        from aura.core.storage import AuraStorage
        storage = AuraStorage()
        findings = storage.get_findings_by_target(args.target)
        if not findings:
            console.print(f"[yellow]No findings for {args.target} found in local DB.[/yellow]")
            return
        total_roi = 0
        for f in findings:
            total_roi += profit_engine.calculate_roi(f.get('finding_type', 'Vulnerability'), f.get('severity', 'MEDIUM'))
        avg_roi = total_roi / len(findings)
        console.print(f"[bold cyan]💹 Target ROI Score for {args.target}: {avg_roi:.2f}[/bold cyan]")
        return

    if args.free_ai:
        state.OPENROUTER_FREE_MODE = True
        console.print("[bold cyan][AI] Zero-Cost Ollama Engine engaged.[/bold cyan]")

    if args.auto_submit:
        state.AUTO_SUBMIT = True
        console.print("[bold red][!] Autonomous Submission Protocol enabled.[/bold red]")

    if args.clinic:
        state.CLINIC_MODE = True
        state.BEGINNER_MODE = True
        console.print("[bold yellow][🎓] Educational Clinic Mode engaged.[/bold yellow]")

    if args.target and os.path.isfile(args.target):
        targets = []
        # v25.1: Robust encoding detection for Windows-generated target files
        content = ""
        for enc in ['utf-8-sig', 'utf-16', 'latin-1']:
            try:
                with open(args.target, "r", encoding=enc) as f:
                    content = f.read()
                    if content: break
            except Exception:
                continue
        
        if content:
            # Clean null bytes and non-printable artifacts common in UTF-16 mismatches
            lines = content.splitlines()
            for line in lines:
                clean_line = line.strip().replace('\x00', '')
                if clean_line and not clean_line.startswith("#"):
                    # Double-check for non-ASCII artifacts at start
                    clean_line = "".join(filter(lambda x: x.isprintable(), clean_line))
                    targets.append(clean_line)

        console.print(f"[bold green]🎯 Mass Ingestion Mode: Processing {len(targets)} targets from {args.target}[/bold green]")
        for t in targets:
            if args.auto:
                console.print(f"\n[bold magenta]🚀 Mission Start: {t}[/bold magenta]")
                asyncio.run(_run_mission(t, swarm=args.swarm))
            else:
                # Handle other flags if needed, or default to standard mission
                asyncio.run(_run_mission(t, swarm=args.swarm))
        return

    if args.auto and args.target:
        # Re-route the standard `--auto` flag to Zenith Absolute Singularity Mode
        console.print("[bold red][!] RE-ROUTING --auto TO ZENITH PROTOCOL...[/bold red]")
        asyncio.run(_run_mission(args.target, swarm=args.swarm))
    elif args.nexus:
        import webbrowser
        import subprocess
        import time
        from aura.core.orchestrator import NeuralOrchestrator
        from aura.core.nexus import launch_nexus
        
        # 1. Start the API Server in the background
        console.print("[bold green][🌐] Starting Nexus API Server...[/bold green]")
        # Since this is running as a package, we find server.py relative to this file
        current_dir = os.path.dirname(os.path.abspath(__file__))
        api_path = os.path.join(current_dir, "api", "server.py")
        
        subprocess.Popen(
            [sys.executable, api_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        )
        
        # 2. Wait a moment for the server to bind
        time.sleep(2)
        
        # 3. Automatically open the browser
        console.print("[bold cyan][🚀] Opening Nexus Dashboard at http://localhost:8000[/bold cyan]")
        webbrowser.open("http://localhost:8000")
        
        # 4. Launch the interactive CLI War Room
        orchestrator = NeuralOrchestrator()
        launch_nexus(orchestrator)
    elif args.targets:
        from aura.modules.target_hunter import run_hunter
        run_hunter()
    elif args.crawl and args.target:
        asyncio.run(_run_crawl(args.target, victim=args.victim))
    elif args.hunt and args.target:
        from aura.modules.idor_engine_v2 import run_hunt
        console.print(f"[bold red]🔥 BOLA/IDOR Hunt: {args.target}[/bold red]")
        run_hunt(args.target, discovery_map_path=args.map)
    elif args.report:
        from aura.modules.ai_analyst import run_report
        console.print(f"[bold cyan]🧠 AI Security Analyst: {args.report}[/bold cyan]")
        model = getattr(args, 'model', 'llama3.1')
        run_report(args.report, model=model)
    elif args.burp:
        from aura.modules.burp_reader import run_burp_import
        console.print(f"[bold yellow]📊 Importing Burp XML: {args.burp}[/bold yellow]")
        target = getattr(args, 'target', None)
        run_burp_import(args.burp, target=args.target)
    elif args.submit:
        from aura.modules.submitter_v2 import run_submit
        dry = getattr(args, 'dry_run', False)
        plat = getattr(args, 'platform', 'intigriti')
        mode_label = "[DRY RUN]" if dry else ""
        console.print(f"[bold green]🚀 Submitting to {plat.upper()} {mode_label}: {args.submit}[/bold green]")
        run_submit(args.submit, platform=plat, dry_run=dry)
    elif args.csrf and args.target:
        from aura.modules.csrf_engine import run_csrf_scan
        console.print(f"[bold red]🔴 CSRF Scan: {args.target}[/bold red]")
        run_csrf_scan(args.target, discovery_map_path=args.map)
    elif args.xss and args.target:
        from aura.modules.xss_engine import run_xss_scan
        headless = not getattr(args, 'no_headless', False)
        console.print(f"[bold yellow]🟡 XSS Scan: {args.target} ({'headless' if headless else 'visible browser'})[/bold yellow]")
        run_xss_scan(args.target, discovery_map_path=args.map, headless=headless)
    elif args.auth and args.target:
        from aura.modules.auth_engine import run_auth_scan
        console.print(f"[bold bright_red]🔐 Auth Logic Scan: {args.target}[/bold bright_red]")
        run_auth_scan(args.target)
    elif args.sqli and args.target:
        from aura.modules.sqli_engine import run_sqli_scan
        console.print(f"[bold yellow]🟠 SQLi Scan: {args.target}[/bold yellow]")
        run_sqli_scan(args.target, discovery_map_path=args.map)
    elif args.web and args.target:
        from aura.modules.web_engine import run_web_scan
        console.print(f"[bold bright_blue]🛡️  Web Security Scan: {args.target}[/bold bright_blue]")
        run_web_scan(args.target)
    elif args.ssrf and args.target:
        from aura.modules.ssrf_engine import run_ssrf_scan
        console.print(f"[bold red]📡 SSRF Scan: {args.target}[/bold red]")
        run_ssrf_scan(args.target, discovery_map_path=args.map)
    elif args.lfi and args.target:
        from aura.modules.lfi_engine import run_lfi_scan
        console.print(f"[bold yellow]📂 Path Traversal (LFI) Scan: {args.target}[/bold yellow]")
        run_lfi_scan(args.target, discovery_map_path=args.map)
    elif args.recon and args.target:
        from aura.modules.recon_engine import run_recon
        console.print(f"[bold cyan]🔍 Recon Mode: {args.target}[/bold cyan]")
        run_recon(args.target)
    elif args.api and args.target:
        from aura.modules.api_engine import run_api_scan
        console.print(f"[bold bright_magenta]🎯 API & GraphQL Scan: {args.target}[/bold bright_magenta]")
        asyncio.run(run_api_scan(args.target, discovery_map_path=args.map))
    elif args.web3 and args.target:
        from aura.modules.web3_engine import run_web3_audit
        console.print(f"[bold purple]🕸️  Web3 Smart Contract Audit: {args.target}[/bold purple]")
        asyncio.run(run_web3_audit(args.target))
    elif args.ast and args.target:
        from aura.modules.semantic_ast_engine import SemanticASTAnalyzer
        import httpx
        from bs4 import BeautifulSoup
        
        async def run_ast():
            console.print(f"[bold cyan]🔬 Semantic AST Taint Analysis: {args.target}[/bold cyan]")
            analyzer = SemanticASTAnalyzer(strict_mode=True)
            async with httpx.AsyncClient(verify=False) as session:
                try:
                    target_url = args.target if args.target.startswith("http") else f"https://{args.target}"
                    resp = await session.get(target_url, timeout=15)
                    
                    content_type = resp.headers.get('content-type', '').lower()
                    scripts = []
                    
                    if 'javascript' in content_type:
                        scripts.append(resp.text)
                    else:
                        soup = BeautifulSoup(resp.text, 'html.parser')
                        for script in soup.find_all('script'):
                            if script.string and script.string.strip():
                                scripts.append(script.string.strip())
                            if script.get('src'):
                                console.print(f"[dim]Note: external script {script.get('src')} ignored (fetch directly if needed).[/dim]")
                        
                    if not scripts:
                        console.print("[yellow]No JavaScript found to analyze![/yellow]")
                        return
                        
                    for i, code in enumerate(scripts):
                        console.print(f"\n[bold green]Analyzing Script Block #{i+1}...[/bold green]")
                        findings = await analyzer.analyze(code, source=f"{args.target} (Block #{i+1})")
                        console.print(analyzer.generate_report())
                        
                except Exception as e:
                    console.print(f"[bold red]Failed to fetch target JS: {e}[/bold red]")
        asyncio.run(run_ast())
        
    elif args.logic_fuzz and args.target:
        from aura.modules.stateful_logic_fuzzer import StatefulLogicFuzzer, WorkflowBuilder
        import json
        
        async def run_logic():
            console.print(f"[bold cyan]🧠 Stateful Logic Fuzzer: {args.target}[/bold cyan]")
            
            if args.workflow:
                try:
                    with open(args.workflow, 'r') as f:
                        workflow_json = json.load(f)
                except Exception as e:
                    console.print(f"[bold red]Failed to load workflow JSON: {e}[/bold red]")
                    return
            else:
                # Default tiny workflow piece if nothing supplied
                workflow_json = [{"method": "GET", "path": "/"}]
                
            target_base = args.target if args.target.startswith("http") else f"https://{args.target}"
            fuzzer = StatefulLogicFuzzer(base_url=target_base)
            steps = fuzzer.define_workflow("cli_test", workflow_json)
            result = await fuzzer.execute_workflow(steps)
            
            if result.findings:
                console.print(f"[bold red]Found {len(result.findings)} Logic Vulnerabilities![/bold red]")
            else:
                console.print("[green]No specific logic findings located dynamically.[/green]")
                
        asyncio.run(run_logic())
    elif args.target:
        asyncio.run(_run_mission(args.target, swarm=args.swarm))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
