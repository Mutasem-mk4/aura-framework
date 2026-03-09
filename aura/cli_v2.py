"""
Aura v2 — Main CLI Entry Point
This file lives inside the `aura` package so pip can find it via pyproject.toml entry_points.
Route: `aura` command -> aura.cli_v2:main -> dispatches to correct engine.
"""

import asyncio
import sys
import argparse
import os
from rich.console import Console

console = Console()


async def _run_mission(target: str):
    from aura.core.orchestrator import NeuralOrchestrator
    orchestrator = NeuralOrchestrator()
    console.print(f"[bold cyan]🚀 Initializing Omni-Sovereign Mission on: {target}[/bold cyan]")
    await orchestrator.execute_advanced_chain(target)


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
    parser = argparse.ArgumentParser(
        prog="aura",
        description="AURA v2 — Professional Bug Bounty & Pentest Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  aura example.com                       # Full automated scan
  aura example.com --crawl               # Authenticated API crawler (attacker session)
  aura example.com --crawl --victim      # Authenticated API crawler (victim session)
  aura example.com --free-ai             # Scan with local Ollama AI (zero cost)
  aura --nexus                           # Launch interactive war room
        """
    )

    parser.add_argument("target", nargs="?", help="Target domain (e.g. example.com)")
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
    parser.add_argument("--victim", action="store_true", help="[v2] Use VICTIM session token for crawl/attack")
    parser.add_argument("--map", default=None, help="[v2] Path to discovery_map.json (auto-detected if omitted)")
    parser.add_argument("--model", default="llama3.1", help="[v2] Ollama model name (default: llama3.1)")

    args = parser.parse_args()

    from aura.core import state
    if args.free_ai:
        state.OPENROUTER_FREE_MODE = True
        console.print("[bold cyan][AI] Zero-Cost Ollama Engine engaged.[/bold cyan]")

    if args.auto_submit:
        state.AUTO_SUBMIT = True
        console.print("[bold red][!] Autonomous Submission Protocol enabled.[/bold red]")

    if args.nexus:
        from aura.core.orchestrator import NeuralOrchestrator
        from aura.core.nexus import launch_nexus
        orchestrator = NeuralOrchestrator()
        launch_nexus(orchestrator)
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
        target = args.target or (self.target_filter if hasattr(args, 'target_filter') else None)
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
    elif args.target:
        asyncio.run(_run_mission(args.target))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
