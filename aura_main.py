"""
Aura v2 — Main Entry Point (Root)
=================================
This script acts as the primary runner for the Aura framework.
It dispatches commands to the specialized modules in the `aura/` package.
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
    from dotenv import load_dotenv
    load_dotenv()
    from aura.modules.auth_crawler import run_crawler
    cookie_key = "AUTH_TOKEN_VICTIM" if victim else "AUTH_TOKEN_ATTACKER"
    cookies = os.getenv(cookie_key, "")
    if not cookies:
        console.print(f"[bold red]❌ {cookie_key} not found in .env![/bold red]")
        return
    account_type = "VICTIM" if victim else "ATTACKER"
    console.print(f"[bold cyan]🕷️  Starting Authenticated Crawl: {target} [{account_type} session][/bold cyan]")
    await run_crawler(target, cookies)

def main():
    parser = argparse.ArgumentParser(
        prog="aura",
        description="AURA v2 — Professional Bug Bounty & Pentest Framework"
    )
    # v1 legacy support
    parser.add_argument("target", nargs="?", help="Target domain")
    parser.add_argument("--nexus", action="store_true", help="Launch interactive War Room")
    parser.add_argument("--auto-submit", action="store_true", help="Enable autonomous submission")
    parser.add_argument("--free-ai", action="store_true", help="Use local AI (Ollama)")
    
    # v2 new flags
    parser.add_argument("--crawl", action="store_true", help="Authenticated API crawler")
    parser.add_argument("--hunt", action="store_true", help="BOLA/IDOR hunt")
    parser.add_argument("--report", metavar="FILE", help="AI-analyze findings")
    parser.add_argument("--burp", metavar="FILE", help="Import Burp XML")
    parser.add_argument("--submit", metavar="FILE", help="Submit report")
    parser.add_argument("--dry-run", action="store_true", help="Preview submission")
    parser.add_argument("--csrf", action="store_true", help="Scan for CSRF")
    parser.add_argument("--xss", action="store_true", help="Scan for XSS")
    parser.add_argument("--auth", action="store_true", help="Auth logic scan")
    parser.add_argument("--sqli", action="store_true", help="SQL Injection scan")
    parser.add_argument("--web", action="store_true", help="[v2] 🌐 Web Security: CORS + Open Redirect + Rate Limiting + Headers")
    parser.add_argument("--ssrf", action="store_true", help="[v2] SSRF Engine — OOB, Localhost, Cloud Metadata")
    parser.add_argument("--lfi", action="store_true", help="[v2] Path Traversal / LFI Engine")
    parser.add_argument("--recon", action="store_true", help="[v2] Recon & JS Scraper")
    parser.add_argument("--api", action="store_true", help="API & GraphQL Fuzzer")
    parser.add_argument("--web3", action="store_true", help="[v3] Web3 Smart Contract Auditing Engine")
    
    parser.add_argument("--auto", action="store_true", help="🚀 AUTOPILOT: run ALL engines automatically")
    parser.add_argument("--skip", default="", metavar="PHASES", help="Skip phases by number (e.g. --skip 1,6)")
    parser.add_argument("--victim", action="store_true", help="Use victim session")
    parser.add_argument("--map", help="Path to discovery map")
    parser.add_argument("--model", default="llama3.1", help="Ollama model")
    parser.add_argument("--proxy-file", default=None, help="[v3] Path to a list of proxies for Phantom Routing (WAF evasion)")
    parser.add_argument("--targets", action="store_true", help="[v3] 🎯 Target Hunter: Fetch and display fresh, profitable bug bounty programs")

    args = parser.parse_args()

    from aura.core import state
    if args.free_ai: state.OPENROUTER_FREE_MODE = True
    if args.auto_submit: state.AUTO_SUBMIT = True

    if args.auto and args.target:
        console.print(f"[bold red][!] AUTO FLAG DETECTED - ENGAGING ZENITH PROTOCOL[/bold red]")
        asyncio.run(_run_mission(args.target))
    elif args.nexus:
        from aura.core.orchestrator import NeuralOrchestrator
        from aura.core.nexus import launch_nexus
        launch_nexus(NeuralOrchestrator())
    elif args.targets:
        from aura.modules.target_hunter import run_hunter
        run_hunter()
    elif args.crawl and args.target:
        asyncio.run(_run_crawl(args.target, victim=args.victim))
    elif args.hunt and args.target:
        from aura.modules.idor_engine_v2 import run_hunt
        run_hunt(args.target, discovery_map_path=args.map)
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
        run_recon(args.target)
    elif args.api and args.target:
        from aura.modules.api_engine import run_api_scan
        asyncio.run(run_api_scan(args.target, discovery_map_path=args.map))
    elif args.web3 and args.target:
        from aura.modules.web3_engine import run_web3_audit
        asyncio.run(run_web3_audit(args.target))
    elif args.target:
        asyncio.run(_run_mission(args.target))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
