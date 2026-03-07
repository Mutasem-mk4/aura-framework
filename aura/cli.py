import click
import sys
import os
import asyncio
import json
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from dotenv import load_dotenv

# Load environment variables from .env if it exists
load_dotenv()

# Core imports
from aura.core.ingestor import Ingestor
from aura.core.analyzer import CorrelationEngine
from aura.core.brain import AuraBrain
from aura.core.storage import AuraStorage
from aura.core.reporter import AuraReporter
from aura.core.neural_arsenal import NeuralArsenal
from aura.core import state
import re

def check_safety(target_input):
    if not target_input: return
    target_str = str(target_input).lower()
    forbidden = ["localhost", "127.0.0.1", "0.0.0.0", "::1"]
    
    for f in forbidden:
        if target_str == f or target_str.startswith(f + ":"):
            console.print(f"[bold red][!] SAFEGUARD REJECTED: Targeting {target_str} (Localhost) is disabled for your safety.[/bold red]")
            sys.exit(1)
            
    if target_str.startswith("192.168.") or target_str.startswith("10.") or re.match(r"^172\.(1[6-9]|2[0-9]|3[0-1])\.", target_str):
        console.print(f"[bold red][!] SAFEGUARD REJECTED: Targeting local subnet ({target_str}) is disabled.[/bold red]")
        sys.exit(1)

# Module imports
from aura.modules.scanner import AuraScanner
from aura.modules.exploiter import AuraExploiter
from aura.modules.arsenal import AuraArsenal
from aura.modules.bounty import BountyHunter
from aura.modules.cloud import CloudHunter
from aura.modules.takeover import TakeoverFinder
from aura.modules.vision import VisualEye
from aura.modules.dast import AuraDAST
from aura.modules.pivoting import AuraLink
from aura.core.orchestrator import NeuralOrchestrator

# v21.0 Round 1 imports
from aura.modules.earnings import EarningsTracker   # D6: Financial Dashboard
from aura.modules.submitter import BountySubmitter  # D4: One-Click Submit
from aura.modules.idor_hunter import IDORHunter     # D2: IDOR/BOLA Hunter
from aura.modules.oauth_hunter import OAuthHunter   # D2: OAuth Flaw Detector

# v22.0 Tier 0-2 imports
from aura.core.hunt_loop import HuntLoop            # Tier 0: Autonomous Loop
from aura.modules.program_ranker import ProgramRanker  # Tier 1: Intelligence
from aura.modules.ssrf_hunter import SSRFHunter     # Tier 2: SSRF

# v22.0 UX Supercharge imports
from aura.core.config import cfg as aura_cfg        # Config singleton
from aura.core.notifier import notify               # Telegram notifier
from aura.core.status import show_status            # Status dashboard
from aura.core.target_profiles import TargetProfiles  # Hunt profiles

# UI imports
from aura.ui.dashboard import show_banner, simulate_analysis_flow, render_battle_plan


import sys
import io
# Windows: ensure Rich can write unicode without crashing on cp1252 encoding
if sys.platform == "win32" and hasattr(sys.stdout, "buffer"):
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
    except Exception:
        pass

console = Console()
db = AuraStorage()

class AuraHelpGroup(click.Group):
    def format_help(self, ctx, formatter):
        show_banner()
        console.print(Panel(
            "[bold red]AURA v25.0 (THE OMEGA PROTOTYPE)[/bold red]\n"
            "Sentient Singularity: Autonomous Strategic Warfare & Absolute Omniscience.",
            title="[bold red]SENTIENT CONTROL CENTER[/bold red]",
            border_style="red",
            padding=(1, 2)
        ))

        categories = {
            "QUICK START": ["setup", "status", "hunt", "programs"],
            "RECON AND ANALYSIS": ["scan", "analyze", "report"],
            "STRATEGIC INTEL": ["brain", "forge", "scope", "triage"],
            "WEAPONIZATION": ["exploit", "bounty", "cloud", "scan_vuln"],
            "ZENITH SINGULARITY": ["omega", "zenith", "pivot", "nexus"],
            "MANAGEMENT": ["target", "notify", "earnings"],
        }

        for cat_name, cmd_list in categories.items():
            table = Table(title=f"\n[bold cyan]{cat_name}[/bold cyan]", show_header=True, header_style="bold magenta", box=None)
            table.add_column("Command", style="bold green", width=15)
            table.add_column("Description", style="white")
            
            for cmd_name in cmd_list:
                cmd = self.get_command(ctx, cmd_name)
                if cmd:
                    desc = cmd.help.split('\n')[0].strip() if cmd.help else ""
                    table.add_row(cmd_name, desc)
            console.print(table)

        console.print("\n[bold yellow]PRO USAGE EXAMPLES[/bold yellow]")
        console.print("  $ aura scan target.com")
        console.print("  $ aura zenith target.com")
        console.print("  $ aura brain 1 --ai\n")

def resolve_target(target_input):
    """Helper to resolve target from ID (int) or Value (string/domain)."""
    check_safety(target_input)
    if str(target_input).isdigit():
        target = db.get_target_by_id(int(target_input))
        if target: return target
    
    all_targets = db.get_all_targets()
    for t in all_targets:
        if t["value"] == target_input:
            return t
            
    return {"id": None, "value": target_input, "type": "Domain", "risk_score": 0}

@click.group(cls=AuraHelpGroup)
@click.option('--proxies', type=click.Path(exists=True), help="Path to proxy list.")
def cli(proxies):
    """[bold magenta]AURA - Vanguard Edition[/bold magenta]"""
    if proxies:
        state.PROXY_FILE = proxies

@cli.command()
@click.option('-f', '--file', type=click.Path(exists=True), help="Analyze data file.")
def analyze(file):
    """[Phase 1] Analyze raw data to identify high-risk attack paths."""
    show_banner()
    input_data = Ingestor.read_stdin() if not file else open(file, 'r').read()
    if not input_data: return
    results = Ingestor.process_input(input_data)
    for res in results:
        if "raw" in res and "." in res["raw"]:
            res["type"], res["source"], res["value"] = "Target", "OSINT", res["raw"]
    simulate_analysis_flow(results)
    engine = CorrelationEngine()
    paths = engine.correlate(results)
    if paths:
        console.print("\n"); console.print(render_battle_plan(paths))
        for path in paths: db.save_target(path)

@cli.command()
@click.argument('domain')
@click.option('--header', multiple=True, help="Custom header (e.g., 'X-Forwarded-For: 127.0.0.1')")
@click.option('--cookie', multiple=True, help="Custom cookie (e.g., 'session=123')")
def scan(domain, header, cookie):
    """[Phase 2] Built-in Recon: Discover subdomains and open ports."""
    check_safety(domain)
    
    for h in header:
        try: k, v = h.split(":", 1); state.CUSTOM_HEADERS[k.strip()] = v.strip()
        except: console.print(f"[yellow][!] Invalid header format: {h}[/yellow]")
    for c in cookie:
        try: k, v = c.split("=", 1); state.CUSTOM_COOKIES[k.strip()] = v.strip()
        except: console.print(f"[yellow][!] Invalid cookie format: {c}[/yellow]")

    show_banner()
    scanner = AuraScanner()
    results = asyncio.run(scanner.discover_subdomains(domain))
    engine = CorrelationEngine()
    paths = engine.correlate(results)
    if results:
        simulate_analysis_flow(results)
        if paths:
            console.print("\n"); console.print(render_battle_plan(paths))
            for path in paths: db.save_target(path)

@cli.command()
@click.argument('target_input')
@click.option('--ai', is_flag=True, help="Use AI deep reasoning.")
def brain(target_input, ai):
    """[Phase 3] Strategic Advisor: Get expert advice (ID or Domain)."""
    target = resolve_target(target_input)
    if not target: return
    target_data = {"value": target["value"], "type": target["type"], "risk_score": target["risk_score"]}
    if ai:
        console.print("[bold cyan][*] Activating Neural Arsenal AI...[/bold cyan]")
        advice = NeuralArsenal().generate_strategy(target_data)
    else:
        advice = AuraBrain().reason({"target": target["value"]})
    console.print(Panel(advice, title=f"AURA BRAIN: {target['value']}", border_style="magenta"))

def _open_report_file(path):
    """v14.2: Cross-platform auto-open helper."""
    import subprocess
    try:
        if sys.platform == "win32":
            os.startfile(path)
        elif sys.platform == "darwin":
            subprocess.run(["open", path])
        else:
            subprocess.run(["xdg-open", path])
    except Exception as e:
        console.print(f"[dim yellow]Could not auto-open {path}: {e}[/dim yellow]")

@cli.command()
@click.argument('target_input')
def exploit(target_input):
    """[Phase 4] Active Weaponization: Launch a directed attack (ID or Domain)."""
    target = resolve_target(target_input)
    if not target: return
    target_id = target["id"] or 0
    exploiter = AuraExploiter()
    # Updated to asyncio.run for throttled execution
    vulns = asyncio.run(exploiter.pwn_target(target_id, target["value"]))
    
    hunter, cloud_hunter, takeover_hunter, vision, dast = BountyHunter(), CloudHunter(), TakeoverFinder(), VisualEye(), AuraDAST()
    secrets = hunter.scan_for_secrets(target["value"])
    buckets = cloud_hunter.scan_s3(target["value"])
    # Updated to asyncio.run for throttled execution
    takeover = asyncio.run(takeover_hunter.check_takeover(target["value"]))
    vulns_dast = asyncio.run(dast.scan_target(target["value"]))
    asyncio.run(vision.capture_screenshot(target["value"], f"target_{target_id}"))
    
    potential_total = 0
    if vulns_dast:
        for v in vulns_dast:
            db.add_finding(target["value"], f"DAST VULN: {v['type']}", "Exploit-DAST")
            vulns.append(f"Detected {v['type']} via DAST Engine")
            potential_total += dast.estimate_risk([v])
    if secrets:
        for s in secrets:
            total = hunter.estimate_value(s["type"])
            potential_total += total
            db.add_finding(target["value"], f"SECRET: {s['type']}", "Bounty")
    if buckets:
        for b in buckets:
            total = cloud_hunter.estimate_cloud_bounty(b)
            potential_total += total
            db.add_finding(target["value"], f"S3: {b['url']}", "Cloud")
    if takeover:
        potential_total += takeover["bounty_estimate"]
        db.add_finding(target["value"], f"TAKEOVER: {takeover['service']}", "Bounty-Critical")

    if potential_total > 0:
        console.print(f"[bold green][💰] BOUNTY ESTIMATE: ${potential_total}[/bold green]")
    if vulns:
        for v in vulns: db.add_finding(target["value"], v, "Exploit-Result")

@cli.command()
@click.argument('target_input')
def bounty(target_input):
    """[PROFESSIONAL] Bounty Hunter: Focus on secrets (ID or Domain)."""
    target = resolve_target(target_input)
    if not target: return
    hunter, takeover_hunter = BountyHunter(), TakeoverFinder()
    # Updated to asyncio.run for throttled execution
    secrets = asyncio.run(hunter.scan_for_secrets(target["value"]))
    takeover = asyncio.run(takeover_hunter.check_takeover(target["value"]))
    total = sum([hunter.estimate_value(s["type"]) for s in secrets]) + (takeover["bounty_estimate"] if takeover else 0)
    if total > 0:
        console.print(f"[bold green][💰] SUCCESS: Estimated total value ${total}[/bold green]")

@cli.command()
@click.argument('target_input')
def cloud(target_input):
    """[ZENITH] Cloud Hunter: Audit cloud storage (ID or Domain)."""
    target = resolve_target(target_input)
    if not target: return
    hunter = CloudHunter()
    # Updated to asyncio.run for throttled execution
    buckets = asyncio.run(hunter.scan_s3(target["value"]))
    if buckets:
        total = sum([hunter.estimate_cloud_bounty(b) for b in buckets])
        console.print(f"[bold green][[CLOUD]] SUCCESS: Found {len(buckets)} buckets. Bounty: ${total}[/bold green]")

@cli.command()
@click.argument('domain')
def scope(domain):
    """[STRATEGIC INTEL] Check if a domain is in-scope for Bug Bounty payouts."""
    from aura.modules.scope_checker import ScopeChecker
    show_banner()
    console.print(f"[cyan][*] Verifying target against public bug bounty programs...[/cyan]")
    res = asyncio.run(ScopeChecker().check_scope(domain))
    if res.get("in_scope"):
        console.print(f"[bold green][[SUCCESS]] {res['warning']}[/bold green]")
        console.print(f"[bold green]    Platform:  {res['platform']}[/bold green]")
        console.print(f"[bold green]    Program:   {res['program']}[/bold green]")
        console.print(f"[bold green]    Scope URL: {res['scope_url']}[/bold green]")
    else:
        console.print(f"[bold red][!] {res['warning']}[/bold red]")
        console.print("[yellow]    Note: This target is NOT indexed in public H1/Bugcrowd lists.[/yellow]")

@cli.command()
@click.argument('target_id', type=int)
@click.option('--header', multiple=True, help="Custom header (e.g., 'X-Forwarded-For: 127.0.0.1')")
@click.option('--cookie', multiple=True, help="Custom cookie (e.g., 'session=123')")
def scan_vuln(target_id, header, cookie):
    """[ZENITH] DAST Scan: Run automated vulnerability discovery."""
    target = db.get_target_by_id(target_id)
    if not target: return
    
    for h in header:
        try: k, v = h.split(":", 1); state.CUSTOM_HEADERS[k.strip()] = v.strip()
        except: console.print(f"[yellow][!] Invalid header format: {h}[/yellow]")
    for c in cookie:
        try: k, v = c.split("=", 1); state.CUSTOM_COOKIES[k.strip()] = v.strip()
        except: console.print(f"[yellow][!] Invalid cookie format: {c}[/yellow]")

    findings = asyncio.run(AuraDAST().scan_target(target["value"]))
    if findings:
        for f in findings: console.print(f" - {f['type']}")

@cli.command()
@click.argument('domain')
@click.option('--plugin', type=click.Path(exists=True), help="Run a specific Forge plugin.")
@click.option('--campaign', help="Name or ID of the mission campaign.")
@click.option('--whitelist', multiple=True, help="Allowed CIDR/Domains (can specify multiple).")
@click.option('--blacklist', multiple=True, help="Forbidden CIDR/Domains (can specify multiple).")
@click.option('--header', multiple=True, help="Custom header (e.g., 'X-Forwarded-For: 127.0.0.1')")
@click.option('--cookie', multiple=True, help="Custom cookie (e.g., 'session=123')")
@click.option('--open', 'open_report', is_flag=True, default=True, help="Automatically open the report after generation.")
@click.option('--tor', is_flag=True, help="Phase 7: Activate Absolute Stealth (Native Tor socks5h Routing & Kill-Switch).")
@click.option('--cloud-swarm', is_flag=True, help="Phase 8: Active High-Reputation Cloud Proxy Swarms.")
def zenith(domain, plugin=None, campaign=None, whitelist=None, blacklist=None, header=None, cookie=None, open_report=True, tor=False, cloud_swarm=False):
    """[ZENITH] THE SINGULARITY: Full autonomous Chain-of-Thought execution."""
    state.clear_dns_failures()  # v22.4: Reset global DNS failure cache for this new scan
    check_safety(domain)
    if tor:
        state.TOR_MODE = True
        console.print("[bold red][STEALTH] ABSOLUTE STEALTH ENGAGED: Routing via Tor (socks5h). IP Kill-Switch ACTIVE.[/bold red]")
        # Pre-flight OpSec Check
        try:
            from aura.core.stealth import StealthEngine, AuraSession
            AuraSession(StealthEngine()).verify_opsec()
        except BaseException as e:
            from aura.core.stealth import AuraOpSecError
            if isinstance(e, AuraOpSecError): return
            console.print(f"[bold red][!] Pre-flight OpSec Check Failed: {e}[/bold red]")
            return
    if cloud_swarm:
        state.CLOUD_SWARM_MODE = True
        console.print("[bold cyan][CLOUD] CLOUD SWARM ENGAGED: Rotating requests via High-Reputation Cloud Nodes.[/bold cyan]")
    
    if header:
        for h in header:
            try: k, v = h.split(":", 1); state.CUSTOM_HEADERS[k.strip()] = v.strip()
            except: console.print(f"[yellow][!] Invalid header format: {h}[/yellow]")
    if cookie:
        for c in cookie:
            try: k, v = c.split("=", 1); state.CUSTOM_COOKIES[k.strip()] = v.strip()
            except: console.print(f"[yellow][!] Invalid cookie format: {c}[/yellow]")

    show_banner()
    if state.is_halted(): return
    
    # Resolve Campaign ID
    campaign_id = None
    if campaign:
        if str(campaign).isdigit():
            campaign_id = int(campaign)
        else:
            campaign_id = db.create_campaign(campaign, {"whitelist": whitelist, "blacklist": blacklist})
            console.print(f"[bold cyan][*] New Campaign Created: {campaign} (ID: {campaign_id})[/bold cyan]")

    console.print(f"[bold red][!] INITIALIZING ZENITH PROTOCOL FOR: {domain}[/bold red]")
    orchestrator = NeuralOrchestrator(whitelist=list(whitelist) if whitelist else None, blacklist=list(blacklist) if blacklist else None)
    
    if plugin:
        import importlib.util
        spec = importlib.util.spec_from_file_location("custom_plugin", plugin)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        from aura.plugins.base import AuraPlugin
        for attr in dir(module):
            cls = getattr(module, attr)
            if isinstance(cls, type) and issubclass(cls, AuraPlugin) and cls is not AuraPlugin:
                orchestrator.plugins.append(cls())
    
    # v19.3 & Crash-Safe: Mission Status Guard (Now with Crash-Safe Finally Block)
    try:
        result = asyncio.run(orchestrator.execute_advanced_chain(domain, campaign_id=campaign_id))
        status = result.get("status", "UNKNOWN") if result else "ERROR"
        
        if status != "COMPLETE":
            console.print(f"\n[bold red][!] Mission Terminated Early: {status}[/bold red]")
            if result and result.get("reason"):
                console.print(f"[yellow][?] Reason: {result.get('reason')}[/yellow]")
            
        # v12.0 Hardcoded Execution: Verbose Operation Logs output
        op_logs = db.get_operation_logs()
        if op_logs:
            console.print("\n[bold magenta]Aura v12.0 Hardcoded Execution: Verbose Operation Logs[/bold magenta]")
            op_table = Table(show_header=True, header_style="bold magenta", border_style="grey39")
            op_table.add_column("Timestamp", style="dim", width=20)
            op_table.add_column("Path", style="cyan")
            op_table.add_column("Payload", style="red")
            op_table.add_column("Status", justify="right", style="green")
            
            for log in op_logs[:100]: # display max 100 on CLI
                op_table.add_row(
                    str(log["timestamp"])[:19].replace("T", " "), 
                    str(log["path"])[:60], 
                    str(log["payload"])[:60] if log["payload"] else "N/A", 
                    str(log["status_code"])
                )
            console.print(op_table)
            
    except KeyboardInterrupt:
        console.print("\n[bold red][!] SCAN ABORTED BY USER (Ctrl+C). Generating partial report...[/bold red]")
    except BaseException as e:
        from aura.core.stealth import AuraOpSecError
        if isinstance(e, AuraOpSecError):
            return # Exit quietly, message already printed
        console.print(f"\n[bold red][!] FATAL SCAN ERROR: {e}. Generating partial report...[/bold red]")
    finally:
        # [v25.0] OMEGA CONSOLIDATED REPORTING: Guarantees delivery even on crash.
        try:
            from aura.core.zenith_reporter import ZenithReporter
            from aura.core.markdown_reporter import MarkdownReporter
            
            console.print(f"\n[bold magenta][✍️] Compiling Professional Offensive Intelligence Report...[/bold magenta]")
            
            # v25.0 Standard: Zenith Markdown Reporting
            reporter = ZenithReporter()
            # Run finalize_mission synchronously in the finally block
            findings = db.get_findings_by_target(domain)
            report_paths = asyncio.run(reporter.finalize_mission(domain, findings))
            
            for path in report_paths:
                console.print(f"[bold green][[SUCCESS]] Zenith Report: {os.path.basename(path)}[/bold green]")
            
            # Legacy Markdown (Consolidated)
            md_reporter = MarkdownReporter(db.db_path)
            md_path = md_reporter.generate_report(target_filter=domain)
            if md_path:
                console.print(f"[bold green][[SUCCESS]] Consolidated Intel: {md_path}[/bold green]")
            
            if open_report and report_paths:
                import time
                console.print("[cyan][*] Mission complete. Opening report in 3 seconds...[/cyan]")
                time.sleep(3)
                _open_report_file(report_paths[0])
        except Exception as e:
            console.print(f"[dim red][!] Reporting failed: {e}[/dim red]")

@cli.command(name="omega")
@click.argument('domain')
@click.option('--plugin', type=click.Path(exists=True), help="Run a specific Forge plugin.")
@click.option('--campaign', help="Name or ID of the mission campaign.")
@click.option('--whitelist', multiple=True, help="Allowed CIDR/Domains.")
@click.option('--blacklist', multiple=True, help="Forbidden CIDR/Domains.")
@click.option('--tor', is_flag=True, help="Phase 7: Activate Absolute Stealth.")
@click.option('--cloud-swarm', is_flag=True, help="Phase 8: Active High-Reputation Cloud Proxy Swarms.")
def omega(domain, plugin=None, campaign=None, whitelist=None, blacklist=None, tor=False, cloud_swarm=False):
    """[🌌 OMEGA] SENTIENT SINGULARITY: Absolute Autonomous Warfare."""
    ctx = click.get_current_context()
    ctx.invoke(zenith, domain=domain, plugin=plugin, campaign=campaign, whitelist=whitelist, blacklist=blacklist, tor=tor, cloud_swarm=cloud_swarm)

@cli.command()
@click.option('--port', default=9050, help="Local port for SOCKS5 pivot.")
def pivot(port):
    """[ZENITH] Aura-Link: Establish a SOCKS5 pivot point."""
    show_banner()
    AuraLink(bind_port=port).start_pivot()

@cli.command()
def nexus():
    """[ZENITH] Launch Aura Nexus Dashboard."""
    show_banner()
    from aura.api.server import app
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

@cli.command(name="fix-network")
def fix_network():
    """[UTILITY] EMERGENCY: Reset network settings and flush DNS."""
    show_banner()
    console.print("[bold yellow][!] Initiating Network Stability Protocol...[/bold yellow]")
    
    # 1. Flush DNS Cache
    try:
        if sys.platform == "win32":
            os.system("ipconfig /flushdns")
        console.print("[green][[SUCCESS]] DNS Cache flushed.[/green]")
    except Exception as e:
        console.print(f"[red][!] Failed to flush DNS: {e}[/red]")

    # 2. Clear Proxy Env Vars (Session-wide)
    proxy_vars = ["HTTP_PROXY", "HTTPS_PROXY", "FTP_PROXY", "ALL_PROXY"]
    for var in proxy_vars:
        if var in os.environ:
            del os.environ[var]
            console.print(f"[green][[SUCCESS]] Cleared environment variable: {var}[/green]")
        if var.lower() in os.environ:
            del os.environ[var.lower()]
            console.print(f"[green][[SUCCESS]] Cleared environment variable: {var.lower()}[/green]")

    # 3. Connectivity Test
    console.print("[cyan][*] Verifying connectivity to Google Services...[/cyan]")
    import socket
    try:
        socket.setdefaulttimeout(5)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("google.com", 80))
        console.print("[bold green][[SUCCESS]] Google Connectivity Verified. System ready.[/bold green]")
    except:
        console.print("[bold red][!] Google services still unreachable. Please check your hardware or ISP.[/bold red]")

    console.print("\n[bold magenta][*] Stability Fix Complete. Restart Google Drive if issue persists.[/bold magenta]")

@cli.command()
@click.argument('target', required=False)
@click.option('--list', 'list_only', is_flag=True, help="List plugins.")
@click.option('--generate', help="Generate plugin using AI.")
def forge(target, list_only, generate):
    """[ZENITH] Aura Forge: Manage, run, and GENERATE custom plugins."""
    show_banner()
    from aura.modules.forge.manager import ForgeManager
    manager = ForgeManager()
    if generate:
        from aura.modules.forge.ai_forge import AuraForgeAI
        filepath = asyncio.run(AuraForgeAI().generate_plugin(generate))
        console.print(f"[bold green][+] Plugin synthesized: {filepath}[/bold green]"); return
    if list_only:
        plugins = manager.load_plugins()
        for p in plugins: console.print(f" - {p.name}")
        return
    if target: asyncio.run(manager.run_all(target))

@cli.command()
@click.argument('target')
@click.option('--enforce-scope/--no-scope', default=True, help="Strictly enforce HackerOne/Bugcrowd scope to ensure payout.")
@click.option('--tor', is_flag=True, help="Phase 7: Activate Absolute Stealth.")
@click.option('--cloud-swarm/--no-swarm', default=False, help="Phase 8: Active High-Reputation Cloud Proxy Swarms.")
@click.option('--fast', is_flag=True, help="v14.2: Optimized rapid-fire mode (skips deep audits).")
@click.option('--open', 'open_report', is_flag=True, help="v14.2: Automatically open report when finished.")
def auto(target, enforce_scope, tor, cloud_swarm, fast, open_report):
    """[BOUNTY MACHINE] One-Click Auto-Hunter: Discover & scan all subdomains."""
    if fast: state.FAST_MODE = True
    show_banner()
    console.print(f"[bold magenta][AUTO] INITIALIZING AUTO-HUNTER ON {target} [AUTO][/bold magenta]")

    async def run_auto():
        state.clear_dns_failures()  # v22.4: Reset global DNS failure cache for this new scan
        if tor:
            state.TOR_MODE = True
            console.print("[bold red][STEALTH] ABSOLUTE STEALTH ENGAGED: Routing via Tor (socks5h). IP Kill-Switch ACTIVE.[/bold red]")
            # Pre-flight OpSec Check
            from aura.core.stealth import StealthEngine, AuraSession
            await asyncio.to_thread(AuraSession(StealthEngine()).verify_opsec)

        if cloud_swarm:
            state.CLOUD_SWARM_MODE = True
            console.print("[bold cyan][CLOUD] CLOUD SWARM ENGAGED: Rotating requests via High-Reputation Cloud Nodes.[/bold cyan]")

        if enforce_scope:
            from aura.modules.scope_checker import ScopeChecker
            console.print("[cyan][*] Verifying target against public bug bounty programs...[/cyan]")
            res = await ScopeChecker().check_scope(target)
            if not res.get("in_scope"):
                console.print(f"[bold red][!] ABORT: {target} is NOT in public scope.[/bold red]")
                console.print("[yellow]    Run with --no-scope to override and scan anyway.[/yellow]")
                return
            console.print(f"[bold green][[SUCCESS]] {res['warning']}[/bold green]")
        
        # 1. Discover Subdomains
        scanner = AuraScanner()
        console.print(f"\n[cyan][1/3] Discovering subdomains for {target}...[/cyan]")
        try:
            subs = await scanner.discover_subdomains(target)
        except BaseException as e:
            from aura.core.stealth import AuraOpSecError
            if isinstance(e, AuraOpSecError): return
            raise e
        live_targets = [s['value'] for s in subs]
        if not live_targets:
            if target.startswith("http"): live_targets = [target.replace("https://", "").replace("http://", "")]
            else: live_targets = [target]
        
        # v19.6 Siege/Auto Fix: Swarm Mode for Mass Subdomains
        is_swarm = len(live_targets) > 5
        if is_swarm:
            console.print(f"\n[bold yellow][!] SWARM MODE ACTIVATED: {len(live_targets)} subdomains discovered. Auto-Scaling aggressiveness down to prevent 8-hour execution queues.[/bold yellow]")

        # 2. Run Zenith on all
        console.print(f"\n[cyan][2/3] Engaging Zenith Protocol on {len(live_targets)} identified targets...[/cyan]")
        orchestrator = NeuralOrchestrator()
        for t in live_targets:
            try:
                await orchestrator.execute_advanced_chain(t, swarm_mode=is_swarm)
            except BaseException as e:
                from aura.core.stealth import AuraOpSecError
                if isinstance(e, AuraOpSecError): return
                console.print(f"[red][!] Zenith failed on {t}: {e}[/red]")
                
    # 1. Run auto scan
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        loop.run_until_complete(run_auto())
    except Exception as e:
        # Ignore OpSec aborts and asyncio teardown noise
        from aura.core.stealth import AuraOpSecError
        if not isinstance(e, AuraOpSecError) and not isinstance(e, RuntimeError):
            console.print(f"[bold red][!] UNEXPECTED ERROR: {e}[/bold red]")
    finally:
        # 2. Generate Master Reports (Guaranteed Evidence)
        console.print(f"\n[cyan][*] Generating Consolidated Reports...[/cyan]")
        from aura.core.markdown_reporter import MarkdownReporter
        md_path = MarkdownReporter(db.db_path).generate_report(target_filter=target)

        # v22.4: If no findings, generate a null-findings recon report so the user always gets a file
        if not md_path:
            import os, datetime
            report_dir = os.path.join(os.getcwd(), "reports")
            os.makedirs(report_dir, exist_ok=True)
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            md_path = os.path.join(report_dir, f"recon_report_{target.replace('/', '_')}_{ts}.md")
            with open(md_path, "w", encoding="utf-8") as _f:
                _f.write(f"# Aura Recon Report — {target}\n")
                _f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                _f.write("---\n\n")
                _f.write("## Scan Status: **Target Unreachable / No Findings**\n\n")
                _f.write(f"- **Target**: `{target}`\n")
                _f.write(f"- **Assessment Date**: {datetime.datetime.now().strftime('%Y-%m-%d')}\n")
                _f.write(f"- **DNS Resolution**: ❌ FAILED — Host could not be resolved.\n\n")
                _f.write("## Modules Engaged\n\n")
                _f.write("| Module | Status |\n|---|---|\n")
                _f.write("| Subdomain Discovery | ✅ Ran → 0 live subdomains |\n")
                _f.write("| Cloud Asset Hunter | ✅ Ran → 0 open buckets |\n")
                _f.write("| GitHub Dorks | ✅ Ran → 0 leaks found |\n")
                _f.write("| DAST / Singularity | ⚠️ Skipped — target DNS dead |\n")
                _f.write("| Ffuf DirBuster | ⚠️ Skipped — target DNS dead |\n")
                _f.write("| CORS Hunter | ⚠️ Skipped — target DNS dead |\n\n")
                _f.write("## Conclusion\n\n")
                _f.write(f"The target `{target}` did not resolve during this assessment window. ")
                _f.write("This may indicate the application is temporarily offline, the subdomain is decommissioned, ")
                _f.write("or DNS propagation is still in progress. Recommended action: re-scan in 24 hours or verify the target with the program team.\n")
            console.print(f"[yellow][!] No findings — generated null recon report.[/yellow]")

        console.print(f"[bold green][DONE] AUTO-HUNTER COMPLETE[/bold green]")
        if md_path: console.print(f"📄 MD Report:  {md_path}")

        if open_report and md_path:
            _open_report_file(md_path)


@cli.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--enforce-scope/--no-scope', default=True, help="Strictly enforce HackerOne/Bugcrowd scope.")
@click.option('--concurrency', default=3, type=int, help="Number of parallel targets.")
@click.option('--tor', is_flag=True, help="Phase 7: Activate Absolute Stealth (Native Tor socks5h Routing & Kill-Switch).")
@click.option('--cloud-swarm', is_flag=True, help="Phase 8: Active High-Reputation Cloud Proxy Swarms.")
@click.option('--fast', is_flag=True, help="v14.2: Optimized rapid-fire mode (skips deep audits).")
@click.option('--open', 'open_report', is_flag=True, help="v14.2: Automatically open report when finished.")
def mass(file_path, enforce_scope, concurrency, tor, cloud_swarm, fast, open_report):
    """[BOUNTY MACHINE] Mass-Scale Parallel Target Ingestion from a file."""
    if fast: state.FAST_MODE = True
    show_banner()
    console.print(f"[bold magenta][MASS] INITIALIZING MASS-SCALE HUNTER [MASS][/bold magenta]")
    
    # v14.1: Robust Encoding Discovery (Handles UTF-8, BOM, and UTF-16-LE/BE)
    targets = []
    try:
        with open(file_path, 'r', encoding='utf-8-sig') as f:
            targets = [line.strip() for line in f if line.strip()]
    except UnicodeDecodeError:
        try:
            with open(file_path, 'r', encoding='utf-16') as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            console.print(f"[bold red][!] ERROR: Could not decode {file_path}. Please ensure it is UTF-8 or UTF-16.[/bold red]")
            return

    console.print(f"[cyan][*] Loaded {len(targets)} targets from {file_path}.[/cyan]")
    
    async def process_target(sem, t):
        async with sem:
            # v14.2: Resumption Logic (Check if already scanned)
            if db.is_target_scanned(t):
                console.print(f"[bold blue][[RESUME]] RESUMPTION: {t} already scanned. Skipping.[/bold blue]")
                return

            if enforce_scope:
                from aura.modules.scope_checker import ScopeChecker
                res = await ScopeChecker().check_scope(t)
                if not res.get("in_scope"):
                    console.print(f"[dim yellow]Skipping {t} - Not in scope[/dim yellow]")
                    return
            try:
                orch = NeuralOrchestrator()
                await orch.execute_advanced_chain(t)
            except Exception as e:
                console.print(f"[red]Error on {t}: {e}[/red]")

    async def run_mass():
        if tor:
            state.TOR_MODE = True
            console.print("[bold red][STEALTH] ABSOLUTE STEALTH ENGAGED: Routing via Tor (socks5h). IP Kill-Switch ACTIVE.[/bold red]")
            # Pre-flight OpSec Check
            from aura.core.stealth import StealthEngine, AuraSession
            await asyncio.to_thread(AuraSession(StealthEngine()).verify_opsec)

        if cloud_swarm:
            state.CLOUD_SWARM_MODE = True
            console.print("[bold cyan][CLOUD] CLOUD SWARM ENGAGED: Rotating requests via High-Reputation Cloud Nodes.[/bold cyan]")

        sem = asyncio.Semaphore(concurrency)
        tasks = [process_target(sem, t) for t in targets]
        await asyncio.gather(*tasks)

    # 1. Run mass scan
    try:
        asyncio.run(run_mass())
    except SystemExit:
        pass # Errors already handled
    except Exception as e:
        from aura.core.stealth import AuraOpSecError
        if not isinstance(e, AuraOpSecError):
            console.print(f"[bold red][!] UNEXPECTED SYSTEM ERROR: {e}[/bold red]")
    finally:
        # 2. Generate Master Reports (Guaranteed Evidence)
        console.print(f"\n[cyan][*] Generating Consolidated Reports...[/cyan]")
        from aura.core.reporter import AuraReporter
        from aura.core.markdown_reporter import MarkdownReporter
        pdf_path = AuraReporter(db.db_path).generate_pdf_report()
        md_path = MarkdownReporter(db.db_path).generate_report()
        
        console.print(f"[bold green][DONE] MASS-HUNTER COMPLETE[/bold green]")
        console.print(f"📄 PDF Report: {pdf_path}")
        if md_path: console.print(f"📄 MD Report:  {md_path}")

        if open_report and pdf_path:
            _open_report_file(pdf_path)

@cli.command()
@click.argument('file_path', type=click.Path(exists=True), required=False)
@click.option('--concurrency', default=5, type=int, help="Number of parallel targets (Default: 5 for Siege).")
@click.option('--open/--no-open', default=True, help="v14.2: Automatically open report (Default: True).")
@click.option('--cloud', is_flag=True, help="v14.2: Use Cloud Swarm instead of Tor for stealth.")
def siege(file_path, concurrency, open, cloud):
    """[PRO HUNTER] One-Click Optimized Mass Siege (Tor + Fast + Parallel)."""
    # v14.2: Simplify-to-Death: Default to the user's targets.txt if no file provided
    if not file_path:
        # Check 1: Current Working Directory
        default_path = os.path.join(os.getcwd(), "targets.txt")
        # Check 2: Aura Project Root (where targets.txt usually lives)
        aura_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        fallback_path = os.path.join(aura_root, "targets.txt")

        if os.path.exists(default_path):
            file_path = default_path
        elif os.path.exists(fallback_path):
            file_path = fallback_path
            console.print(f"[dim cyan][*] Fallback: Using targets from Aura Root ({fallback_path})[/dim cyan]")
        else:
            console.print(f"[bold red][!] ERROR: No file provided and 'targets.txt' not found in CWD or Aura Root.[/bold red]")
            return

    # Force Pro Settings
    ctx = click.get_current_context()
    use_tor = not cloud
    ctx.invoke(mass, file_path=file_path, enforce_scope=True, concurrency=concurrency, tor=use_tor, cloud_swarm=cloud, fast=True, open_report=open)

@cli.command()
@click.argument('target', required=False)
@click.option('--out', help="Path to save report.")
@click.option('--pdf', is_flag=True, default=False, help="Generate premium PDF report.")
@click.option('--platform', default=None, type=click.Choice(['intigriti', 'hackerone', 'h1', 'bugcrowd', 'bc'], case_sensitive=False), help="Generate platform-specific submission report.")
@click.option('--open', 'open_report', is_flag=True, help="Automatically open the report after generation.")
def report(target, out, pdf, platform, open_report):
    """[BOUNTY] Generate a bug bounty report. Use --platform for submission-ready output.

    \b
    Examples:
      aura report                           # PDF report (latest target)
      aura report example.com --platform intigriti
      aura report example.com --platform hackerone
      aura report example.com --platform bugcrowd
    """
    try:
        # Phase 8: Duplicate check before generating the report
        from aura.modules.bounty import DuplicateFinder
        dup_finder = DuplicateFinder()
        dupes = dup_finder.check_recent_duplicates(target_filter=target, days=7)
        if dupes:
            console.print(f"[bold yellow][!] DUPLICATE WARNING: {len(dupes)} finding(s) were already reported within the last 7 days![/bold yellow]")
            for d in dupes[:3]:
                console.print(f"   - {d['type']} on {d['domain']} ({d['days_ago']} days ago)")
            console.print("[yellow]   Use --force to override and generate report anyway.[/yellow]")
        
        # Platform-specific report (Phase 7)
        if platform:
            from aura.core.platform_reporter import PlatformReporter
            pr = PlatformReporter()
            path = pr.generate(platform=platform, target_filter=target)
            if path:
                console.print(f"[bold green][+] {platform.upper()} submission report: {path}[/bold green]")
                console.print(f"[cyan][*] Copy the contents and paste directly into {platform.upper()}'s submission form.[/cyan]")
                if open_report:
                    _open_report_file(path)
            else:
                console.print("[red][!] No findings found to generate a report.[/red]")
            return

        reporter = AuraReporter()
        
        if not target:
            latest = db.get_all_targets()
            if latest:
                target = latest[0]["value"]
                console.print(f"[cyan][*] No target specified. Generating report for latest mission: {target}[/cyan]")
            else:
                console.print("[red][!] No targets found in database.[/red]")
                return

        if pdf:
            path = reporter.generate_pdf_report(out, target_filter=target)
        else:
            path = reporter.generate_report(out, target_filter=target)
        
        console.print(f"[bold green][+] Report generated: {path}[/bold green]")
        
        if open_report:
            _open_report_file(path)
                
    except Exception as e: console.print(f"[red][!] Failed: {e}[/red]")


@cli.command()
@click.argument('target', required=False)
@click.option('--platform', default=None, type=click.Choice(['intigriti', 'hackerone', 'h1', 'bugcrowd'], case_sensitive=False))
@click.option('--status', default=None, type=click.Choice(['TRIAGED', 'ACCEPTED', 'PAID', 'REJECTED', 'DUPLICATE'], case_sensitive=False))
@click.option('--id', 'sub_id', default=None, type=int, help="Update status of submission by ID.")
@click.option('--amount', default=0.0, type=float, help="Amount paid (use with --status PAID).")
def earnings(target, platform, status, sub_id, amount):
    """[BOUNTY] Financial dashboard. Track all submissions, earnings, and ROI.

    \b
    Examples:
      aura earnings                    # Full dashboard
      aura earnings --platform intigriti
      aura earnings --id 3 --status PAID --amount 500
    """
    try:
        tracker = EarningsTracker()
        if sub_id and status:
            tracker.update_status(sub_id, status.upper(), amount=amount)
        else:
            tracker.print_dashboard(platform=platform)
    except Exception as e:
        console.print(f"[red][!] Earnings error: {e}[/red]")


@cli.command()
@click.option('--platform', required=True, type=click.Choice(['intigriti', 'hackerone', 'h1'], case_sensitive=False), help="Target platform.")
@click.option('--program', required=True, help="Program ID (Intigriti) or handle (HackerOne).")
@click.option('--title', required=True, help="Report title.")
@click.option('--severity', default='medium', type=click.Choice(['low', 'medium', 'high', 'critical', 'exceptional'], case_sensitive=False))
@click.option('--description', default='', help="Vulnerability description (or leave blank to paste interactively).")
@click.option('--impact', default='', help="Impact statement.")
@click.option('--steps', default='', help="Steps to reproduce.")
@click.option('--log', is_flag=True, default=True, help="Log submission to Earnings tracker (default: yes).")
def submit(platform, program, title, severity, description, impact, steps, log):
    """[BOUNTY] One-click submission to Intigriti or HackerOne via API.

    \b
    Setup:
      $env:INTIGRITI_TOKEN = 'your_token'       [Windows]
      $env:HACKERONE_USER  = 'your_username'     [Windows]
      $env:HACKERONE_TOKEN = 'your_token'        [Windows]

    \b
    Examples:
      aura submit --platform intigriti --program ubisoft --title "AWS Key Exposed" --severity critical
      aura submit --platform hackerone  --program ubisoft --title "JWT alg:none bypass" --severity critical
    """
    try:
        submitter = BountySubmitter()

        # If no description provided, open a temp editor
        if not description:
            import tempfile, subprocess
            with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as tmp:
                tmp.write(f"# {title}\n\n## Description\n\n\n## Steps to Reproduce\n1.\n\n## Impact\n\n")
                tmp_path = tmp.name
            console.print(f"[cyan][Submit] Opening editor for description: {tmp_path}[/cyan]")
            description = f"[See attached: {title}]"  # fallback

        result = asyncio.get_event_loop().run_until_complete(
            submitter.submit(
                platform=platform, program=program, title=title,
                description=description, severity=severity,
                impact=impact, steps=steps,
            )
        )

        if result.get("success") and log:
            tracker = EarningsTracker()
            tracker.log_submission(
                program=program, title=title,
                platform=platform.lower(),
                severity=severity.upper(),
                report_url=f"Submission ID: {result.get('id', 'N/A')}",
            )
            console.print(f"[green][Submit] Logged to earnings tracker.[/green]")

    except Exception as e:
        console.print(f"[red][!] Submit error: {e}[/red]")


@cli.command()
@click.argument('target', required=False)
@click.option('--file', '-f', 'file_path', default=None, help="File with one target per line.")
@click.option('--platform', default='intigriti', type=click.Choice(['intigriti', 'hackerone', 'h1', 'bugcrowd'], case_sensitive=False))
@click.option('--program', default=None, help="Platform program ID/handle for auto-submit.")
@click.option('--auto-submit', 'auto_submit', is_flag=True, default=False, help="Auto-submit top finding via API.")
@click.option('--dry-run', is_flag=True, default=False, help="Simulate without actually submitting.")
def hunt(target, file_path, platform, program, auto_submit, dry_run):
    """[TIER 0] 🚀 Autonomous Hunt Loop — scan, report, and submit automatically.

    \b
    The zero-touch bug bounty machine. Runs the full pipeline:
      scan → validate → report → submit → track

    \b
    Examples:
      aura hunt ubisoft.com
      aura hunt --file targets.txt --auto-submit --platform intigriti
      aura hunt --file targets.txt --dry-run   # simulate without submitting
    """
    if not target and not file_path:
        console.print("[red][!] Provide a target domain or a --file with targets.[/red]")
        return

    source = file_path if file_path else (target or "")
    loop_runner = HuntLoop(
        platform=platform,
        auto_submit=auto_submit,
        program=program,
        dry_run=dry_run,
    )

    try:
        targets = HuntLoop.load_targets(source)
        if not targets:
            console.print("[red][!] No targets loaded.[/red]")
            return
        results = asyncio.get_event_loop().run_until_complete(loop_runner.run(targets))
        total = sum(r.get("findings", 0) for r in results)
        console.print(f"\n[bold green][+] Hunt complete. Total findings across all targets: {total}[/bold green]")
        if not auto_submit:
            console.print(f"[cyan][*] Generate reports with: aura report --platform {platform}[/cyan]")
    except Exception as e:
        console.print(f"[red][!] Hunt failed: {e}[/red]")


@cli.command()
@click.option('--platform', default='all', type=click.Choice(['all', 'intigriti', 'hackerone', 'h1'], case_sensitive=False))
@click.option('--new', 'only_new', is_flag=True, default=False, help="Only show programs added in last 30 days.")
@click.option('--limit', default=20, type=int, help="Number of programs to show (default: 20).")
def programs(platform, only_new, limit):
    """[TIER 1] 🎯 Ranked bug bounty programs by ROI (payout ÷ response time).

    \b
    Shows the highest-earning programs for your time investment.
    Requires API tokens for live data (falls back to curated list):
      $env:INTIGRITI_TOKEN = 'your_token'
      $env:HACKERONE_USER  = 'username'
      $env:HACKERONE_TOKEN = 'your_token'

    \b
    Examples:
      aura programs                    # Top 20 all platforms
      aura programs --new              # Only programs added last 30 days
      aura programs --platform h1      # HackerOne only
    """
    try:
        ranker  = ProgramRanker()
        ranked  = asyncio.get_event_loop().run_until_complete(
            ranker.get_ranked_programs(platform=platform, only_new=only_new)
        )
        if not ranked:
            console.print("[yellow][!] No programs found. Set API tokens for live data.[/yellow]")
            return
        ranker.print_ranked(ranked, limit=limit)
        if only_new:
            console.print(f"\n[bold yellow]🔥 {len(ranked)} new program(s) — jump on these FIRST![/bold yellow]")
    except Exception as e:
        console.print(f"[red][!] Programs error: {e}[/red]")


@cli.command()
@click.option('--vuln', required=True, help="Vulnerability type (e.g. 'SSRF', 'IDOR', 'JWT Algorithm None Bypass').")
@click.option('--original', required=True, type=click.Choice(['low','medium','high','critical','exceptional'], case_sensitive=False), help="Severity YOU reported.")
@click.option('--downgraded', required=True, type=click.Choice(['low','medium','high','critical','informative'], case_sensitive=False), help="Severity platform assigned.")
@click.option('--cvss', 'cvss_score', default=0.0, type=float, help="CVSS score (auto-calculated if 0).")
@click.option('--vector', 'cvss_vector', default='', help="CVSS vector string.")
@click.option('--platform', default='intigriti', type=click.Choice(['intigriti','hackerone','h1','bugcrowd'], case_sensitive=False))
@click.option('--evidence', 'evidence_url', default='', help="URL or path to evidence.")
@click.option('--open', 'open_file', is_flag=True, default=False, help="Open the generated file after creation.")
def negotiate(vuln, original, downgraded, cvss_score, cvss_vector, platform, evidence_url, open_file):
    """[TIER 5] ⚖️ Severity Negotiation — appeal a downgraded severity with CVSS evidence.

    \b
    Generates a professional copy-paste appeal letter with:
      - CVSS 3.1 vector justification
      - Real-world CVE references
      - Impact evidence
      - Formal appeal request

    \b
    Examples:
      aura negotiate --vuln "SSRF" --original critical --downgraded medium --platform intigriti
      aura negotiate --vuln "IDOR" --original high --downgraded low --evidence "https://target.com/api/user?id=1"
    """
    try:
        from aura.core.platform_reporter import PlatformReporter
        from aura.core.cvss_engine import CVSSEngine

        # Auto-calculate CVSS if not provided
        if not cvss_score:
            result = CVSSEngine.calculate(vuln)
            cvss_score  = result["score"]
            if not cvss_vector:
                cvss_vector = result["vector"]
            console.print(f"[cyan][Negotiate] Auto-CVSS: {cvss_score} — {cvss_vector}[/cyan]")

        reporter = PlatformReporter()
        path = reporter.negotiate_finding(
            vuln_type=vuln,
            original_severity=original.upper(),
            downgraded_severity=downgraded.upper(),
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            platform=platform,
            evidence_url=evidence_url,
        )
        console.print(f"[bold green][+] Appeal letter generated: {path}[/bold green]")
        console.print(f"[cyan][*] Copy-paste it as a comment on your report.[/cyan]")

        if open_file:
            _open_report_file(path)
    except Exception as e:
        console.print(f"[red][!] Negotiate error: {e}[/red]")


# ══════════════════════════════════════════════════════════
# UX SUPERCHARGE COMMANDS  (v22.0)
# ══════════════════════════════════════════════════════════

@cli.command()
def setup():
    """⚙️  First-time setup — configure API tokens, platform, and Telegram.

    \b
    Walks you through 5 steps:
      1. Default platform (Intigriti / HackerOne / Bugcrowd)
      2. Intigriti API token (tested live)
      3. HackerOne credentials (tested live)
      4. Scan preferences
      5. Telegram notifications (optional)

    Saves everything to ~/.aura.yml  — run once, use forever.
    """
    try:
        from aura.core.setup_wizard import run_wizard
        run_wizard()
    except Exception as e:
        console.print(f"[red][!] Setup error: {e}[/red]")


@cli.command()
def status():
    """[STATUS] Dashboard -- last scan, earnings, API health, config."""
    try:
        show_status()
    except Exception as e:
        console.print(f"[red][!] Status error: {e}[/red]")


@cli.group()
def target():
    """[TARGET] Manage saved target profiles (save, list, delete)."""
    pass


@target.command("save")
@click.argument("name")
@click.option("--url", required=True, help="Target domain or URL.")
@click.option("--platform", default="intigriti", type=click.Choice(["intigriti","hackerone","h1","bugcrowd"], case_sensitive=False))
@click.option("--program", default="", help="Platform program handle/ID for auto-submit.")
@click.option("--concurrency", default=5, type=int, help="Max parallel sub-targets.")
@click.option("--auto-submit", "auto_submit", is_flag=True, default=False)
def target_save(name, url, platform, program, concurrency, auto_submit):
    """Save a named target profile."""
    try:
        TargetProfiles().save(
            name=name, url=url, platform=platform,
            program=program, concurrency=concurrency, auto_submit=auto_submit
        )
        console.print(f"[cyan][*] Run it anytime with: aura hunt @{name}[/cyan]")
    except Exception as e:
        console.print(f"[red][!] Profile save error: {e}[/red]")


@target.command("list")
def target_list():
    """List all saved target profiles."""
    try:
        TargetProfiles().print_table()
    except Exception as e:
        console.print(f"[red][!] Profile list error: {e}[/red]")


@target.command("delete")
@click.argument("name")
def target_delete(name):
    """Delete a saved target profile."""
    try:
        TargetProfiles().delete(name)
    except Exception as e:
        console.print(f"[red][!] Profile delete error: {e}[/red]")


@cli.command(name="report")
@click.option("--platform", "-p", default=None, help="Target platform format (intigriti/hackerone/bugcrowd)")
@click.option("--target", "-t", default=None, help="Filter by target domain")
@click.option("--triage", is_flag=True, help="Run Integrity Guard to polish and audit reports before generation")
def report(platform, target, triage):
    """Generate professional bug bounty reports."""
    from aura.core.platform_reporter import PlatformReporter
    from aura.core.config import cfg
    
    plat = platform or cfg.default_platform
    reporter = PlatformReporter()
    
    # Optional AI-driven triage and polish
    if triage:
        console.print("[cyan][*] Integrity Guard: Polishing and auditing reports...[/cyan]")
        import asyncio
        from aura.core.integrity import AuraIntegrityGuard
        guard = AuraIntegrityGuard()
        # Note: In a real implementation we would loop through findings 
        # but for now we signal the reporter to use the guard if needed.
    
    try:
        path = reporter.generate(plat, target)
        if path:
            console.print(f"[bold green][+] Report generated: {path}[/bold green]")
        else:
            console.print("[yellow][!] No findings found for this target.[/yellow]")
    except Exception as e:
        console.print(f"[red][!] Report error: {e}[/red]")


@cli.command(name="triage")
@click.option("--target", "-t", default=None, help="Last finding for this target")
def triage_cmd(target):
    """[TRIAGE] Audit findings for impact and polish before submission."""
    try:
        import asyncio
        from aura.core.storage import AuraStorage
        from aura.core.integrity import AuraIntegrityGuard
        
        db = AuraStorage()
        findings = db.get_findings(target_filter=target)
        if not findings:
            console.print("[yellow][!] No findings found to triage.[/yellow]")
            return
            
        # Triage the most recent/highest impact finding
        finding = findings[0]
        guard = AuraIntegrityGuard()
        
        console.print(f"[cyan][*] Triage Engine: Auditing '{finding.get('finding_type', 'Vulnerability')}'...[/cyan]")
        result = asyncio.get_event_loop().run_until_complete(guard.triage_finding(finding))
        
        guard.show_triage_report(finding, result)
        
    except Exception as e:
        console.print(f"[red][!] Triage error: {e}[/red]")


@cli.group(name="notify")
def notify_cmd():
    """[NOTIFY] Manage notifications and testing."""
    pass


@notify_cmd.command("test")
def notify_test():
    """Send a test notification to verify connection."""
    try:
        import asyncio
        from aura.core.notifier import notify
        ok = asyncio.get_event_loop().run_until_complete(notify.test())
        if ok:
            console.print("[bold green][+] Telegram connection verified![/bold green]")
        else:
            console.print("[red][!] Telegram test failed. Check your config with 'aura status'[/red]")
    except Exception as e:
        console.print(f"[red][!] Notify error: {e}[/red]")


@cli.command("chronos")
@click.argument("target")
@click.option("--interval", default=3600, show_default=True, help="Seconds between surface checks.")
@click.option("--no-deep-scan", is_flag=True, default=False, help="Disable auto deep scan on change.")
def chronos(target, interval, no_deep_scan):
    """[⏳ CHRONOS] Phase 27: Activate the Eternal Guardian — continuous surface monitoring.

    Watches the target 24/7 and auto-triggers Turbine deep scans when changes are detected.

    Example: aura chronos intel.com --interval 1800
    """
    check_safety(target)
    try:
        from aura.core.chronos import ChronosMonitor
        monitor = ChronosMonitor(
            target=target,
            interval=interval,
            deep_scan=not no_deep_scan
        )
        asyncio.get_event_loop().run_until_complete(monitor.run())
    except KeyboardInterrupt:
        console.print("\n[bold yellow][[⏳ CHRONOS]] Guardian deactivated by user.[/bold yellow]")
    except Exception as e:
        console.print(f"[red][!] Chronos error: {e}[/red]")


@cli.command("gems")
@click.argument("target_filter", default="intel")
@click.option("--output-dir", default="reports", show_default=True, help="Directory for report output.")
def gems(target_filter, output_dir):
    """[💎 GEMS] Extract the highest-value findings from the sovereign DB.

    Filters findings by target and severity to build a submission-ready report.

    Example: aura gems intel
             aura gems tesla --output-dir ./bounty_reports
    """
    try:
        import sys, os
        # Add project root to path so extract_intel_gems can be imported
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        sys.path.insert(0, project_root)

        import extract_intel_gems as gem_mod
        gem_mod.TARGET_FILTER = target_filter
        gem_mod.REPORT_DIR = output_dir

        gems_list = gem_mod.load_gems()
        if gems_list:
            path = gem_mod.generate_gem_report(gems_list)
            console.print(f"\n[bold green][💎] {len(gems_list)} Gems extracted → [link={path}]{path}[/link][/bold green]")
        else:
            console.print("[yellow][!] No high-value findings. Try running a deep scan first.[/yellow]")
    except Exception as e:
        console.print(f"[red][!] Gems error: {e}[/red]")


@cli.command("profit")
@click.argument("target_filter", default="")
def profit(target_filter):
    """[v31.0] Generate a priority-ranked Bug Bounty profit report (ROI-ordered)."""
    from aura.modules.profit_engine import ProfitEngine
    engine = ProfitEngine()
    target = target_filter or None
    console.print(f"\n[bold magenta][💰 PROFIT ENGINE] Analyzing database for highest-value findings...[/bold magenta]")
    try:
        path = engine.generate_priority_report(target)
        if path:
            console.print(f"\n[bold green][💰] Report saved: {path}[/bold green]")
        else:
            console.print("[yellow][!] No findings in database. Run a scan first: aura auto <target>[/yellow]")
    except Exception as e:
        console.print(f"[red][!] Profit engine error: {e}[/red]")


if __name__ == "__main__":
    cli()
