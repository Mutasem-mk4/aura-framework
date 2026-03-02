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

# UI imports
from aura.ui.dashboard import show_banner, simulate_analysis_flow, render_battle_plan

console = Console()
db = AuraStorage()

class AuraHelpGroup(click.Group):
    def format_help(self, ctx, formatter):
        show_banner()
        console.print(Panel(
            "[bold cyan]AURA v10.0 (Sovereign)[/bold cyan]\n"
            "Autonomous Domain Dominance & Offensive Intelligence Framework.",
            title="[bold cyan]SOVEREIGN CONTROL CENTER[/bold cyan]",
            border_style="cyan",
            padding=(1, 2)
        ))

        categories = {
            "RECON AND ANALYSIS": ["scan", "analyze", "report"],
            "STRATEGIC INTEL": ["brain", "forge"],
            "WEAPONIZATION": ["exploit", "bounty", "cloud", "scan_vuln"],
            "ZENITH SINGULARITY": ["auto_pwn", "zenith", "pivot", "nexus"]
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
def scan(domain):
    """[Phase 2] Built-in Recon: Discover subdomains and open ports."""
    check_safety(domain)
    show_banner()
    scanner = AuraScanner()
    results = scanner.discover_subdomains(domain)
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
        console.print(f"[bold green][☁️] SUCCESS: Found {len(buckets)} buckets. Bounty: ${total}[/bold green]")

@cli.command()
@click.argument('target_id', type=int)
def scan_vuln(target_id):
    """[ZENITH] DAST Scan: Run automated vulnerability discovery."""
    target = db.get_target_by_id(target_id)
    if not target: return
    findings = asyncio.run(AuraDAST().scan_target(target["value"]))
    if findings:
        for f in findings: console.print(f" - {f['type']}")

@cli.command()
@click.argument('domain')
@click.option('--plugin', type=click.Path(exists=True), help="Run a specific Forge plugin.")
@click.option('--campaign', help="Name or ID of the mission campaign.")
@click.option('--whitelist', multiple=True, help="Allowed CIDR/Domains (can specify multiple).")
@click.option('--blacklist', multiple=True, help="Forbidden CIDR/Domains (can specify multiple).")
@click.option('--open', 'open_report', is_flag=True, default=True, help="Automatically open the report after generation.")
def zenith(domain, plugin=None, campaign=None, whitelist=None, blacklist=None, open_report=True):
    """[ZENITH] THE SINGULARITY: Full autonomous Chain-of-Thought execution."""
    check_safety(domain)
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
    
    asyncio.run(orchestrator.execute_advanced_chain(domain, campaign_id=campaign_id))
    
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
    
    # [v8.0.1] CONSOLIDATED REPORTING: Single PDF Entry Point
    try:
        from aura.core.reporter import AuraReporter
        reporter = AuraReporter()
        report_path = reporter.generate_pdf_report(target_filter=domain)
        console.print(f"[bold green][+] Professional Mission Report generated: {report_path}[/bold green]")
        
        if open_report:
            import subprocess
            if sys.platform == "win32":
                os.startfile(report_path)
            elif sys.platform == "darwin":
                subprocess.run(["open", report_path])
            else:
                try: subprocess.run(["xdg-open", report_path])
                except: pass
    except Exception as e:
        console.print(f"[dim red][!] Auto-report failed or could not open: {e}[/dim red]")

@cli.command(name="auto_pwn")
@click.argument('domain')
@click.option('--plugin', type=click.Path(exists=True), help="Run a specific Forge plugin.")
@click.option('--whitelist', multiple=True)
@click.option('--blacklist', multiple=True)
@click.option('--open', 'open_report', is_flag=True, default=True)
def auto_pwn(domain, plugin=None, campaign=None, whitelist=None, blacklist=None, open_report=True):
    """[ULTIMATE WEAPON] Alias for 'zenith' - Full Autonomous Loop."""
    ctx = click.get_current_context()
    ctx.invoke(zenith, domain=domain, plugin=plugin, campaign=campaign, whitelist=whitelist, blacklist=blacklist, open_report=open_report)

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
        console.print("[green][✔] DNS Cache flushed.[/green]")
    except Exception as e:
        console.print(f"[red][!] Failed to flush DNS: {e}[/red]")

    # 2. Clear Proxy Env Vars (Session-wide)
    proxy_vars = ["HTTP_PROXY", "HTTPS_PROXY", "FTP_PROXY", "ALL_PROXY"]
    for var in proxy_vars:
        if var in os.environ:
            del os.environ[var]
            console.print(f"[green][✔] Cleared environment variable: {var}[/green]")
        if var.lower() in os.environ:
            del os.environ[var.lower()]
            console.print(f"[green][✔] Cleared environment variable: {var.lower()}[/green]")

    # 3. Connectivity Test
    console.print("[cyan][*] Verifying connectivity to Google Services...[/cyan]")
    import socket
    try:
        socket.setdefaulttimeout(5)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("google.com", 80))
        console.print("[bold green][✔] Google Connectivity Verified. System ready.[/bold green]")
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
@click.argument('target', required=False)
@click.option('--out', help="Path to save report.")
@click.option('--pdf', is_flag=True, default=True, help="Generate premium PDF report (default).")
@click.option('--open', 'open_report', is_flag=True, help="Automatically open the report after generation.")
def report(target, out, pdf, open_report):
    """[Phase 1] Generate Evidence: Create professional report for a target (or latest)."""
    try:
        reporter = AuraReporter()
        
        # [Simplified Reporting] Auto-resolve latest target if none provided
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
            import subprocess
            if sys.platform == "win32":
                os.startfile(path)
            elif sys.platform == "darwin":
                subprocess.run(["open", path])
            else:
                subprocess.run(["xdg-open", path])
                
    except Exception as e: console.print(f"[red][!] Failed: {e}[/red]")

if __name__ == "__main__":
    cli()
