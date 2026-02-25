import click
import sys
import os
import asyncio
import json
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from aura.core.ingestor import Ingestor
from aura.core.analyzer import CorrelationEngine
from aura.core.brain import AuraBrain
from aura.core.storage import AuraStorage
from aura.core.reporter import AuraReporter
from aura.core.neural_arsenal import NeuralArsenal
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
from aura.ui.dashboard import show_banner, simulate_analysis_flow, render_battle_plan

console = Console()
db = AuraStorage()

@click.group()
def cli():
    """
    [bold magenta]AURA - Autonomous Offensive Intelligence Framework[/bold magenta]
    
    Aura is a high-performance, automated tool designed for reconnaissance, 
    risk analysis, and active exploitation.
    """
    pass

@cli.command()
@click.option('-f', '--file', type=click.Path(exists=True), help="Analyze data from a specific file.")
def analyze(file):
    """
    [Phase 1] Analyze raw data to identify high-risk attack paths.
    
    Accepts piped input (stdin) or a file. Uses the Correlation Engine to rank 
    targets based on their strategic value.
    """
    show_banner()
    
    input_data = ""
    if file:
        with open(file, 'r') as f:
            input_data = f.read()
    else:
        input_data = Ingestor.read_stdin()

    if not input_data:
        console.print("[red][!] No input detected. Pipe data into Aura or use -f.[/red]")
        return

    results = Ingestor.process_input(input_data)
    
    # Enrich results for visual impact
    for res in results:
        if "raw" in res and "." in res["raw"]:
            res["type"] = "Target"
            res["source"] = "OSINT"
            res["value"] = res["raw"]

    simulate_analysis_flow(results)

    # 2. Run Correlation Engine
    engine = CorrelationEngine()
    paths = engine.correlate(results)

    if paths:
        console.print("\n")
        console.print(render_battle_plan(paths))
        # Save results to permanent storage
        for path in paths:
            db.save_target(path)
    else:
        console.print("\n[yellow][!] No immediate high-risk attack paths identified.[/yellow]")

@cli.command()
@click.argument('domain')
def scan(domain):
    """
    [Phase 2] Built-in Recon: Discover subdomains and open ports.
    
    Replaces external tools like Subfinder. Automatically saves discovered 
    targets to the local intelligence database (SQLite).
    """
    show_banner()
    scanner = AuraScanner()
    results = scanner.discover_subdomains(domain)
    
    # Process findings
    engine = CorrelationEngine()
    paths = engine.correlate(results)
    
    if results:
        simulate_analysis_flow(results)
        if paths:
            console.print("\n")
            console.print(render_battle_plan(paths))
            for path in paths:
                db.save_target(path)
    else:
        console.print("[yellow][!] No targets found during scan.[/yellow]")

@cli.command()
@click.argument('target_id', type=int)
@click.option('--ai', is_flag=True, help="Use Neural Arsenal (AI) for deep analysis.")
def brain(target_id, ai):
    """
    [Phase 3] Strategic Advisor: Get expert advice on a specific target.
    
    Analyzes the target's metadata and suggests specific exploitation 
    strategies. Use --ai for Neural Arsenal deep reasoning.
    """
    target = db.get_target_by_id(target_id)
    if not target:
        console.print(f"[red][!] Target ID {target_id} not found in database.[/red]")
        return

    target_data = {"value": target["value"], "type": target["type"], "risk_score": target["risk_score"]}
    
    if ai:
        console.print("[bold cyan][*] Activating Neural Arsenal AI...[/bold cyan]")
        neural = NeuralArsenal()
        advice = neural.generate_strategy(target_data)
    else:
        brain_engine = AuraBrain()
        advice = brain_engine.reason({"target": target["value"]})

    console.print(Panel(
        advice,
        title=f"[bold cyan]AURA BRAIN - Strategic Analysis: {target['value']}[/bold cyan]",
        border_style="magenta",
        padding=(1, 2)
    ))

@cli.command()
@click.argument('target_id', type=int)
def exploit(target_id):
    """
    [Phase 4] Active Weaponization: Launch a directed attack on a target.
    
    Performs directory fuzzing, sensitive file discovery, and brute-force 
    attacks. Automatically logs success findings to the database.
    """
    target = db.get_target_by_id(target_id)
    if not target:
        console.print(f"[red][!] Target ID {target_id} not found.[/red]")
        return

    exploiter = AuraExploiter()
    vulns = exploiter.pwn_target(target_id, target["value"])
    
    # Professional Chain: Bounty Hunting
    hunter = BountyHunter()
    cloud_hunter = CloudHunter()
    takeover_hunter = TakeoverFinder()
    vision = VisualEye()
    dast = AuraDAST()
    
    secrets = hunter.scan_for_secrets(target["value"])
    buckets = cloud_hunter.scan_s3(target["value"])
    takeover = takeover_hunter.check_takeover(target["value"])
    
    # Run DAST Scan
    vulns_dast = asyncio.run(dast.scan_target(target["value"]))
    
    # Async capture for screenshot
    asyncio.run(vision.capture_screenshot(target["value"], f"target_{target_id}"))
    
    potential_total = 0
    if vulns_dast:
        for v in vulns_dast:
            db.add_finding(target["value"], f"DAST VULN: {v['type']}", "Exploit-DAST")
            vulns.append(f"Detected {v['type']} via DAST Engine")
            potential_total += dast.estimate_risk([v])

    if secrets:
        for secret in secrets:
            value = hunter.estimate_value(secret["type"])
            potential_total += value
            db.add_finding(target["value"], f"SECRET FOUND: {secret['type']} (Value: ${value})", "Bounty")
            vulns.append(f"Found {secret['type']} in {secret['location']}")

    if buckets:
        for bucket in buckets:
            value = cloud_hunter.estimate_cloud_bounty(bucket)
            potential_total += value
            db.add_finding(target["value"], f"S3 BUCKET: {bucket['url']} ({bucket['status']})", "Cloud")
            vulns.append(f"Discovered {bucket['status']} S3 Bucket: {bucket['url']}")

    if takeover:
        potential_total += takeover["bounty_estimate"]
        db.add_finding(target["value"], f"TAKEOVER VULNERABILITY: {takeover['service']}", "Bounty-Critical")
        vulns.append(f"Potential {takeover['service']} Takeover detected!")

    if potential_total > 0:
        console.print(f"[bold green][💰] BOUNTY ESTIMATE: Aura estimates this target could yield ${potential_total} in rewards.[/bold green]")
    
    # NEW: Chain with Arsenal Brute-force if it's an admin panel
    if "admin" in target["value"].lower():
        creds = AuraArsenal.http_brute_force(f"http://{target['value']}/login")
        if creds:
            db.add_finding(target["value"], f"BruteForce-Success: {creds}", "Credential")
            vulns.append(f"HTTP Brute-force success: {creds}")
    
    # Save exploit findings to DB
    if vulns:
        for vuln in vulns:
            db.add_finding(target["value"], vuln, "Exploit-Result")

@cli.command()
@click.argument('domain')
def auto_pwn(domain):
    """
    [ULTIMATE WEAPON] Full Autonomous Exploitation Loop.
    
    Chains Scan -> Analyze -> Brain -> Exploit without user intervention. 
    The fastest way to breach a perimeter and gather intelligence.
    """
    show_banner()
    console.print(f"[bold red][!] INITIALIZING AUTO-PWN PROTOCOL FOR: {domain}[/bold red]")
    
    # 1. Scan
    scanner = AuraScanner()
    results = scanner.discover_subdomains(domain)
    
    # 2. Analyze & Correlate
    engine = CorrelationEngine()
    paths = engine.correlate(results)
    
    if not paths:
        console.print("[yellow][!] No high-risk targets found. Aborting Auto-Pwn.[/yellow]")
        return

    # 3. Take the top target
    top_target = paths[0]
    db.save_target(top_target)
    
    console.print(f"\n[bold green][*] TOP TARGET IDENTIFIED: {top_target['target']} (Risk: {top_target['risk_score']})[/bold green]")
    
    # 4. Consult Brain (Simulated insight for the log)
    brain_engine = AuraBrain()
    insight = brain_engine.reason({"target": top_target["target"]})
    console.print(Panel(insight, title="AUTO-PWN STRATEGIC INSIGHT", border_style="magenta"))
    
    # 5. Exploit & Bounty & Vision
    exploiter = AuraExploiter()
    hunter = BountyHunter()
    vision = VisualEye()
    
    vulns = exploiter.pwn_target(1, top_target["target"])
    secrets = hunter.scan_for_secrets(top_target["target"])
    import asyncio
    asyncio.run(vision.capture_screenshot(top_target["target"], "target_1"))
    
    if vulns or secrets:
        for vuln in vulns:
            db.add_finding(top_target["target"], vuln, "Auto-Pwn-Finding")
        for secret in secrets:
            db.add_finding(top_target["target"], f"{secret['type']} @ {secret['location']}", "Auto-Bounty")
            
        console.print(f"\n[bold red][!!!] AUTO-PWN COMPLETE: Multi-stage breach successful.[/bold red]")
    else:
        console.print("\n[yellow][!] No immediate vulnerabilities or secrets identified.[/yellow]")

@cli.command()
@click.argument('target_id', type=int)
def bounty(target_id):
    """
    [PROFESSIONAL] Bounty Hunter: Focus only on high-value secrets.
    
    Scans for leaked API keys, tokens, and credentials that yield 
    the highest payouts in bounty programs.
    """
    target = db.get_target_by_id(target_id)
    if not target:
        console.print(f"[red][!] Target ID {target_id} not found.[/red]")
        return

    hunter = BountyHunter()
    takeover_hunter = TakeoverFinder()
    
    secrets = hunter.scan_for_secrets(target["value"])
    takeover = takeover_hunter.check_takeover(target["value"])
    
    found_count = len(secrets) + (1 if takeover else 0)
    if found_count > 0:
        total = sum([hunter.estimate_value(s["type"]) for s in secrets])
        if takeover:
            total += takeover["bounty_estimate"]
            
        console.print(f"\n[bold green][💰] SUCCESS: Found {found_count} high-value issues with estimated total value of ${total}[/bold green]")
    else:
        console.print("[yellow][!] No high-payout vulnerabilities identified on this target.[/yellow]")

@cli.command()
@click.argument('target_id', type=int)
def cloud(target_id):
    """
    [ZENITH] Cloud Hunter: Audit cloud storage infrastructure.
    
    Scans for misconfigured S3 buckets and cloud leaks related to the target 
    domain. Public buckets can lead to critical data exposure.
    """
    target = db.get_target_by_id(target_id)
    if not target:
        console.print(f"[red][!] Target ID {target_id} not found.[/red]")
        return

    hunter = CloudHunter()
    buckets = hunter.scan_s3(target["value"])
    
    if buckets:
        public_count = len([b for b in buckets if b["status"] == "PUBLIC"])
        total_value = sum([hunter.estimate_cloud_bounty(b) for b in buckets])
        console.print(f"\n[bold green][☁️] SUCCESS: Found {len(buckets)} S3 buckets ({public_count} PUBLIC). Total potential bounty: ${total_value}[/bold green]")
    else:
        console.print("[yellow][!] No Cloud storage related to this target identified.[/yellow]")

@cli.command()
@click.argument('target_id', type=int)
def scan_vuln(target_id):
    """
    [ZENITH] DAST Scan: Run automated vulnerability discovery.
    
    Uses the headless DAST engine to find SQLi, XSS, and SSRF on the target.
    """
    target = db.get_target_by_id(target_id)
    if not target:
        console.print(f"[red][!] Target ID {target_id} not found.[/red]")
        return

    dast = AuraDAST()
    findings = asyncio.run(dast.scan_target(target["value"]))
    
    if findings:
        console.print(f"\n[bold red][🔥] CRITICAL: Found {len(findings)} vulnerabilities![/bold red]")
        for f in findings:
            console.print(f" - {f['type']} (Confidence: {f.get('confidence', 'N/A')})")
    else:
        console.print("[green][+] DAST Scan completed. No common vulnerabilities detected.[/green]")

@cli.command()
@click.argument('domain')
def zenith(domain):
    """
    [ZENITH] THE SINGULARITY: AI-driven autonomous Chain-of-Thought execution.
    
    The most advanced mode. Aura takes full control, thinks strategically,
    and executes a multi-step attack chain using the entire Zenith arsenal.
    """
    show_banner()
    orchestrator = NeuralOrchestrator()
    results = asyncio.run(orchestrator.execute_advanced_chain(domain))
    
    console.print("\n[bold magenta]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold magenta]")
    console.print(f"[bold white]FINAL ZENITH STATUS: DOMINATION COMPLETE[/bold white]")
    console.print("[bold magenta]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold magenta]")

@cli.command()
@click.option('--port', default=9050, help="Local port for SOCKS5 pivot.")
def pivot(port):
    """
    [ZENITH] Aura-Link: Establish a SOCKS5 pivot point.
    
    Creates a local SOCKS5 proxy that tunnels traffic through Aura,
    allowing you to reach internal networks or bypass egress filters.
    """
    show_banner()
    linker = AuraLink(bind_port=port)
    linker.start_pivot()

@cli.command()
def nexus():
    """
    [ZENITH] Launch Aura Nexus: Start the web command center.
    """
    show_banner()
    console.print("[bold cyan][*] Starting Aura Nexus Command Center on http://localhost:8000[/bold cyan]")
    from aura.api.server import app
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

@cli.command()
@click.option('--out', default="aura_report.html", help="Path to save the report.")
def report(out):
    """
    [Phase 1] Generate Evidence: Create a professional HTML security report.
    
    Compiles all findings, risk scores, and exploit successes from the 
    database into a visually stunning format for documentation.
    """
    reporter = AuraReporter()
    try:
        path = reporter.generate_report(out)
        console.print(f"[bold green][+] Report generated successfully: {path}[/bold green]")
    except Exception as e:
        console.print(f"[red][!] Failed to generate report: {e}[/red]")

if __name__ == "__main__":
    cli()
