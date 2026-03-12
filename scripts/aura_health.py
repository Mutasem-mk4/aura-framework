#!/usr/bin/env python3
"""
Aura Health Check v25.2 - Self-Diagnostic Tool
Run this anytime to verify Aura is in peak condition.
Usage: python scripts/aura_health.py
"""
import sys
import os

try:
    if sys.stdout.encoding.lower() != 'utf-8':
        sys.stdout.reconfigure(encoding='utf-8')
except AttributeError:
    pass

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import print as rprint
    console = Console()
except ImportError:
    print("Please install 'rich' to use the health check: pip install rich")
    sys.exit(1)

passed = 0
failed = 0

def check(label, fn):
    global passed, failed
    try:
        result = fn()
        if result is True or result is None:
            console.print(f"  [bold green]✓[/bold green] {label}")
            passed += 1
        elif result is False:
            console.print(f"  [bold red]✗[/bold red] {label}")
            failed += 1
        else:
            console.print(f"  [bold green]✓[/bold green] {label}: [cyan]{result}[/cyan]")
            passed += 1
    except Exception as e:
        console.print(f"  [bold red]✗[/bold red] {label} → [dim]{e}[/dim]")
        failed += 1

console.print(Panel(
    "[bold cyan]AURA v25.2 — System Diagnostics & Health Check[/bold cyan]", 
    border_style="cyan", 
    expand=False
))
console.print()

# ── 1. Python Version
console.print("[bold white][1] Python Environment[/bold white]")
check("Python ≥ 3.10",
    lambda: sys.version_info >= (3, 10) or (_ for _ in ()).throw(Exception(f"Python {sys.version_info.major}.{sys.version_info.minor} — need 3.10+")))

# ── 2. Core Dependencies
console.print("\n[bold white][2] Core Dependencies[/bold white]")
def chk_import(mod):
    return lambda: __import__(mod) and True

check("aiohttp",         chk_import("aiohttp"))
check("requests",        chk_import("requests"))
check("rich",            chk_import("rich"))
check("python-dotenv",   chk_import("dotenv"))
check("playwright",      chk_import("playwright"))
check("google.generativeai",    chk_import("google.generativeai"))

# ── 3. Environment Variables
console.print("\n[bold white][3] API Keys & Configuration[/bold white]")
from dotenv import load_dotenv
load_dotenv()

def chk_env(key, label=None):
    val = os.environ.get(key, "")
    if val and len(val) > 5:
        return lambda: f"{label or key} = {val[:8]}..."
    else:
        return lambda: (_ for _ in ()).throw(Exception(f"{label or key} is MISSING or EMPTY"))

check("GEMINI_API_KEY",      chk_env("GEMINI_API_KEY", "Gemini API Key"))
check("SHODAN_API_KEY",      chk_env("SHODAN_API_KEY", "Shodan"))
check("VIRUSTOTAL_API_KEY",  chk_env("VIRUSTOTAL_API_KEY", "VirusTotal"))
check("OTX_API_KEY",         chk_env("OTX_API_KEY", "AlienVault OTX"))
check("ABUSEIPDB_API_KEY",   chk_env("ABUSEIPDB_API_KEY", "AbuseIPDB"))

# ── 4. Aura Core Modules
console.print("\n[bold white][4] Aura Core Modules[/bold white]")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

check("state.py",        lambda: __import__("aura.core.state", fromlist=["state"]) and True)
check("brain.py",        lambda: __import__("aura.core.brain", fromlist=["AuraBrain"]) and True)
check("orchestrator.py", lambda: __import__("aura.core.orchestrator", fromlist=["NeuralOrchestrator"]) and True)

# ── 5. AI Brain Live Test
console.print("\n[bold white][5] AI Brain Live Test[/bold white]")
def test_brain():
    from aura.core.brain import AuraBrain
    b = AuraBrain()
    if not b.enabled:
        raise Exception("Brain disabled — check GEMINI_API_KEY")
    result = b._call_ai(
        "Reply with exactly: AURA_OK", 
        system_instruction="You are a helpful assistant confirming your system is online.", 
        use_cache=False
    )
    if result and len(result) > 0:
        return f"AI Response: '{result.strip()[:40]}'"
    raise Exception("No response from Gemini")

check("Gemini AI Live Ping", test_brain)

# ── 6. Storage & Reports directories
console.print("\n[bold white][6] Directories[/bold white]")
def chk_dir(d):
    return lambda: os.makedirs(d, exist_ok=True) or os.path.isdir(d)

check("reports/",        chk_dir("reports"))
check("screenshots/",    chk_dir("screenshots"))
check("logs/",           chk_dir("logs"))

# ── Final Summary
console.print()
total = passed + failed
score = int((passed / total) * 100) if total > 0 else 0

if failed == 0:
    console.print(Panel(
        f"[bold green]✅ ALL CHECKS PASSED ({passed}/{total}) — Aura is at PEAK condition![/bold green]\n"
        f"Score: {score}% {'🔥' * (score // 20)}",
        border_style="green", expand=False
    ))
elif failed <= 2:
    console.print(Panel(
        f"[bold yellow]⚠️  MOSTLY OK ({passed}/{total}) — {failed} issue(s) need attention.[/bold yellow]\n"
        f"Score: {score}% {'🔥' * (score // 20)}",
        border_style="yellow", expand=False
    ))
else:
    console.print(Panel(
        f"[bold red]❌ ISSUES DETECTED ({passed}/{total}) — Run: pip install -r requirements.txt[/bold red]\n"
        f"Score: {score}% {'🔥' * (score // 20)}",
        border_style="red", expand=False
    ))

sys.exit(0 if failed == 0 else 1)
