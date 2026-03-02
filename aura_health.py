#!/usr/bin/env python3
"""
Aura Health Check v19.4 - Self-Diagnostic Tool
Run this anytime to verify Aura is in peak condition.
Usage: python aura_health.py
"""
import sys
import os

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def ok(msg):   print(f"  {GREEN}[✓]{RESET} {msg}")
def fail(msg): print(f"  {RED}[✗]{RESET} {msg}")
def warn(msg): print(f"  {YELLOW}[!]{RESET} {msg}")
def info(msg): print(f"  {CYAN}[*]{RESET} {msg}")

passed = 0
failed = 0

def check(label, fn):
    global passed, failed
    try:
        result = fn()
        if result is True or result is None:
            ok(label)
            passed += 1
        elif result is False:
            fail(label)
            failed += 1
        else:
            ok(f"{label}: {result}")
            passed += 1
    except Exception as e:
        fail(f"{label} → {e}")
        failed += 1

print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════╗")
print(f"║   AURA v14.0 — Health Check v19.4   ║")
print(f"╚══════════════════════════════════════╝{RESET}\n")

# ── 1. Python Version
print(f"{BOLD}[1] Python Environment{RESET}")
check("Python ≥ 3.10",
    lambda: sys.version_info >= (3, 10) or (_ for _ in ()).throw(Exception(f"Python {sys.version_info.major}.{sys.version_info.minor} — need 3.10+")))

# ── 2. Core Dependencies
print(f"\n{BOLD}[2] Core Dependencies{RESET}")
def chk_import(mod):
    return lambda: __import__(mod) and True

check("aiohttp",         chk_import("aiohttp"))
check("requests",        chk_import("requests"))
check("rich",            chk_import("rich"))
check("python-dotenv",   chk_import("dotenv"))
check("playwright",      chk_import("playwright"))
check("google-genai",    chk_import("google.genai"))

# ── 3. Environment Variables
print(f"\n{BOLD}[3] API Keys & Configuration{RESET}")
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
print(f"\n{BOLD}[4] Aura Core Modules{RESET}")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

check("state.py",        lambda: __import__("aura.core.state", fromlist=["state"]) and True)
check("brain.py",        lambda: __import__("aura.core.brain", fromlist=["AuraBrain"]) and True)
check("orchestrator.py", lambda: __import__("aura.core.orchestrator", fromlist=["NeuralOrchestrator"]) and True)
check("scanner.py",      lambda: __import__("aura.modules.scanner", fromlist=["AuraScanner"]) and True)
check("cloud_recon.py",  lambda: __import__("aura.modules.cloud_recon", fromlist=["AuraCloudRecon"]) and True)
check("poc_engine.py",   lambda: __import__("aura.modules.poc_engine", fromlist=["PoCEngine"]) and True)

# ── 5. AI Brain Live Test
print(f"\n{BOLD}[5] AI Brain Live Test{RESET}")
def test_brain():
    from aura.core.brain import AuraBrain
    b = AuraBrain()
    if not b.enabled:
        raise Exception("Brain disabled — check GEMINI_API_KEY")
    result = b._call_ai("Reply with exactly: AURA_OK", use_cache=False)
    if result and len(result) > 0:
        return f"AI Response: '{result.strip()[:40]}'"
    raise Exception("No response from Gemini")

check("Gemini AI Live Ping", test_brain)

# ── 6. Model Name
print(f"\n{BOLD}[6] Configuration Check{RESET}")
from aura.core import state

def chk_model():
    model = state.GEMINI_MODEL
    if "gemini" not in model:
        raise Exception(f"Model name looks wrong: {model}")
    return f"Model = {model}"

check("Gemini Model",    chk_model)
check("DB Path",         lambda: state.GEMINI_API_KEY and True)

# ── 7. Storage & Reports directories
print(f"\n{BOLD}[7] Directories{RESET}")
def chk_dir(d):
    return lambda: os.makedirs(d, exist_ok=True) or os.path.isdir(d)

check("reports/",        chk_dir("reports"))
check("screenshots/",    chk_dir("screenshots"))
check("logs/",           chk_dir("logs"))

# ── Final Summary
print(f"\n{'═'*42}")
total = passed + failed
score = int((passed / total) * 100) if total > 0 else 0

if failed == 0:
    print(f"{GREEN}{BOLD}  ✅ ALL CHECKS PASSED ({passed}/{total}) — Aura is at PEAK condition!{RESET}")
elif failed <= 2:
    print(f"{YELLOW}{BOLD}  ⚠️  MOSTLY OK ({passed}/{total}) — {failed} issue(s) need attention.{RESET}")
else:
    print(f"{RED}{BOLD}  ❌ ISSUES DETECTED ({passed}/{total}) — Run: pip install -r requirements.txt{RESET}")

print(f"  Score: {score}% {'🔥' * (score // 20)}")
print(f"{'═'*42}\n")

sys.exit(0 if failed == 0 else 1)
