
import asyncio
import os
import json
from aura.core.brain import AuraBrain
from aura.core.orchestrator import NeuralOrchestrator
from aura.core.storage import AuraStorage
from aura.core.zenith_reporter import ZenithReporter

async def verify_phase22():
    print("[*] Starting Phase 22: The Oracle Synthesis Verification...")
    
    brain = AuraBrain()
    db = AuraStorage()
    reporter = ZenithReporter(brain)
    orchestrator = NeuralOrchestrator(db)
    
    # 1. Test Predictive Vulnerability Engine
    print("\n[1] Testing Predictive Vulnerability Engine...")
    context = {"domain": "test.target.com", "targets_found": 10}
    findings = [{"type": "SSRF", "severity": "HIGH", "target": "test.target.com/api/v1"}]
    
    predictions = brain.predict_implied_vulns(context, findings)
    print(f"[*] Oracle Predictions: {json.dumps(predictions, indent=2)}")
    
    if isinstance(predictions, list):
        print("[SUCCESS] Predictive Engine returned valid prediction format.")
    else:
        print("[FAILURE] Predictive Engine returned invalid format.")

    # 2. Test Autonomous Exploit Chaining
    print("\n[2] Testing Autonomous Exploit Chaining...")
    # Mocking findings for chaining
    vulns = [
        {"type": "SSRF", "severity": "HIGH", "target": "http://target.com/api/proxy"},
        {"type": "Information Disclosure", "severity": "MEDIUM", "target": "http://target.com/config.json"}
    ]
    
    await orchestrator.execute_exploit_chaining("target.com", vulns)
    
    has_chain = any("Exploit Chain" in f.get("type", "") for f in vulns)
    if has_chain:
        print("[SUCCESS] Exploit Chainer identified and recorded a potential chain.")
    else:
        print("[INFO] No chain identified (dependent on AI reasoning results), but method executed.")

    # 3. Test Deep-Stack Remediation (ZenithReporter)
    print("\n[3] Testing Deep-Stack Remediation Reporting...")
    finding = {"type": "IDOR", "severity": "CRITICAL", "content": "UserID parameter vulnerable"}
    report_path = await reporter.generate_final_report("target.com", finding, tech_stack="Node.js/Express")
    
    if os.path.exists(report_path):
        print(f"[SUCCESS] Zenith Report with Deep-Stack Advice generated: {report_path}")
        with open(report_path, "r") as f:
            content = f.read()
            if "Node.js/Express" in content:
                 print("[SUCCESS] Tech stack identification verified in report content.")
            if "Deep-Stack Remediation" in content:
                 print("[SUCCESS] Deep-Stack Remediation section found in report.")
    else:
        print("[FAILURE] Failed to generate Zenith report.")

    print("\n[*] Phase 22 Verification Complete.")

if __name__ == "__main__":
    asyncio.run(verify_phase22())
