import asyncio
import json
from aura.modules.frontend_deconstructor import FrontendDeconstructor
from aura.modules.ai_mutator import AIMutatorEngine

class MockContext:
    def __init__(self, target):
        self.target = target
        self.target_url = target
        self.intel = {"urls": {f"{target}/rest/products/search?q=apple", f"{target}/api/Feedbacks?comment=test"}}

    def get_intel(self):
        return self.intel

class MockBrain:
    def analyze(self, prompt):
        # Force a successful SQLi payload for Juice Shop search bypass
        # Juice shop returns 500 on ' and 200 on valid SQLi
        return "apple')) OR 1=1--"
        
async def main():
    target = "https://demo.owasp-juice.shop"
    ctx = MockContext(target)
    
    # --- Frontend Deconstructor Test ---
    fd = FrontendDeconstructor()
    fd.context = ctx
    fd.target = target
    fd.emit_progress = lambda **kw: None
    fd.emit_vulnerability = lambda v: fd.results.append(v) if hasattr(fd, 'results') else None
    
    fd_findings = []
    try:
        fd_findings = await fd.run()
    except Exception as e:
        print(f"FD Error: {e}")

    # --- AI Mutator Test ---
    mutator = AIMutatorEngine()
    mutator.context = ctx
    mutator.target = target
    mutator.brain = MockBrain()  # Bypass local API key requirement for testing
    mutator.emit_progress = lambda **kw: None
    mutator.emit_vulnerability = lambda v: mutator.results.append(v) if hasattr(mutator, 'results') else None
    
    mutator_findings = []
    try:
        mutator_findings = await mutator.run()
    except Exception as e:
        print(f"Mutator Error: {e}")
        
    output_data = {
        "frontend_vulns": fd_findings,
        "mutator_vulns": mutator_findings
    }
    
    with open("test_results.json", "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)

if __name__ == "__main__":
    asyncio.run(main())
