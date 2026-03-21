"""
Aura - TestPHP VulnWeb Attack Test
Target: http://testphp.vulnweb.com
"""
import asyncio
import json
import httpx
from aura.modules.frontend_deconstructor import FrontendDeconstructor
from aura.modules.ai_mutator import AIMutatorEngine

TARGET = "http://testphp.vulnweb.com"

class MockContext:
    def __init__(self, target):
        self.target = target
        self.target_url = target
        self.intel = {
            "urls": {
                f"{target}/listproducts.php?cat=1",
                f"{target}/artists.php?artist=1",
                f"{target}/search.php?test=query"
            }
        }
    def get_intel(self):
        return self.intel

class MockBrain:
    def analyze(self, prompt):
        return "-1 UNION SELECT 1,2,3,4,5,6,7,8,9,10,11--"

async def main():
    ctx = MockContext(TARGET)
    
    # --- Frontend Deconstructor Test ---
    fd = FrontendDeconstructor()
    fd.context = ctx
    fd.target = TARGET
    fd.emit_progress = lambda **kw: None
    fd.emit_vulnerability = lambda v: fd.results.append(v) if hasattr(fd, 'results') else None
    
    fd_findings = []
    try:
        fd_findings = await fd.run()
    except Exception as e:
        pass

    # --- AI Mutator Test ---
    mutator = AIMutatorEngine()
    mutator.context = ctx
    mutator.target = TARGET
    mutator.brain = MockBrain()  # Simulates LLM generating a Union SQLi payload tailored for testphp
    mutator.emit_progress = lambda **kw: None
    mutator.emit_vulnerability = lambda v: mutator.results.append(v) if hasattr(mutator, 'results') else None
    
    mutator_findings = []
    try:
        mutator_findings = await mutator.run()
    except Exception as e:
        pass
        
    output_data = {
        "target": TARGET,
        "frontend_vulns": fd_findings,
        "mutator_vulns": mutator_findings
    }
    
    with open("testphp_results.json", "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)

if __name__ == "__main__":
    asyncio.run(main())
