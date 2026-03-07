import asyncio
from aura.modules.lateral_engine import LateralEngine
from aura.core.brain import AuraBrain

async def test_nebula():
    brain = AuraBrain()
    lateral = LateralEngine(brain)
    
    test_finding = {
        "type": "SSRF",
        "url": "https://victim.com/api/proxy",
        "param": "url",
        "content": "Server returned status 200 from 169.254.169.254"
    }
    
    print("Testing Nebula Ghost Escalation...")
    await lateral.pivot_from_finding(test_finding)
    
    if test_finding.get("escalation_attempted"):
        print(f"SUCCESS: Escalation attempted!")
        print(f"Type: {test_finding.get('escalation_type')}")
        print(f"Payload: {test_finding.get('escalation_payload')}")
    else:
        print("FAILURE: Escalation not triggered.")

if __name__ == "__main__":
    asyncio.run(test_nebula())
