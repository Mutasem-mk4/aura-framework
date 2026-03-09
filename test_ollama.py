import asyncio
from aura.core.brain import AuraBrain

def test():
    brain = AuraBrain()
    print("AI Enabled:", brain.enabled)
    print("Provider:", brain.active_provider)
    print("Testing reason_json...")
    res = brain.reason_json("Generate a fake vulnerability finding.", "Respond ONLY in JSON: {'vuln': 'name'}")
    print("Response:", res)

if __name__ == "__main__":
    test()
