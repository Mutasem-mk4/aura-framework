import asyncio
import sys
import os

# Add aura to path
sys.path.append(os.getcwd())

from aura.core.polymorphic_engine import PolymorphicEngine

async def test_polymorphic():
    engine = PolymorphicEngine()
    payload = "' OR 1=1--"
    print(f"Base Payload: {payload}")
    
    swarm = await engine.generate_swarm(payload, count=5, context="Cloudflare")
    
    print("\nPolymorphic Swarm:")
    for i, p in enumerate(swarm):
        print(f"{i+1}: {repr(p)}")

if __name__ == "__main__":
    asyncio.run(test_polymorphic())
