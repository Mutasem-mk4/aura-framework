import asyncio
from aura.core.stealth import StealthEngine, AuraSession
from aura.core import state

async def run_test():
    stealth = StealthEngine()
    session = AuraSession(stealth)
    
    domain = "dvwa.co.uk"
    resp = await session.get(f"https://{domain}", timeout=10)
    
    print("Response Status:", resp.status_code if resp else 'None')
    if resp:
        print("Response Server:", resp.headers.get("server", ""))

asyncio.run(run_test())
