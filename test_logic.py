import asyncio
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
from aura.modules.logic_engine import AILogicEngine
import httpx

class MockSession:
    async def request(self, method, url, timeout=10, **kwargs):
        async with httpx.AsyncClient() as client:
            return await client.request(method, url, timeout=timeout)

async def test_logic_engine():
    urls_to_test = [
        "http://127.0.0.01:5000/api/profile?id=1",
        "http://127.0.0.1:5000/api/transfer?amount=50"
    ]
    
    session = MockSession()
    engine = AILogicEngine(session=session)
    
    print("Testing Logic Engine against Mock API...")
    findings = await engine.analyze(urls_to_test)
    
    for f in findings:
        print(f"\n[DETECTED] {f['type']} at {f['url']}")
        print(f"Method: {f['method']}")

if __name__ == "__main__":
    asyncio.run(test_logic_engine())
