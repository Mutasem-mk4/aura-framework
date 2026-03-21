import httpx
import asyncio

async def main():
    targets = ["https://brokencrystals.com", "http://testphp.vulnweb.com", "http://testasp.vulnweb.com"]
    async with httpx.AsyncClient(verify=False, timeout=5) as c:
        for t in targets:
            try:
                r = await c.get(t)
                print(f"{t}: HTTP {r.status_code}")
            except Exception as e:
                print(f"{t}: Error {e}")

asyncio.run(main())
