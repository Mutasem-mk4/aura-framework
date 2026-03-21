import asyncio
import httpx
import os

async def inspect():
    if not os.path.exists("paypal_bundles.txt"):
        print("Error: Missing bundles list.")
        return

    with open("paypal_bundles.txt", "r") as f:
        url = f.readline().strip()
    
    print(f"[*] Inspecting sample bundle: {url}")
    async with httpx.AsyncClient(verify=False) as client:
        resp = await client.get(url, timeout=20)
        if resp.status_code == 200:
            print("\n--- SAMPLE CONTENT (FIRST 2000 CHARS) ---")
            print(resp.text[:2000])
            print("\n--- END SAMPLE ---")
        else:
            print(f"Failed to fetch: {resp.status_code}")

if __name__ == "__main__":
    asyncio.run(inspect())
