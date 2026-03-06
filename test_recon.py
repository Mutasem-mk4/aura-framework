import asyncio
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
from aura.modules.recon_pipeline import ReconPipeline

async def main():
    pipeline = ReconPipeline()
    subs = await pipeline.stage1_subfinder("intel.com")
    print(f"Total live subdomains retrieved: {len(subs)}")

asyncio.run(main())
