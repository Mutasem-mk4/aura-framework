import asyncio
import os
from aura.modules.poc_visualizer import PoCVisualizer

async def run():
    artifact_path = r"C:\Users\User\.gemini\antigravity\scratch\aura\reports\evidence\artifacts\ghost_csrf_bypass.html"
    file_url = "file://" + artifact_path.replace("\\", "/")
    
    visualizer = PoCVisualizer()
    print(f"Generating proof for GHOST bypass...")
    path = await visualizer.generate_visual_proof(file_url, "Ghost CSRF Bypass")
    
    if path:
        print(f"SUCCESS: Screenshot saved to {path}")
    else:
        print("FAILED: No screenshot generated.")

if __name__ == "__main__":
    asyncio.run(run())
