import asyncio
import os
from aura.modules.poc_visualizer import PoCVisualizer

async def run():
    # Use the absolute path to the generated exploit artifact
    artifact_path = r"C:\Users\User\.gemini\antigravity\scratch\aura\reports\evidence\artifacts\csrf_exploit_20260313_022337.html"
    
    if not os.path.exists(artifact_path):
        print(f"Artifact not found at {artifact_path}")
        return

    # Convert local path to file URL
    file_url = "file://" + artifact_path.replace("\\", "/")
    
    visualizer = PoCVisualizer()
    print(f"Generating visual proof for CSRF exploit...")
    path = await visualizer.generate_visual_proof(file_url, "OAuth CSRF Bypass")
    
    if path:
        print(f"SUCCESS: Screenshot saved to {path}")
    else:
        print("FAILED: No screenshot generated.")

if __name__ == "__main__":
    asyncio.run(run())
