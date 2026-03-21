import logging
import asyncio
import os
import httpx
import re
from typing import List, Dict, Any, Optional
from aura.core.brain import AuraBrain
from aura.ui.formatter import ZenithUI

logger = logging.getLogger("aura")

class WeaponizationEngine:
    """
    Phase 4: Zero-Day & CVE Weaponization (Optimized).
    Monitors GitHub for top 2 fresh CVEs and synthesizes hardened Aura modules.
    """
    def __init__(self, brain: AuraBrain, modules_dir: str = None):
        self.brain = brain
        self.modules_dir = modules_dir or os.path.join(os.path.dirname(__file__), "..", "plugins")
        if not os.path.exists(self.modules_dir):
            os.makedirs(self.modules_dir)
        
    async def poll_feeds(self) -> List[Dict[str, str]]:
        """Polls for top 2 fresh CVEs from 2025 for maximum scan startup speed."""
        new_pocs = []
        
        with ZenithUI.status("Polling global feeds for fresh 0-Days..."):
            headers = {"Accept": "application/vnd.github.v3+json"}
            from datetime import datetime, timedelta
            recent_date = (datetime.utcnow() - timedelta(days=1)).strftime('%Y-%m-%d')
            
            # Target 2025 CVEs for extreme freshness
            query = f"CVE-2025 PoC created:>{recent_date}"
            url = f"https://api.github.com/search/repositories?q={query}&sort=updated&order=desc"
            
            try:
                async with httpx.AsyncClient() as client:
                    resp = await client.get(url, headers=headers, timeout=5.0)
                    if resp.status_code == 200:
                        data = resp.json()
                        # Limit to TOP 2 to prevent scan startup delays
                        for item in data.get("items", [])[:2]:
                            repo_name = item.get("full_name")
                            readme_url = f"https://raw.githubusercontent.com/{repo_name}/main/README.md"
                            readme_resp = await client.get(readme_url, timeout=5.0)
                            
                            new_pocs.append({
                                "cve_id": repo_name.split("/")[-1].upper(),
                                "repo": repo_name,
                                "content": (readme_resp.text if readme_resp.status_code == 200 else "")[:1500]
                            })
            except Exception: pass
            
        return new_pocs

    async def synthesize_weapon(self, poc_data: Dict[str, str]) -> Optional[str]:
        """Synthesizes a native Aura plugin while strictly stripping AI markdown garbage."""
        cve_id = poc_data.get('cve_id', 'Unknown_CVE')
        
        with ZenithUI.status(f"Forging native Aura module for {cve_id} via Sentient AI..."):
            prompt = (
                f"As AURA-Zenith AI, synthesize a Python 3 AuraPlugin class for {cve_id}.\n"
                f"Context: {poc_data.get('content')}\n"
                "Requirements: Inherit from AuraPlugin, implement async run(target, context).\n"
                "STRICT: Respond ONLY with the raw Python code. NO markdown formatting, NO ```python tags."
            )
            
            raw_code = await asyncio.to_thread(self.brain._call_ai, prompt, use_cache=True)
            
            if raw_code:
                # Hardened cleaning: Strip ALL markdown tags and language identifiers
                clean_code = re.sub(r"```[a-zA-Z]*", "", raw_code).replace("```", "").strip()
                
                if "class " in clean_code and "AuraPlugin" in clean_code:
                    header = "import asyncio\nimport httpx\nfrom aura.plugins.base import AuraPlugin\n\n"
                    return header + clean_code
                
        return None

    async def deploy_weapon(self, cve_id: str, code: str):
        """Saves the synthesized weapon to the plugins directory for immediate loading."""
        if not code: 
            return
        
        safe_name = cve_id.lower().replace("-", "_").replace(".", "_")
        filename = f"auto_{safe_name}.py"
        filepath = os.path.join(self.modules_dir, filename)
        
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(code)
            logger.info(f"[☢️ WEAPONIZATION] Weapon {filename} successfully forged and deployed.")
        except Exception as e:
            logger.error(f"[☢️ WEAPONIZATION] Failed to save weapon {filename}: {e}")

    async def run_weaponization_cycle(self):
        """The main autonomous loop called during mission start."""
        pocs = await self.poll_feeds()
        
        if not pocs:
            logger.info("[☢️ WEAPONIZATION] No new 0-days found in the current cycle.")
            return

        for poc in pocs:
            cve_id = poc.get("cve_id", "")
            safe_name = cve_id.lower().replace("-", "_").replace(".", "_")
            
            if os.path.exists(os.path.join(self.modules_dir, f"auto_{safe_name}.py")):
                continue
                
            weapon_code = await self.synthesize_weapon(poc)
            if weapon_code:
                await self.deploy_weapon(cve_id, weapon_code)
