from __future__ import annotations

"""
aura.phases.recon

Controller for Phase 2: Active Reconnaissance.
Implements the BaseEngine Protocol and is decoupled from the main Orchestrator.
"""

from typing import Any
from aura.core.engine_base import AbstractEngine
from aura.ui.formatter import ZenithUI, console
from aura.modules.recon_pipeline import ReconPipeline
from aura.modules.secret_hunter import SecretHunter

class ReconPhase(AbstractEngine):
    """
    Executes deep infrastructure mapping, subdomain discovery, and secret hunting.
    """
    def __init__(self, recon_pipeline: ReconPipeline, secret_hunter: SecretHunter, takeover_hunter: Any) -> None:
        super().__init__()
        self.recon_pipeline = recon_pipeline
        self.secret_hunter = secret_hunter
        self.takeover_hunter = takeover_hunter

    async def run(
        self,
        target_ip: str | None = None,
        intel_data: dict[str, Any] | None = None,
        campaign_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Executes the recon phase using the provided MissionContext.
        """
        domain = self.context.target_url
        
        if self.context.flags.clinic_mode:
            ZenithUI.clinic_info("Phase 2: Active Recon", "Here we map the infrastructure. We look for hidden subdomains and services that might be vulnerable or forgotten by the owner.")
            
        ZenithUI.phase_banner("Phase 2: Active Reconnaissance", domain, icon="[SATELLITE]")
        self._emit_progress("Mapping infrastructure & subdomains...", percentage=30)
        
        # 1. Pipeline Execution
        recon_data = await self.recon_pipeline.run(
            domain, 
            target_ip, 
            intel_data=intel_data or {}, 
            stealth_mode=self.context.flags.fast_mode,
            beginner_mode=self.context.flags.beginner_mode
        )
        
        # 2. Subdomain Takeover Analysis
        all_subs = recon_data.get("subdomains", [])
        if all_subs and self.takeover_hunter:
            await self.takeover_hunter.run(all_subs)
            
        # 3. Active Secret Hunting on discovered URLs
        found_urls = [r["url"] for r in recon_data.get("urls", []) if "url" in r]
        if found_urls:
            console.print(f"[bold yellow]SecretHunter: Scanning JS/Config files in {len(found_urls)} URLs...[/bold yellow]")
            secrets = await self.secret_hunter.hunt_js_files(found_urls)
            if secrets:
                for s in secrets:
                    self._emit_vuln(s)
                    
        return recon_data
