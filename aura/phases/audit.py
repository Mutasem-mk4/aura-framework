from __future__ import annotations

"""
aura.phases.audit

Controller for Phase 4: Deep Security Audit.
Manages the concurrent execution of DAST, Nuclei, Singularity, and Apex Sentinel.
"""

from typing import Any
from aura.core.engine_base import AbstractEngine
from aura.ui.formatter import ZenithUI, console
import asyncio

class AuditPhase(AbstractEngine):
    """
    Executes core exploitation payloads, fuzzy testing, and autonomous logic verification.
    """
    def __init__(self, power_stack: Any, nuclei_engine: Any, singularity: Any, dast: Any, fleet_manager: Any, apex: Any, bounty_reporter: Any) -> None:
        super().__init__()
        self.power_stack = power_stack
        self.nuclei_engine = nuclei_engine
        self.singularity = singularity
        self.dast = dast
        self.fleet_manager = fleet_manager
        self.apex = apex
        self.bounty_reporter = bounty_reporter
        
        self.dast_semaphore = asyncio.Semaphore(10)
        self.sing_semaphore = asyncio.Semaphore(5)

    async def run(self, discovered_urls: list[str], swarm_mode: bool = False) -> list[dict[str, Any]]:
        domain = self.context.target_url
        ZenithUI.phase_banner("Phase 4: Deep Security Audit", domain, icon="💥")
        self._emit_progress("Initiating Deep Security Audit...", percentage=75)
        
        all_vulns = []
        
        # Zenith v33: Engaging Heavy Weapons Suite
        try:
            from aura.modules.scanners.smuggling_engine import SmugglingEngine
            from aura.modules.scanners.race_engine import RaceEngine
            smuggler = SmugglingEngine()
            racer = RaceEngine()
            
            console.print("[bold red]Engaging Smuggling & Race Engines (Zenith Suite)...[/bold red]")
            heavy_results = await asyncio.gather(
                smuggler.run(domain),
                racer.run(domain, discovered_urls)
            )
            for sub_finding_list in heavy_results:
                all_vulns.extend(sub_finding_list)
        except ImportError:
            console.print("[dim yellow]Heavy Weapons Suite not available in this build.[/dim yellow]")

        # 1. PowerStack / Nuclei
        try:
            if self.power_stack:
                power_findings = await self.power_stack.nuclei_scan(domain)
                all_vulns.extend(power_findings)
            elif self.nuclei_engine:
                vulns = await self.nuclei_engine.scan(domain)
                all_vulns.extend(vulns)
        except Exception as e:
            console.print(f"[dim red][!] PowerStack/Nuclei error: {e}[/dim red]")

        # 2. AuraSingularity
        try:
            if self.singularity:
                async with self.sing_semaphore:
                    sing_findings = await self.singularity.execute_singularity(domain)
                    all_vulns.extend(sing_findings)
        except Exception as e:
            console.print(f"[dim red][!] AuraSingularity skipped: {e}[/dim red]")

        # 3. AuraDAST (Multi-target Fuzzing)
        unique_urls = list(set([domain] + discovered_urls))
        targets_to_audit = unique_urls[:15] # Audit Limit
        
        async def _run_dast(url):
            async with self.dast_semaphore:
                try:
                    return await self.dast.scan_target(url)
                except Exception as e:
                    console.print(f"[dim red][!] AuraDAST Error on {url}: {e}[/dim red]")
                    return []

        if swarm_mode and self.fleet_manager and getattr(self.fleet_manager, '_enabled', False):
            nodes = await self.fleet_manager.provision_nodes(count=3)
            await self.fleet_manager.distribute_workflow("deep-audit", targets_to_audit, nodes)
            swarm_results = await self.fleet_manager.collect_results()
            for res in swarm_results:
                all_vulns.extend(res.get("findings", []))
            await self.fleet_manager.decommission_fleet()
        else:
            if self.dast:
                dast_results = await asyncio.gather(*[_run_dast(u) for u in targets_to_audit])
                for cluster in dast_results:
                    all_vulns.extend(cluster)

        # 4. Apex Sentinel (Autonomous Verification)
        verified_vulns = []
        for v in all_vulns:
            if isinstance(v, dict) and v.get("severity") in ["CRITICAL", "HIGH", "MEDIUM"]:
                if self.apex:
                    is_real = await self.apex.verify_finding(v, domain)
                    if is_real:
                        v["confirmed"] = True
                        v["verified_by"] = "ApexSentinel"
                        verified_vulns.append(v)
                        if v.get("severity") in ["HIGH", "CRITICAL"] and self.bounty_reporter:
                            await self.bounty_reporter.generate_report(v)
                else:
                    verified_vulns.append(v)
            else:
                verified_vulns.append(v)

        # 5. Deduplicate and Emit
        final_vulns = []
        seen_findings = set()
        for v in verified_vulns:
            if isinstance(v, dict):
                sig = f"{v.get('type')}_{str(v.get('content'))[:100]}"
                if sig not in seen_findings:
                    seen_findings.add(sig)
                    final_vulns.append(v)
                    self._emit_vuln(v)
            elif isinstance(v, str):
                if v not in seen_findings:
                    seen_findings.add(v)
                    f_dict = {"type": "Manual Finding", "content": v, "severity": "MEDIUM"}
                    final_vulns.append(f_dict)
                    self._emit_vuln(f_dict)

        console.print(f"[bold green][OK] Deep Security Audit complete: {len(final_vulns)} verified vulnerabilities.[/bold green]")
        return final_vulns
