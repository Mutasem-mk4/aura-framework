"""
aura.phases.deconstruction

Controller for Phase 3.5: API & Frontend Deconstruction.
Abstracts the massive nested try/except blocks of API/GQL Reapers.
"""

from typing import Any, Dict, List, Optional
from aura.core.engine_base import AbstractEngine
from aura.ui.formatter import ZenithUI, console
import asyncio

class DeconstructionPhase(AbstractEngine):
    """
    Dissects Webpack frontends, REST APIs, and GraphQL endpoints dynamically.
    """
    def __init__(self, ssti_engine: Any, smuggling_engine: Any, ws_oauth_engine: Any, logic_fuzzer: Any, brain: Any):
        super().__init__()
        self.ssti_engine = ssti_engine
        self.smuggling_engine = smuggling_engine
        self.ws_oauth_engine = ws_oauth_engine
        self.logic_fuzzer = logic_fuzzer
        self.brain = brain

    async def run(self, recon_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        domain = self.context.target_url
        ZenithUI.phase_banner("Phase 3.5: Deconstruction Doctrine", domain, icon="🏗️")
        self._emit_progress("Dissecting frontend and APIs...", percentage=60)
        
        all_findings = []
        endpoints_to_fuzz = []
        
        # 1. Webpack Unpacker (Frontend Deconstructor)
        try:
            from aura.modules.frontend_deconstructor import FrontendDeconstructor
            webpack_engine = FrontendDeconstructor(target=domain)
            webpack_findings = await webpack_engine.run()
            all_findings.extend(webpack_findings)
            hidden_routes = [f["value"] for f in webpack_findings if "Endpoint" in f.get("type", "")]
            for r in hidden_routes:
                endpoints_to_fuzz.append({
                    "method": "GET", 
                    "path": r, 
                    "fuzz_params": ["id", "q", "page"], 
                    "fuzz_types": ["sqli", "xss", "path_traversal", "ssrf"]
                })
        except Exception as e:
            hidden_routes = []
            console.print(f"[dim red]Webpack Unpacker error: {e}[/dim red]")

        # 2. API Reaper
        try:
            from aura.modules.api_reaper import APIReaper
            api_engine = APIReaper(target=domain, discovered_endpoints=hidden_routes)
            api_findings = await api_engine.run()
            all_findings.extend(api_findings)
            for ep in getattr(api_engine, 'endpoints', []):
                params = ep.get("params", {})
                params_dict = {k: v for k, v in params.items()} if isinstance(params, dict) else {}
                fuzz_param_names = list(params_dict.keys())
                
                if fuzz_param_names or ep.get("body_schema"):
                    endpoints_to_fuzz.append({
                        "method": ep["method"],
                        "path": ep["path"],
                        "params": params_dict,
                        "data": ep.get("body_schema", {}) if isinstance(ep.get("body_schema"), dict) else {},
                        "fuzz_params": fuzz_param_names,
                        "fuzz_types": ["sqli", "xss", "path_traversal", "negative", "boolean_toggle"]
                    })
        except Exception as e: console.print(f"[dim red]API Reaper error: {e}[/dim red]")
        
        # 3. GraphQL Reaper
        try:
            from aura.modules.graphql_reaper import GraphQLReaper
            graphql_engine = GraphQLReaper(target=domain)
            graphql_findings = await graphql_engine.run()
            all_findings.extend(graphql_findings)
        except Exception as e: console.print(f"[dim red]GraphQL Reaper error: {e}[/dim red]")
        
        # 4. Specialized Engines (SSTI, Smuggling, WS/OAuth)
        try:
            if self.ssti_engine:
                self.ssti_engine.target = domain
                ssti_findings = await self.ssti_engine.run({"all_api_calls": [{"url": domain}]})
                all_findings.extend(ssti_findings)
        except Exception as e: console.print(f"[dim red]SSTI Engine error: {e}[/dim red]")

        try:
            if self.smuggling_engine:
                smuggling_findings = await self.smuggling_engine.scan_target(domain)
                all_findings.extend(smuggling_findings)
        except Exception as e: console.print(f"[dim red]Smuggling Engine error: {e}[/dim red]")

        try:
            if self.ws_oauth_engine:
                ws_oauth_findings = await self.ws_oauth_engine.scan_target(domain)
                all_findings.extend(ws_oauth_findings)
        except Exception as e: console.print(f"[dim red]WS+OAuth Engine error: {e}[/dim red]")

        # 5. Neural-Chain Autonomous Fuzzer
        if endpoints_to_fuzz and self.logic_fuzzer and self.brain:
            console.print(f"[bold red][⛓️] Neural-Chain: Synthesizing autonomous workflow for {len(endpoints_to_fuzz)} endpoints...[/bold red]")
            workflow_json = await asyncio.to_thread(self.brain.synthesize_workflow, endpoints_to_fuzz)
            
            if workflow_json:
                console.print(f"[bold cyan]🧠 [Brain] Workflow synthesized with {len(workflow_json)} steps.[/bold cyan]")
                findings = await self.logic_fuzzer.run(
                    target=domain, 
                    workflow_json=workflow_json
                )
                for f in findings:
                    vuln = f.model_dump() if hasattr(f, "model_dump") else f
                    all_findings.append(vuln)
                    console.print(f"[bold red][[!!!]] Logic Flaw Detected: {vuln.get('content')}[/bold red]")
            else:
                console.print("[yellow][!] AI failed to synthesize a valid workflow. Skipping autonomous fuzzer.[/yellow]")

        for f in all_findings:
            self._emit_vuln(f)
            
        return all_findings