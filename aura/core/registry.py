"""
aura.core.registry

The EngineRegistry is a central dynamic loader that manages all vulnerability,
OSINT, and utility engines. It handles instantiation with the unified
constructor (persistence, telemetry, brain) and supports Smart Routing.
"""

import asyncio
import logging
import importlib
import pkgutil
import inspect
from typing import Any, Dict, Optional, List, Type
from aura.core.context import MissionContext
from aura.core.engine_base import AbstractEngine
from aura.core.engine_interface import IEngine

logger = logging.getLogger("aura.registry")

class EngineRegistry:
    """
    Singleton Registry for Aura Engines.
    Loads modules dynamically and manages their lifecycle.
    Supports Smart Routing based on Finding Types.
    """
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, package_path: str = "aura.modules"):
        if self._initialized:
            return
            
        self.package_path = package_path
        self._engines: Dict[str, Type[AbstractEngine]] = {}
        self._routing_rules: Dict[str, List[str]] = {
            "subdomain": ["threat_intel", "subdomain_takeover"],
            "endpoint": ["api_reaper", "graphql_reaper"],
            "vulnerability": ["exploit_chain", "apex_sentinel"],
            "secret": ["secret_hunter", "leak_prober"]
        }
        
        # Register core engines from aura.core
        self._register_core_engines()
        
        self._initialized = True
        logger.info("EngineRegistry initialized.")
    
    def _register_core_engines(self):
        """Register core engines that live in aura.core."""
        try:
            from aura.core.nexus_bridge import NexusBridge
            self._engines["nexus_bridge"] = NexusBridge
            logger.debug("Registered core engine: nexus_bridge")
            
            # Register known modules that may not be in aura.modules
            self._try_register("aura.modules.leaks", "leak_prober")
            self._try_register("aura.modules.secret_hunter", "secret_hunter")
            self._try_register("aura.modules.cve_provider", "cve_provider")
            self._try_register("aura.modules.pivoting", "aura_link")
            self._try_register("aura.modules.lateral_engine", "lateral_engine")
            self._try_register("aura.modules.takeover", "subdomain_takeover")
            self._try_register("aura.modules.nuclei_engine", "nuclei_engine")
            self._try_register("aura.modules.submitter", "bounty_submitter")
            self._try_register("aura.modules.profit_engine", "profit_engine")
            self._try_register("aura.modules.ssti_engine", "ssti_engine")
            self._try_register("aura.modules.smuggling_engine", "smuggling_engine")
            self._try_register("aura.modules.oauth_engine", "ws_oauth_engine")
            self._try_register("aura.modules.fleet_manager", "fleet_manager")
            self._try_register("aura.modules.mission_hunter", "mission_hunter")
            self._try_register("aura.modules.sentinel_watch", "sentinel_watch")
            self._try_register("aura.modules.omega_crawler", "omega_crawler")
            self._try_register("aura.modules.apex_sentinel", "apex_sentinel")
            self._try_register("aura.modules.shadow_state", "shadow_state_modeler")
            self._try_register("aura.modules.bounty_reporter", "bounty_reporter")
            self._try_register("aura.modules.bola_butcher", "bola_butcher")
            self._try_register("aura.modules.race_assassin", "race_assassin")
            self._try_register("aura.modules.ai_mutator", "ai_mutator")
            self._try_register("aura.modules.exploit_chain", "exploit_chain")
            self._try_register("aura.modules.stateful_logic_fuzzer", "logic_fuzzer")
            self._try_register("aura.modules.dorks_intel", "dorks_intel")
            self._try_register("aura.modules.heavy_weapons", "heavy_weapons")
            self._try_register("aura.modules.cloud_recon", "aura_cloud_recon")
            self._try_register("aura.modules.ghost_ops", "ghost_ops")
            self._try_register("aura.modules.api_reaper", "api_reaper")
            self._try_register("aura.modules.frontend_deconstructor", "frontend_deconstructor")
            self._try_register("aura.modules.graphql_reaper", "graphql_reaper")
            
        except ImportError as e:
            logger.warning(f"Failed to register core engines: {e}")
    
    def _try_register(self, module_name: str, engine_id: str = None):
        """Try to import and register an engine from a module."""
        try:
            mod = importlib.import_module(module_name)
            for name, obj in inspect.getmembers(mod, inspect.isclass):
                if issubclass(obj, (AbstractEngine, IEngine)) and obj not in (AbstractEngine, IEngine):
                    eid = engine_id or getattr(obj, "ENGINE_ID", name.lower())
                    self._engines[eid] = obj
                    logger.debug(f"Registered engine: {eid} from {module_name}")
                    return True
        except Exception:
            pass
        return False

    def discover(self):
        """Dynamic Discovery: Scans aura.modules for classes implementing AbstractEngine or IEngine."""
        try:
            package = importlib.import_module(self.package_path)
            for _, name, is_pkg in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
                if not is_pkg:
                    try:
                        mod = importlib.import_module(name)
                        for _, obj in inspect.getmembers(mod, inspect.isclass):
                            # Support both AbstractEngine and IEngine inheritance
                            if (issubclass(obj, (AbstractEngine, IEngine)) 
                                and obj not in (AbstractEngine, IEngine)):
                                engine_id = getattr(obj, "ENGINE_ID", obj.__name__.lower())
                                self._engines[engine_id] = obj
                                logger.debug(f"Discovered engine: {engine_id}")
                    except Exception as e:
                        logger.warning(f"Failed to load module {name}: {e}")
        except Exception as e:
            logger.error(f"Registry discovery failed: {e}")

    def register(self, engine_id: str, engine_class: Type[AbstractEngine]):
        """Manually register an engine class."""
        self._engines[engine_id] = engine_class
        logger.info(f"Registered engine: {engine_id}")

    def register_routing_rule(self, trigger: str, engine_ids: List[str]):
        """Add a smart routing rule (trigger -> list of engines to run)."""
        self._routing_rules[trigger] = engine_ids

    def get_engine(self, engine_id: str) -> Optional[Type[AbstractEngine]]:
        """Retrieve an engine class by ID."""
        return self._engines.get(engine_id)

    def list_engines(self) -> List[str]:
        """Return list of all registered engine IDs."""
        return list(self._engines.keys())

    def resolve_routing(self, finding_type: str) -> List[str]:
        """
        Smart Routing: Returns a list of engine IDs to run based on the finding type.
        Falls back to empty list if no rule matches.
        """
        finding_type_lower = finding_type.lower()
        
        # Exact match
        if finding_type_lower in self._routing_rules:
            return self._routing_rules[finding_type_lower]
            
        # Partial match (e.g., "SQL Injection" contains "injection")
        for trigger, engines in self._routing_rules.items():
            if trigger in finding_type_lower:
                return engines
                
        return []

    async def instantiate_and_run(self, engine_id: str, context: MissionContext, **kwargs) -> Optional[Any]:
        """
        Factory method: Instantiates an engine and runs it with the MissionContext.
        Handles asyncio properly.
        """
        engine_cls = self.get_engine(engine_id)
        if not engine_cls:
            logger.warning(f"Engine {engine_id} not found in registry.")
            return None
            
        try:
            # Unified Constructor Injection
            instance = engine_cls(**kwargs)
            
            # Standard Lifecycle
            if hasattr(instance, 'setup'):
                await instance.setup(context)
                
            if hasattr(instance, 'run'):
                result = await instance.run()
                
            if hasattr(instance, 'teardown'):
                await instance.teardown()
                
            return result
            
        except Exception as e:
            logger.error(f"Failed to run engine {engine_id}: {e}")
            return None

    async def run_parallel(self, engine_ids: List[str], context: MissionContext, timeout: float = 300.0, **kwargs) -> List[Any]:
        """
        Async Execution: Runs multiple engines in parallel without blocking.
        Wrapped in wait_for to eliminate Ghost Processes.
        """
        tasks = [
            self.instantiate_and_run(eid, context, **kwargs) 
            for eid in engine_ids
        ]
        
        # Ghost Process Elimination: use wait_for
        try:
            results = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=timeout)
            return [r for r in results if not isinstance(r, Exception)]
        except asyncio.TimeoutError:
            logger.warning(f"Parallel execution timed out after {timeout}s.")
            return []

# Global Access
_registry = None
def get_registry() -> EngineRegistry:
    global _registry
    if _registry is None:
        _registry = EngineRegistry()
        _registry.discover() # Auto-discover on first access
    return _registry
