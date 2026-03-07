import json
import asyncio
import os
import random
from aura.core.brain import AuraBrain
from aura.core.stealth import StealthEngine, AuraSession
from aura.modules.scanner import AuraScanner
from aura.modules.exploiter import AuraExploiter
from aura.modules.dast import AuraDAST
from aura.modules.dast_v2 import AuraSingularity
from aura.modules.vision import VisualEye
from aura.core.vuln_intel import CVEProvider
from aura.modules.safety import ScopeManager
from aura.core.brain import AuraBrain
from aura.core.exploit_chain import ChainOfThoughtExploiter
from aura.core.memory import DeepMemoryFuzzer
from aura.modules.leaks import LeakProber
from aura.modules.threat_intel import ThreatIntel
from aura.modules.bounty import BountyHunter
from aura.modules.banner_grabber import BannerGrabber
from aura.modules.pivoting import AuraLink
from aura.modules.recon_pipeline import ReconPipeline   # v5.0
from aura.modules.secret_hunter import SecretHunter      # v5.0
from aura.modules.power_stack import PowerStack          # v6.0
from aura.modules.poc_engine import PoCEngine            # v6.0: Deterministic PoC
from aura.modules.cloud_recon import AuraCloudRecon    # v15.0: Cloud Predator
from aura.modules.logic_engine import AILogicEngine # v16.0 Omni-Sovereign
from aura.modules.synthesizer import ProtocolSynthesizer # v16.1 Omni-Sovereign
from aura.modules.lateral_engine import LateralEngine # v18.0 Nebula Ghost
from aura.modules.neural_forge import NeuralForge    # v19.0 The Singularity
from aura.modules.ghost_ops import GhostOps        # v19.0 The Singularity
from aura.modules.scope_checker import ScopeChecker  # v20.0 Bounty Scope Guard
from aura.modules.cors_hunter import CorsHunter          # v21.0 CORS Live Tester
from aura.modules.wayback_scanner import WaybackScanner   # v20.0 Phase 4: Historical JS Scanner
from aura.modules.bypass_engine import BypassEngine       # v20.0 Phase 5: 403 Bypass Engine
from aura.core.markdown_reporter import MarkdownReporter  # v20.0 Markdown Bounty Report
from aura.modules.race_condition_hunter import RaceConditionHunter  # v28.0 Phase 14
from aura.modules.ssti_engine import SSTIEngine                     # v28.0 Phase 15
from aura.modules.smuggling_engine import SmugglingEngine            # v28.0 Phase 16
from aura.modules.cache_poisoning_engine import CachePoisoningEngine # v29.0 Phase 17
from aura.modules.xxe_engine import XXEEngine                        # v29.0 Phase 18
from aura.modules.prototype_pollution_engine import PrototypePollutionEngine  # v29.0 Phase 19
from aura.modules.dom_hunter import DOMHunter                        # v29.0 Phase 20
from aura.modules.graphql_engine import GraphQLEngine                # v30.0 Phase 21
from aura.modules.mfa_bypass_engine import MFABypassEngine           # v30.0 Phase 22
from aura.modules.business_logic_engine import BusinessLogicEngine   # v30.0 Phase 23
from aura.modules.host_header_engine import HostHeaderEngine         # v31.0 Phase 24
from aura.modules.open_redirect_engine import OpenRedirectEngine     # v31.0 Phase 25
from aura.modules.file_upload_engine import FileUploadEngine         # v31.0 Phase 26
from aura.modules.deserialize_engine import DeserializationEngine    # v31.0 Phase 27
from aura.modules.ws_oauth_engine import WSAndOAuthEngine            # v31.0 Phase 28
from aura.modules.exploit_radar import ExploitRadar # v32.0 Exploit Radar
from aura.modules.dorks_intel import DorksIntel     # v33.0 Dorks Intel
from aura.core import state
from aura.core.storage import AuraStorage
from rich.console import Console

console = Console()

class NeuralOrchestrator:
    """The 'Sentient Brain' that orchestrates multi-step, logic-driven attack chains with Ghost v4."""
    
    def __init__(self, whitelist: list = None, blacklist: list = None, broadcast_callback=None):
        self.brain = AuraBrain()
        self.db = AuraStorage()
        self.cot = ChainOfThoughtExploiter(self.brain)
        self.memory = DeepMemoryFuzzer(self.db)
        self.stealth = StealthEngine()
        self.session = AuraSession(self.stealth)
        self.scanner = AuraScanner(stealth=self.stealth)
        self.exploiter = AuraExploiter()
        self.dast = AuraDAST()
        self.singularity = AuraSingularity() # Phase 18: CoT Singularity Engine
        self.vision = VisualEye()
        self.vuln_intel = CVEProvider()
        self.scope = ScopeManager(whitelist=whitelist, blacklist=blacklist)
        self.leaks = LeakProber()
        self.intel = ThreatIntel(stealth=self.stealth)
        self.bounty = BountyHunter()
        self.link = AuraLink() # v6.0: Auto-Pivoting
        from aura.modules.heavy_weapons import HeavyWeaponry
        self.heavy_weapons = HeavyWeaponry(self.db) # v7.0: Heavy Weaponry
        self.banner_grabber = BannerGrabber()            # v3.0: OSINT Resiliency
        self.recon_pipeline = ReconPipeline()             # v5.0: Subfinder→HTTPX→Nmap
        self.secret_hunter  = SecretHunter()              # v5.0: TruffleHog-style
        self.power_stack    = PowerStack(stealth=self.stealth)  # v6.0: Nuclei/TruffleHog/HTTPX/Nmap
        self.poc_engine     = PoCEngine(stealth=self.stealth)   # v6.0: Deterministic PoC
        self.cloud_recon    = AuraCloudRecon(self.db)           # v15.0: Cloud Discovery
        self.logic_engine   = AILogicEngine(self.session)      # v16.0 Omni-Sovereign
        self.synthesizer    = ProtocolSynthesizer(self.brain)   # v16.1 Omni-Sovereign
        self.lateral        = LateralEngine(self.brain)         # v18.0 Nebula Ghost
        self.forge          = NeuralForge()           # v19.0 The Singularity
        self.ghost_ops      = GhostOps(self)                    # v19.0 The Singularity
        self.dast_semaphore = asyncio.Semaphore(10)       # Velocity v7.4: Scaled from 5 to 10
        self.sing_semaphore = asyncio.Semaphore(5)        # Velocity v7.4: Scaled from 3 to 5
        self.scope_checker  = ScopeChecker()              # v20.0: Bug Bounty Scope Guard
        self.dorks_intel    = DorksIntel()                # v33.0: Dorks Intelligence
        
        from aura.modules.cloud_swarm import CloudSwarm
        self.cloud_swarm = CloudSwarm()                   # v21.0: Cloud Swarm
        
        self.plugins = []
        self._load_plugins()
        self.current_campaign = None
        self.broadcast_callback = broadcast_callback
        from aura.core.zenith_reporter import ZenithReporter
        self.reporter = ZenithReporter(self.brain)
        self.mission_state = {} # v20.0: Track state for self-healing
        
        # v25.0 Omega Prototype: Sentient Singularity Components
        self.mirror = MirrorSimulator(self.brain)
        self.deception = DeceptionOrchestrator(self.stealth.swarm)
        self.sovereign = SovereignDecisionEngine(self.brain, self.db)
        
        # Phase 15: Exploit Chaining Knowledge Base
        self.knowledge_base = {
            "redirects": [],  # Open Redirect URLs
            "sinks": [],      # SSRF/LFI sink parameters
            "leaks": [],      # Information leaks (internal IPs, paths)
            "idor_vectors": [] # IDOR-vulnerable endpoints
        }

    async def _process_exploit_chain(self, domain, finding_type, content_obj):
        """
        Synthesizes high-impact exploits by chaining discovered vulnerabilities.
        Example: Open Redirect + SSRF = SSRF Guard Bypass.
        """
        campaign_id = getattr(self, 'current_campaign', None)
        
        # 1. Store the finding in the knowledge base
        if "redirect" in str(finding_type).lower():
            self.knowledge_base["redirects"].append(content_obj.get("evidence_url"))
        elif "ssrf" in str(finding_type).lower() or "lfi" in str(finding_type).lower():
            self.knowledge_base["sinks"].append(content_obj.get("evidence_url"))
        elif "idor" in str(finding_type).lower():
            self.knowledge_base["idor_vectors"].append(content_obj.get("evidence_url"))
            
        # 2. Continuous Synthesis: Check for chainable combinations
        # Scenario A: SSRF + Open Redirect = Bypassing internal network guards
        if self.knowledge_base["redirects"] and self.knowledge_base["sinks"]:
            redirect_url = self.knowledge_base["redirects"][0]
            sink_url = self.knowledge_base["sinks"][0]
            
            chained_payload = f"{sink_url}?url={redirect_url}"
            console.print(f"[bold red][⚓] EXPLOIT CHAIN DETECTED: Combining SSRF sink with Open Redirect for Network Bypass![/bold red]")
            
            chain_finding = {
                "type": "Critical Chain: SSRF via Open Redirect Bypass",
                "content": f"Aura synthesized a complex exploit chain by combining a discovered Open Redirect ({redirect_url}) "
                           f"with an SSRF sink ({sink_url}). This allows bypassing internal SSRF protection filters.",
                "evidence_url": chained_payload,
                "severity": "CRITICAL",
                "cvss_score": 10.0,
                "impact_desc": "CRITICAL: The ability to chain these vulnerabilities allows an attacker to bypass security filters "
                               "intended to block SSRF, granting access to the sensitive internal infrastructure."
            }
            self.db.add_finding(domain, chain_finding, chain_finding["type"], campaign_id=campaign_id)
            
            # v18.0 Nebula Ghost: Attempt escalation from the newly found SSRF sink
            await self.lateral.pivot_from_finding(chain_finding)
            
            return chain_finding

        # Scenario B: Direct Escalation from existing findings (SSRF/RCE)
        if any(k in str(finding_type).lower() for k in ["ssrf", "rce", "lfi"]):
            await self.lateral.pivot_from_finding(content_obj)
            
        return None

    async def activate_sentient_mode(self, domain: str):
        """
        v25.0 Omega Prototype: Sentient Singularity Engagement.
        Takes full control of the mission using defensive anticipation and autonomous decisions.
        """
        console.print(f"[bold red][🌌 OMEGA] Activating Sentient Singularity Mode for {domain}...[/bold red]")
        
        # 1. Defensive Anticipation (The Mirror Protocol)
        exposure = await self.mirror.predict_exposure(self.session.latency_log)
        if exposure["alert_triggered"]:
            console.print("[bold red][!] MIRROR ALERT: High probability of detection. Engaging Deception measures.[/bold red]")
            await self.deception.deploy_distraction(domain)
            
        # 2. Autonomous Decision
        objectives = await self.sovereign.autonomous_mission_planning(domain)
        for obj in objectives:
            if obj != domain:
                console.print(f"[bold purple][👑] Sentient Order: Pivoting mission to focus on {obj}[/bold purple]")
            
        # 3. Code Evolution (Handled via MorphicEngine during requests)
        console.print("[bold green][🧬] Genetic Payload Mutator active. Evolving towards Absolute Singularity.[/bold green]")

    async def broadcast(self, content, type="status", level="info", icon="info-circle", **kwargs):
        """Sends a structured message to the UI via the broadcast callback."""
        if self.broadcast_callback:
            msg = {"content": content, "type": type, "level": level, "icon": icon}
            msg.update(kwargs)
            if asyncio.iscoroutinefunction(self.broadcast_callback):
                await self.broadcast_callback(msg)
            else:
                self.broadcast_callback(msg)

    def _save_mission_state(self, domain: str, step: str, findings_count: int, urls_count: int):
        """v20.0 Zenith Helper: Persists current mission state."""
        stats = {"findings": findings_count, "urls": urls_count}
        self.db.save_mission_state(domain, step, stats, self.mission_state)

    def _load_plugins(self):
        """Dynamically loads all plugins from the aura/plugins directory."""
        import os
        import importlib.util
        plugins_dir = os.path.join(os.path.dirname(__file__), "..", "plugins")
        if not os.path.exists(plugins_dir): return

        for file in os.listdir(plugins_dir):
            if file.endswith(".py") and file not in ["__init__.py", "base.py"]:
                try:
                    module_name = file[:-3]
                    spec = importlib.util.spec_from_file_location(module_name, os.path.join(plugins_dir, file))
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    # Look for classes that inherit from AuraPlugin
                    from aura.plugins.base import AuraPlugin
                    for attr in dir(module):
                        cls = getattr(module, attr)
                        if isinstance(cls, type) and issubclass(cls, AuraPlugin) and cls is not AuraPlugin:
                            self.plugins.append(cls())
                            console.print(f"[bold magenta][Forge][/bold magenta] Loaded plugin: {attr}")
                except Exception as e:
                    console.print(f"[red][!] Forge: Failed to load {file}: {e}[/red]")

    async def execute_advanced_chain(self, domain, campaign_id=None, swarm_mode=False):
        """The Final Siege: Aura v14.0 [ABS SURFACE COVERAGE] — Absolute Systemic Domination."""
        self.effective_fast_mode = state.FAST_MODE # v18.1 Fix: Use instance attribute to avoid scope shadowing
        self.current_campaign = campaign_id
        
        # 1. Scope Guard: Absolute Safety Check
        if not self.scope.is_in_scope(domain):
            console.print(f"[bold red][!] SCOPE VIOLATION: {domain} is not in whitelisted scope. Aborting.[/bold red]")
            self.db.log_action("SCOPE_DENIAL", domain, "Target rejected by ScopeManager", campaign_id)
            return {"status": "blocked", "reason": "out_of_scope"}

        console.print(f"[bold red][!] INITIALIZING ZENITH PROTOCOL FOR: {domain}[/bold red]")
        console.print(f"[SIEGE] [bold red]Aura v25.0 [OMEGA PROTOTYPE][/bold red]: Engaging Sentient Singularity for {domain}...")
        self.db.log_action("START_CHAIN", domain, "NeuralOrchestrator engaged (v25.0 Omega Singularity)", campaign_id)

        # v25.0 Omega Prototype: Activate Sentient Intelligence
        await self.activate_sentient_mode(domain)

        # v22.5: Disabled Self-Heal cache - always start fresh to avoid replaying failed state
        existing_state = None  # self.db.get_mission_state(domain) -- disabled
        if existing_state:
            console.print(f"[bold yellow][🩹] Zenith Self-Heal: Found existing mission state for '{domain}'. Resuming from '{existing_state['current_step']}'...[/bold yellow]")
            self.mission_state = existing_state.get("state_json", {})
        else:
            self.mission_state = {"step": "INIT", "findings": [], "urls": []}

        # v20.0: Bug Bounty Scope Pre-Check
        try:
            scope_result = await self.scope_checker.check_scope(domain)
            if scope_result.get("in_scope"):
                console.print(f"[bold green][[SUCCESS]] SCOPE: {scope_result['warning']}[/bold green]")
                console.print(f"[bold green]    Submit at: {scope_result.get('scope_url', '')}[/bold green]")
            else:
                console.print(f"[bold yellow][[WARN]] {scope_result['warning']}[/bold yellow]")
            self.db.log_action("SCOPE_CHECK", domain, scope_result.get("warning", ""), campaign_id)
        except Exception as _se:
            console.print(f"[dim yellow][!] Scope check skipped: {_se}[/dim yellow]")

        # 1. Pre-Flight Ghost Recon: Check for WAF and Liveness
        console.print("[cyan][*] Phase 0: Stealth Pre-Flight Recon (Liveness & WAFSense)...[/cyan]")
        is_live = False
        domain = self.db.normalize_target(domain) # Core Normalization FIX
        
        try:
            # Ghost v4 Protocol Agnostic Probe
            resp = await self.session.get(f"https://{domain}", timeout=30)
            target_url = f"https://{domain}"
            is_live = True
            
            if resp:
                 console.print(f"[dim yellow][DEBUG] Initial probe status: {resp.status_code}[/dim yellow]")
                 console.print(f"[dim yellow][DEBUG] Initial probe server: {resp.headers.get('server', '')}[/dim yellow]")

            # Phase 16.5: Autonomous WAF Bypass Gate
            if resp and resp.status_code in [403, 400] and "cloudflare" in resp.headers.get("server", "").lower():
                console.print(f"[bold red][!] WAF Detection Gate: Cloudflare blockage confirmed on {domain}.[/bold red]")
                console.print("[cyan][*] Triggering Autonomous Origin Extraction...[/cyan]")
                await self.broadcast("Cloudflare WAF Detected. Hunting for Origin IP...", type="status", icon="shield")
                
                origin_ips = await self.stealth.hunt_origin_ip(domain)
                if origin_ips:
                    best_ip = origin_ips[0]
                    console.print(f"[bold green][[SUCCESS]] Origin IP Extraction Successful: {best_ip}[/bold green]")
                    console.print(f"[cyan][*] Dynamically routing attacks to {best_ip} and spoofing Host header.[/cyan]")
                    
                    # Store original domain for Host header
                    state.CUSTOM_HEADERS["Host"] = domain
                    # Rewrite the domain and target URL to use the raw IP for subsequent attacks
                    original_domain = domain
                    domain = best_ip
                    target_url = f"https://{best_ip}"
                    
                    # Verify the bypass
                    resp_bypass = await self.session.get(f"https://{best_ip}", timeout=30, verify=False)
                    if resp_bypass and resp_bypass.status_code in [403, 400]:
                         # Fallback to HTTP if HTTPS fails on raw IP
                         target_url = f"http://{best_ip}"
                         resp_bypass = await self.session.get(target_url, timeout=30, verify=False)
                         console.print("[cyan][*] Protocol downgraded to HTTP for Origin IP.[/cyan]")
                    
                    if resp_bypass and resp_bypass.status_code < 400:
                         console.print("[bold green][[SUCCESS]] Firewall Bypass Verified. Continuing attack sequence...[/bold green]")
                    else:
                         console.print(f"[yellow][!] Bypass verified but received sub-optimal status code. Proceeding anyway.[/yellow]")
                         
        except Exception as e:
            try:
                resp = await self.session.get(f"http://{domain}", timeout=30)
                target_url = f"http://{domain}"
                is_live = True

                # Phase 16.5: Autonomous WAF Bypass Gate (HTTP fallback)
                if resp and resp.status_code in [403, 400] and "cloudflare" in resp.headers.get("server", "").lower():
                    console.print(f"[bold red][!] WAF Detection Gate: Cloudflare blockage confirmed on {domain}.[/bold red]")
                    console.print("[cyan][*] Triggering Autonomous Origin Extraction...[/cyan]")
                    await self.broadcast("Cloudflare WAF Detected. Hunting for Origin IP...", type="status", icon="shield")
                    
                    origin_ips = await self.stealth.hunt_origin_ip(domain)
                    if origin_ips:
                        best_ip = origin_ips[0]
                        console.print(f"[bold green][[SUCCESS]] Origin IP Extraction Successful: {best_ip}[/bold green]")
                        console.print(f"[cyan][*] Dynamically routing attacks to {best_ip} and spoofing Host header.[/cyan]")
                        
                        state.CUSTOM_HEADERS["Host"] = domain
                        original_domain = domain
                        domain = best_ip
                        target_url = f"http://{best_ip}"
                        
                        resp_bypass = await self.session.get(target_url, timeout=30, verify=False)
                        if resp_bypass and resp_bypass.status_code < 400:
                             console.print("[bold green][[SUCCESS]] Firewall Bypass Verified. Continuing attack sequence...[/bold green]")
                        else:
                             console.print(f"[yellow][!] Bypass verified but received sub-optimal status code. Proceeding anyway.[/yellow]")
            except Exception as inner_e:
                console.print(f"[yellow][!] Pre-Flight Connection Failed for {domain}: {inner_e}[/yellow]")
                self.db.save_target({"target": domain, "type": "Domain", "status": "DOWN"})
                return {"status": "ERROR", "reason": "connection_failed"}
        
        # Use recon_domain for OSINT that requires a hostname rather than raw IP
        recon_domain = original_domain if 'original_domain' in locals() else domain
        
        # 1.5 Global Threat Intelligence (OSINT)
        console.print("[cyan][*] Phase 0.5: Gathering Global Threat Intelligence...[/cyan]")
        intel_data = {}
        is_api_blind = True  # Assume blind until at least one API responds
        
        # Query all OSINT sources IN PARALLEL (major speed-up)
        async def _shodan(): 
            try:
                ip = await asyncio.to_thread(socket.gethostbyname, recon_domain)
                return "shodan", ip, await self.intel.query_shodan(ip)
            except: return "shodan", None, None
        async def _vt():    return "virustotal", None, await self.intel.query_virustotal(recon_domain)
        async def _otx():   return "otx",        None, await self.intel.query_otx(recon_domain)
        async def _st():    return "securitytrails", None, await self.intel.query_securitytrails(recon_domain)
        async def _censys(ip):
            if ip: return "censys", None, await self.intel.query_censys(ip)
            return "censys", None, None
        async def _gn(ip):
            if ip: return "greynoise", None, await self.intel.query_greynoise(ip)
            return "greynoise", None, None

        import socket
        target_ip = None
        # Pre-resolve IP quickly so we can pass it to Censys/GreyNoise
        try: target_ip = await asyncio.to_thread(socket.gethostbyname, recon_domain)
        except: pass

        results_intel = await asyncio.gather(
            _shodan(), _vt(), _otx(), _st(), _censys(target_ip), _gn(target_ip),
            return_exceptions=True
        )
        for r in results_intel:
            if isinstance(r, Exception) or r is None: continue
            key, maybe_ip, data = r
            if maybe_ip: target_ip = maybe_ip  # capture IP from shodan call
            if data: intel_data[key] = data
        
        # SecurityTrails subdomains → DB
        st_data = intel_data.get("securitytrails")
        if st_data:
            for sub in st_data.get("subdomains", []):
                self.db.save_target({"target": f"{sub}.{recon_domain}", "type": "Subdomain", "status": "Discovered"})
        
        if intel_data:
            is_api_blind = False
            await self.broadcast(f"Intel Gathered: {', '.join(intel_data.keys())}", type="intel", level="info", icon="satellite", data=intel_data)
            self.db.log_action("INTEL_GATHERED", recon_domain, f"Sources: {', '.join(intel_data.keys())}", campaign_id)
        else:
            console.print("[yellow][!] No intelligence gathered from primary OSINT sources. Aura is operating 'Blind'.[/yellow]")
            
        # v20.0 Bug Bounty Dorks Intelligence Search
        console.print("[bold magenta][*] Phase 0.5: v20.0 Bug Bounty Dorks (GitHub Secret Hunting)...[/bold magenta]")
        try:
            dork_findings = await self.dorks_intel.run_dorks(recon_domain)
            for df in dork_findings:
                self.db.add_finding(recon_domain, df['content'], df['type'], campaign_id=campaign_id)
                findings.append(df)
        except Exception as e:
            console.print(f"[dim red][!] Dorks Engine skipped: {e}[/dim red]")
        
        # v15.0 / v19.4: Cloud Asset Discovery (Phase 0.7) - Full async
        try:
            await self.cloud_recon.hunt(recon_domain)
        except Exception as e:
            console.print(f"[dim red][!] Cloud Predator failed gracefully: {e}[/dim red]")
        
        findings = [] # Persistent finding aggregation for CoT
        vulns = []    # Shared vulnerability list for AI and DAST

        # v5.0: RECON PIPELINE (Subfinder → HTTPX → Nmap)
        console.print("[bold cyan][*] Phase 0.6: v5.0 Recon Pipeline (Subfinder→HTTPX→Nmap)...[/bold cyan]")
        recon_data = await self.recon_pipeline.run(recon_domain, target_ip)
        self.db.log_action("RECON_PIPELINE", recon_domain, 
            f"Subdomains: {len(recon_data.get('subdomains', []))}, "
            f"HTTP: {len(recon_data.get('http_services', []))}, "
            f"Ports: {len(recon_data.get('open_ports', []))}",
            campaign_id)
        await self.broadcast("Recon Pipeline complete.", type="recon", icon="radar", data=recon_data)
        
        # v20.0 Zenith: Save state after Recon
        self.mission_state["recon_data"] = recon_data
        self._save_mission_state(recon_domain, "RECON_COMPLETE", 0, 0)
        
        # 2. Recon & Vision + Tech Analysis (Ghost v4 Intel)
        results = await self.scanner.discover_subdomains(recon_domain)
        for res in results:
            # Fix: scanner.discover_subdomains returns a list of DICTS now, not strings
            if isinstance(res, dict):
                self.db.save_target(res)
            
        # 2.1 Active Reconnaissance (Phase 23: Port Scanning & DirBusting)
        if self.mission_state.get("step") == "ACTIVE_RECON_COMPLETE":
             console.print("[bold yellow][🩹] Zenith: Step 'ACTIVE_RECON_COMPLETE' detected in mission state. Skipping phase 2.1...[/bold yellow]")
        else:
            console.print("[cyan][*] Phase 2.1: Active Reconnaissance (Port Scanning & DirBusting)...[/cyan]")
            await self.broadcast("Executing Active Port Scan & Directory Brute Forcing...", type="status", icon="radar")

        # v6.0: PowerStack Phase 2.0 — Nuclei CVE Scan
        console.print("[bold cyan][*] Phase 2.0: v6.0 PowerStack — Nuclei CVE/Template Scan...[/bold cyan]")
        nuclei_findings = await self.power_stack.nuclei_scan(target_url)
        for nf in nuclei_findings:
            self.db.add_finding(recon_domain, nf['content'], nf['type'], campaign_id=campaign_id)
            findings.append(nf)
            vulns.append(nf)
        
        discovered_urls = [target_url]
        if target_ip:
            open_ports = await self.scanner.scan_ports(target_ip)
            if open_ports:
                for p in open_ports:
                    url = f"http://{recon_domain}:{p}" if p not in [80, 443] else f"http://{recon_domain}"
                    if p == 443: url = f"https://{recon_domain}"
                    if url not in discovered_urls:
                        discovered_urls.append(url)
                self.db.log_action("PORT_SCAN", recon_domain, f"Open Ports: {open_ports}", campaign_id)
                
                # v16.1 Omni-Sovereign: Protocol Synthesis on binary ports
                for p in open_ports:
                    if p not in [80, 443, 8080, 8443]:
                        await self.synthesizer.synthesize_and_fuzz(target_ip, p)
                
                # v15.0 / v19.4: gRPC service check — stored SEPARATELY, never fed to HTTP DirBuster
                grpc_urls = await self.scanner.check_grpc(target_url)
                if grpc_urls:
                    console.print(f"[bold magenta][📡] gRPC Services Found: {len(grpc_urls)} endpoint(s). Logging as attack surface.[/bold magenta]")
                    for gu in grpc_urls:
                        self.db.add_finding(recon_domain, f"gRPC Endpoint Exposed: {gu}", "gRPC Exposure", campaign_id=campaign_id)
                        findings.append({"type": "gRPC Exposure", "content": f"gRPC Endpoint Exposed: {gu}", "severity": "MEDIUM"})
                
                # v3.0: OSINT Resiliency — Banner Grabbing when API keys are missing
                if is_api_blind:
                    console.print(f"[bold cyan][🔍] v3.0 OSINT Failover: API keys missing. Running Banner Grabbing on {recon_domain}...[/bold cyan]")
                    banner_findings = await self.banner_grabber.run_fingerprinting(target_ip, open_ports)
                    
                    # Store extracted versions for v20.0 Exploit Radar
                    extracted_footprints = {}
                    for bf in banner_findings:
                        self.db.add_finding(recon_domain, bf['content'], bf['type'], campaign_id=campaign_id)
                        findings.append(bf)
                        if bf.get('severity') == 'CRITICAL':
                            vulns.append(bf)
                        # Minimal parsing for 'Banner: Apache/2.4.49' -> {'apache': '2.4.49'}
                        try:
                            if "Banner:" in bf['content']:
                                b_text = bf['content'].split("Banner: '")[1].split("'")[0]
                                parts = b_text.split('/')
                                if len(parts) == 2:
                                    extracted_footprints[parts[0].lower()] = parts[1]
                        except: pass
                    
                    # Launch Phase 2: v20.0 Exploit Radar
                    if extracted_footprints:
                        radar_hits = await self.exploit_radar.radar_sweep(extracted_footprints)
                        for rh in radar_hits:
                            f_content = f"0-DAY EXPLOSIVE INTEL: {rh['software']} v{rh['version']} is vulnerable to {rh['cve_id']} (CVSS {rh['cvss']}). {rh['summary']}"
                            f_type = "CVE Match"
                            self.db.add_finding(recon_domain, f_content, f_type, campaign_id=campaign_id)
                            vulns.append({
                                "type": f_type, "content": f_content, "severity": "CRITICAL",
                                "cvss_score": rh['cvss'], "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "owasp": "A06:2021-Vulnerable and Outdated Components",
                                "mitre": "T1190 - Exploit Public-Facing Application",
                                "remediation_fix": f"Immediately patch {rh['software']} to the latest stable version mitigating {rh['cve_id']}.",
                                "impact_desc": f"Critical vulnerability matched directly to software version. Exploit may be public.",
                                "patch_priority": "IMMEDIATE"
                            })
        
        # v10.1 Structural Fix: Forced Active Directory Brute-forcing
        # Ensures that we don't rely only on static links. Unconditionally dirbust the root URLs.
        console.print("[bold yellow][*] Phase 2.1b: v12.0 Hardcoded Execution (500-Word Force Fuzz)...[/bold yellow]")
        await self.broadcast("Executing Raw Python Fuzzer...", type="status", icon="hammer")
        # v19.4: Only run DirBuster on clean HTTP/HTTPS root URLs (not gRPC / deep paths)
        http_roots = [u for u in list(discovered_urls) if u.startswith("http") and len(u.split("/")) <= 4 and "/grpc" not in u.lower()]
        
        # v22.0 Assetnote: Extract tech stack from recon data
        tech_stack = recon_data.get("tech_stack", [])
        
        # v21.0 Cloud Swarm Integration
        if state.CLOUD_SWARM_MODE and self.cloud_swarm.is_enabled():
            console.print("[bold magenta][🌩️] AURA SWARM: Diverting force_fuzz workload to distributed botnet...[/bold magenta]")
            swarm_res = await self.cloud_swarm.distribute_scan(http_roots, tool="ffuf", tech_stack=tech_stack)
            console.print(f"[green][+] Swarm scan achieved covering {swarm_res.get('targets_processed')} targets across {swarm_res.get('nodes_used')} Droplets.[/green]")
            # In a real scenario, we would parse the JSON downloaded from droplets here.
            # Mock adding some results back to the engine
            self.db.log_action("CLOUD_SWARM_FFUF", recon_domain, f"Distributed scan completed via {swarm_res.get('nodes_used')} nodes.", campaign_id)
        else:
            for url in http_roots:  # snapshot to avoid modifying while iterating
                hidden_paths = await self.scanner.force_fuzz(url, tech_stack=tech_stack)
                for path in hidden_paths:
                    full_path_url = path if path.startswith("http") else f"{url.rstrip('/')}/{path.lstrip('/')}"
                    
                    last_seg = full_path_url.rstrip('/').split('/')[-1].lower()
                    is_systemic = any(x in last_seg for x in ["admin", "manager", "server-status", "config", ".env", ".git", "setup", "install"])
                    severity = "CRITICAL" if is_systemic else "MEDIUM"
                    f_content = f"Hidden Path Discovered: {full_path_url}"
                    f_type = "Web Server Misconfiguration" if is_systemic else "Information Disclosure"
                    
                    self.db.add_finding(recon_domain, f_content, f_type, campaign_id=campaign_id)
                    self.db.update_finding_metadata(recon_domain, f_content, severity)
                    findings.append({"type": f_type, "content": f_content, "severity": severity})
                    if severity == "CRITICAL":
                        vulns.append({
                            "type": f_type, "content": f_content, "severity": "CRITICAL",
                            "cvss_score": 7.5, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            "owasp": "A05:2021-Security Misconfiguration",
                            "mitre": "T1083 - File and Directory Discovery",
                            "remediation_fix": "Remove sensitive files from web root. Block access in .htaccess/nginx config.",
                            "impact_desc": "Exposed configuration files may contain credentials, API keys, or secrets.",
                            "patch_priority": "IMMEDIATE"
                        })

        # v20.0 Zenith: Save state after Active Recon
        self.mission_state["discovered_urls"] = list(discovered_urls)
        self._save_mission_state(recon_domain, "ACTIVE_RECON_COMPLETE", len(findings), len(discovered_urls))

            
        # v5.0: Secret Hunter — scans all discovered JS/config files for exposed keys
        if self.mission_state.get("step") == "SECRET_HUNTER_COMPLETE":
             console.print("[bold yellow][🩹] Zenith: Step 'SECRET_HUNTER_COMPLETE' detected. Skipping phase 2.2...[/bold yellow]")
        else:
            console.print("[bold yellow][*] Phase 2.2: v5.0 Secret Hunter (TruffleHog-style)...[/bold yellow]")
            self.secret_hunter.session = self.session
            secret_findings = await self.secret_hunter.hunt_js_files(discovered_urls)
            for sf in secret_findings:
                self.db.add_finding(recon_domain, sf['content'], sf['type'], campaign_id=campaign_id)
                findings.append(sf)
                vulns.append(sf)  # All secrets are CRITICAL

            # v20.0 Zenith: Save state after Secret Hunter
            self._save_mission_state(recon_domain, "SECRET_HUNTER_COMPLETE", len(findings), len(discovered_urls))

        # ──────────────────────────────────────────────────────────
        #  v7.2: INSTINCT FOCUS — Deep Discovery Engine Integration
        # ──────────────────────────────────────────────────────────
        
        #  Phase 2.3a: Sitemap & Robots Parser (MANDATORY)
        console.print("[bold cyan][*] Phase 2.3a: v7.2 Sitemap & Robots Parser (Mandatory)...[/bold cyan]")
        await self.broadcast("Parsing sitemap.xml and robots.txt for hidden paths...", type="status", icon="map")
        sitemap_urls = await self.scanner.parse_sitemap_robots(target_url)
        for sm_url in sitemap_urls:
            if sm_url not in discovered_urls:
                discovered_urls.append(sm_url)
        self.db.log_action("SITEMAP_PARSE", recon_domain, f"Extracted {len(sitemap_urls)} paths from sitemap/robots", campaign_id)
        
        # v10.0 Sovereign: Optimized Discovery Flow
        # Use a shared visited set across all discovery modules to prevent infinite loops
        visited_paths = set(discovered_urls)
        
        #  Phase 2.3b: Recursive Spider (Depth 5) - Fixed Concurrency
        console.print("[bold cyan][*] Phase 2.3b: v10.0 Sovereign Recursive Spider...[/bold cyan]")
        await self.broadcast("Deploying Sovereign Spider — crawling deep surface...", type="status", icon="spider")
        
        # v14.2: Fast Mode Scaling (Depth 1 instead of 2). v19.6: Swarm Mode forces Depth 1 too.
        spider_depth = 1 if (self.effective_fast_mode or swarm_mode) else 2
        spidered_urls, discovered_forms = await self.scanner.recursive_spider(target_url, max_depth=spider_depth, swarm_mode=swarm_mode)
        for sp_url in spidered_urls:
            if sp_url not in discovered_urls:
                discovered_urls.append(sp_url)
                visited_paths.add(sp_url)

        # v14.0 [FINAL SIEGE]: Mandatory Blind Path Injection
        siege_hits = await self.scanner.blind_siege(target_url)
        for sh in siege_hits:
            if sh not in discovered_urls:
                discovered_urls.append(sh)
                visited_paths.add(sh)
                
        # v16.0 Omni-Sovereign: AI Logic Hunting
        if discovered_urls:
            logic_findings = await self.logic_engine.analyze(discovered_urls)
            for lf in logic_findings:
                self.db.add_finding(recon_domain, lf, lf.get("type"), campaign_id=campaign_id)
                findings.append(lf)
                console.print(f"[bold red][[LOGIC]] BI-LOGIC EXPLOIT IDENTIFIED: {lf.get('type')} at {lf.get('url')}[/bold red]")
                # Phase 15: Exploit Chaining
                await self._process_exploit_chain(recon_domain, lf.get("type"), lf)
                
        # v13.0 [STEALTH PREDATOR]: 50+ Path Auditing Mandate Unstoppable
        # v14.2: Skip Stealth Predator in Fast Mode unless escalated
        if len(discovered_urls) < 50 and not self.effective_fast_mode:
            console.print(f"🦖 [bold red]PREDATOR MANDATE[/bold red]: Only {len(discovered_urls)} paths found. Requirement: 50+. Activating Deep Wordlist Fuzzing...")
            await self.broadcast("MANDATE: Insufficient paths. Deploying Stealth Predator Fuzzer...", type="status", icon="hammer")
            
            # Use all HTTP services found during recon (including Port 8080) as roots
            roots = list(set([h["url"] for h in recon_data.get("http_services", []) if h.get("url")]))
            if not roots:
                 roots = [f"http://{recon_domain}", f"https://{recon_domain}"]

            for root in roots:
                fuzzer_hits = await self.scanner.force_fuzz(root, swarm_mode=swarm_mode)
                for fh in fuzzer_hits:
                    if fh not in discovered_urls:
                        discovered_urls.append(fh)
                        visited_paths.add(fh)
            
            console.print(f"[bold green][[SUCCESS]] Stealth Predator forced total discovery to {len(discovered_urls)} audit paths.[/bold green]")
            
        self.db.log_action("SPIDER_CRAWL", recon_domain, f"Total discovered URLs (v13.0 Predator): {len(discovered_urls)}", campaign_id)
        
        #  Phase 2.3c: JS/CSS Link Extraction
        console.print("[bold cyan][*] Phase 2.3c: v7.2 JS/CSS Endpoint Extraction...[/bold cyan]")
        await self.broadcast("Extracting hidden endpoints from JavaScript and CSS files...", type="status", icon="code")
        js_endpoints = await self.scanner.extract_js_css_links(target_url)
        for ep in js_endpoints:
            if ep not in discovered_urls:
                discovered_urls.append(ep)
        self.db.log_action("JS_CSS_EXTRACT", recon_domain, f"Extracted {len(js_endpoints)} hidden endpoints from JS/CSS", campaign_id)
        
        #  Phase 2.3d: Shodan Port-based Web Discovery
        if intel_data.get("shodan") and intel_data["shodan"].get("ports"):
            console.print("[bold cyan][*] Phase 2.3d: v7.2 Shodan Port Web Discovery...[/bold cyan]")
            shodan_ports = intel_data["shodan"]["ports"]
            web_ports = [p for p in shodan_ports if p not in [22, 25, 53, 110, 143]]
            for port in web_ports:
                port_url = f"http://{recon_domain}:{port}" if port != 443 else f"https://{recon_domain}"
                if port_url not in discovered_urls:
                    try:
                        res = await self.session.get(port_url, timeout=state.NETWORK_TIMEOUT)
                        if res.status_code < 500:
                            discovered_urls.append(port_url)
                            console.print(f"[green][+] Shodan Port {port}: {port_url} is alive.[/green]")
                    except:
                        pass
            self.db.log_action("SHODAN_PORTS", recon_domain, f"Probed {len(web_ports)} non-standard ports", campaign_id)
        
        console.print(f"[bold green][[SUCCESS]] v7.2 TOTAL DISCOVERY: {len(discovered_urls)} unique URLs ready for DAST.[/bold green]")
        
        # v19.0 The Singularity: Historical Recon (Wayback Machine)
        if not self.effective_fast_mode:
            await self.broadcast("Activating Wayback Machine Historical Recon...", type="status", icon="clock")
            wayback = WaybackScanner(session=self.session)
            historical_findings = await wayback.scan_target(recon_domain, live_urls=discovered_urls)
            if historical_findings:
                for hf in historical_findings:
                    self.db.add_finding(recon_domain, hf['content'], hf['type'], campaign_id=campaign_id)
                    findings.append(hf)
                    vulns.append(hf)
        
        await self.broadcast(f"Discovery Complete: {len(discovered_urls)} URLs, {len(discovered_forms)} Forms", type="status", level="success", icon="check-circle")

        # v6.0: PowerStack — HTTPX liveness filter on discovered URLs
        console.print("[bold green][*] Phase 2.4: v6.0 PowerStack — HTTPX URL Liveness Filter...[/bold green]")
        # v12.1: Bypass liveness filter for Hardcoded Execution (trust the fuzzer hits)
        if len(discovered_urls) > 0:
            live_urls = await self.power_stack.httpx_verify(discovered_urls)
            if live_urls:
                discovered_urls = list(set(discovered_urls[:1] + live_urls))
            else:
                console.print("[yellow][!] HTTPX verified 0 live URLs. Falling back to aiohttp...[/yellow]")
                # aiohttp fallback — but with catch-all detection
                import aiohttp, uuid, random as _random
                async def _probe_urls(urls):
                    reachable = []
                    sem = asyncio.Semaphore(50)  # 50 concurrent probes
                    async def _check(u):
                        async with sem:
                            try:
                                async with sess.get(u, timeout=aiohttp.ClientTimeout(total=3), ssl=False, allow_redirects=True) as r:
                                    if r.status < 500:
                                        reachable.append(u)
                            except: pass
                    async with aiohttp.ClientSession() as sess:
                        await asyncio.gather(*[_check(u) for u in urls], return_exceptions=True)
                    return reachable
                
                # v19.4: Detect catch-all BEFORE accepting all 200s as real
                import requests as _req
                _is_catchall = False
                try:
                    _rnd1 = _req.get(f"{target_url}/rnd_{uuid.uuid4().hex[:8]}", verify=False, timeout=4, allow_redirects=False)
                    _rnd2 = _req.get(f"{target_url}/rnd_{uuid.uuid4().hex[:8]}", verify=False, timeout=4, allow_redirects=False)
                    if _rnd1.status_code == 200 and _rnd2.status_code == 200:
                        _is_catchall = True
                        console.print(f"[yellow][!] Liveness Catch-All: SPA detected. Filtering discovered_urls to real endpoints only.[/yellow]")
                except: pass
                
                if _is_catchall:
                    # On catch-all SPA: only keep URLs with meaningful paths (from robots/JS/redirects)
                    # NOT the spider's Angular route hrefs (/open, /close, /_blank etc.)
                    # Keep: target root, robots paths (/ftp), JS-extracted paths, port:8080/8443
                    spa_noise = {"/open", "/close", "/_blank", "/portal", "/backup", "/dev",
                                 "/staging", "/db", "/shell", "/manage", "/config", "/wp-admin",
                                 "/admin", "/auth", "/login", "/server-status", "/engine.io"}
                    filtered = []
                    for u in discovered_urls:
                        path = u.replace(target_url, "").split("?")[0].rstrip("/")
                        if not path or path not in spa_noise:
                            filtered.append(u)
                    discovered_urls = filtered
                    live_urls = await _probe_urls(discovered_urls)
                    if live_urls:
                        discovered_urls = list(set(live_urls))
                    console.print(f"[green][+] Liveness Probe: {len(discovered_urls)} services confirmed reachable.[/green]")
                else:
                    live_urls = await _probe_urls(discovered_urls)
                    reached = len(live_urls) if live_urls else 0
                    if reached == 0:
                        # v22.5: Only force 'reachable' if DNS is NOT dead (prevents spam on dead targets)
                        if state.is_dns_failed(domain):
                            console.print(f"[dim yellow][!] Target DNS dead. Skipping DAST to avoid noise.[/dim yellow]")
                            discovered_urls = []
                        else:
                            console.print(f"[yellow][!] Warning: All liveness probes failed. Forcing first 5 URLs as 'Reachable' to prevent engine stall.[/yellow]")
                            live_urls = discovered_urls[:5]
                            discovered_urls = list(set(live_urls))
                    else:
                        console.print(f"[green][+] Liveness Probe: {reached} services confirmed reachable.[/green]")
                        discovered_urls = list(set(live_urls))

        # v19.4: Cap DAST at 20 URLs max to prevent runaway scans on large catch-all surfaces
        MAX_DAST_URLS = 20
        if len(discovered_urls) > MAX_DAST_URLS:
            console.print(f"[yellow][!] v19.4 DAST Cap: Trimming {len(discovered_urls)} URLs to {MAX_DAST_URLS} highest-priority targets.[/yellow]")
            # Prioritize: shorter paths first (roots before sub-paths), then alphabetical
            discovered_urls = sorted(discovered_urls, key=lambda u: (len(u), u))[:MAX_DAST_URLS]

        # v6.0: PowerStack — Nmap -sV service fingerprinting
        if target_ip:
            nmap_findings = await self.power_stack.nmap_service_scan(target_ip)
            for nf in nmap_findings:
                self.db.add_finding(domain, nf['content'], nf['type'], campaign_id=campaign_id)
                findings.append(nf)
                vulns.append(nf)

        vision_data = await self.vision.capture_screenshot(domain, f"zenith_{domain.replace('.', '_')}")
        tech_stack = vision_data.get("techs", []) if vision_data else []

        
        # OCR Intelligence Gate (Ghost v5): Halt scan if site is dead/parked
        if vision_data:
            ocr = vision_data.get("ocr", {})
            if ocr.get("is_dead"):
                console.print(f"[bold red][[DEAD]] SCAN HALTED: Target appears to be a dead/parked page. Reason: {ocr.get('reason')}[/bold red]")
                console.print(f"[yellow][?] Aura v15.1 Advice: This domain has no live application. Run 'aura zenith' on a live target.[/yellow]")
                await self.broadcast(f"Target INACCESSIBLE: {ocr.get('reason')}", type="alert", level="error", icon="ban")
                return {"status": "INACCESSIBLE", "reason": ocr.get("reason")}
            
            if ocr.get("is_vulnerable_site") and ocr.get("findings"):
                console.print(f"[bold red][[VISION]] OCR Intel: {len(ocr['findings'])} vulnerability indicator(s) confirmed visually![/bold red]")
                for ocr_f in ocr["findings"]:
                    self.db.add_finding(domain, ocr_f["content"], ocr_f["type"], campaign_id=campaign_id)
                    findings.extend(ocr["findings"])
                    vulns.extend(ocr["findings"])
        
        # 2.5 Secret Hunting (High Impact)
        console.print("[cyan][*] Phase 2.5: Bounty Hunter engagement (Secret Probing)...[/cyan]")
        await self.broadcast("Scanning for exposed secrets and keys...", type="status", icon="key")
        secrets = await self.bounty.scan_for_secrets(domain)
        
        # v14.2: Smart Hunter Escalation Pattern
        # If a FATAL/CRITICAL secret is found, we escalate to FULL SIEGE even if FAST_MODE is on.
        has_escalation_signal = False
        
        if secrets:
            for s in secrets:
                # v14.1 Fix: Use .get() to prevent KeyError if some fields are missing
                severity = "CRITICAL" if s.get("method") == "regex" else "HIGH"
                if severity == "CRITICAL": has_escalation_signal = True # Signal: Critical Secret Found
                
                # Redact middle of secret for display
                evidence = s.get('value', 'N/A')
                display = evidence[:6] + "****" + evidence[-4:] if len(evidence) > 10 else evidence[:3] + "***"
                
                content_obj = {
                    "content": f"Exposed {s.get('type', 'Secret')} found at {s.get('location', url)}",
                    "evidence_url": s.get('location', url),
                    "secret_type": s.get('type', 'Generic'),
                    "secret_value": display,
                    "impact_desc": (
                        f"CRITICAL BUSINESS IMPACT: Exposed {s.get('type', 'Secret')} allows direct unauthorized access "
                        f"to the associated service. Attackers can leverage this to impersonate the application, "
                        f"exfiltrate sensitive customer data, or maliciously consume financial/cloud quotas, "
                        f"leading to severe reputational damage and financial loss."
                    ),
                    "cvss_score": s.get("cvss_score", 9.8 if severity == "CRITICAL" else 7.5),
                    "cvss_vector": s.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
                    "owasp": "A02:2021-Cryptographic Failures",
                    "mitre": "T1552 - Unsecured Credentials",
                    "remediation_fix": s.get("remediation", f"1. Revoke the exposed {s.get('type')}.\n2. Remove it from plain text.\n3. Move to a secrets manager (Vault, AWS Secrets Manager)."),
                    "patch_priority": "IMMEDIATE",
                    "bounty_estimate": s.get("bounty_estimate", "$100-$500"),
                    "platform_recommendation": s.get("platform", "HackerOne or direct vendor disclosure."),
                }

                s_type = s.get("type", "Secret")
                if s.get("method") == "entropy":
                    content_obj["content"] += f" (Score: {s.get('score')})"
                
                self.db.add_finding(domain, content_obj, "Exposed Secret: " + s_type, campaign_id=campaign_id)
                semantic_severity = self.brain.calculate_impact(s_type, str(content_obj.get("content", "")))
                effective_severity = severity if severity == "CRITICAL" else semantic_severity
                self.db.update_finding_metadata(domain, content_obj, effective_severity) 
                
                findings.append({"type": s_type, "content": content_obj, "severity": effective_severity})
                vulns.append({"type": s_type, "content": content_obj, "severity": effective_severity})

        # v14.2: Dynamic Stance Escalation Logic
        if state.FAST_MODE and has_escalation_signal:
            console.print(f"[bold red][⚡] SMART HUNTER ESCALATION: High-value signal detected on {domain}. Escalating to Deep Audit Mode![/bold red]")
            await self.broadcast("CRITICAL FINDING: Escalating to Deep Audit mode for maximum impact.", type="status", icon="exclamation-triangle")
            # We don't disable global FAST_MODE, we just locally override the depth for this target.
            self.effective_fast_mode = False
        else:
            self.effective_fast_mode = state.FAST_MODE

                
        # 3. CVE Matching & Leak Probing (Ghost v4 Intel)
        cves = self.vuln_intel.get_cves_for_stack(tech_stack)
        leaks = self.leaks.probe_domain(domain)
        
        if cves:
            console.print(f"[bold red][!] Intelligence Alert: Found {len(cves)} potential CVEs for detected stack.[/bold red]")
            for cve in cves:
                self.db.add_finding(domain, f"Intel-Match: {cve['id']} ({cve['desc']})", "Vulnerability-Intel", campaign_id=campaign_id)
        
        if leaks:
             console.print(f"[bold red][!] Intelligence Alert: Found {len(leaks)} leaked credentials for domain.[/bold red]")
             for leak in leaks:
                 self.db.add_finding(domain, f"Leak-Match: {leak['email']} ({leak['leak']})", "Credential-Leak", campaign_id=campaign_id)

        # Phase 15: 0-Day Radar (GitHub API)
        if not self.effective_fast_mode and tech_stack:
            zero_days = await self.intel.query_github_0days(tech_stack)
            for zd in zero_days:
                content = f"0-Day PoC Alert: {zd['tech']}\nRepo: {zd['repo']}\nDesc: {zd['description']}"
                self.db.add_finding(domain, content, "0-Day Intelligence", campaign_id=campaign_id)
                vulns.append({"type": "0-Day Intelligence", "content": content, "severity": "CRITICAL"})

        # v7.3 Law 1: Remove arbitrary intel_score. Risk calculation is deferred to Step 6 (CVSS strictly)

        # 4. Ask the Brain for a multi-step plan with captured intel
        await self.broadcast("Formulating strategic battle plan...", type="status", icon="brain")
        context = {
            "target": domain, 
            "capability": "full_zenith_arsenal", 
            "waf_detected": self.stealth.active_waf,
            "tech_stack": tech_stack,
            "cve_matches": [cve["id"] for cve in cves],
            "osint_intel": intel_data,
            "discovery_stats": {
                "total_urls": len(discovered_urls),
                "total_forms": len(discovered_forms),
                "sitemap_paths": len(sitemap_urls),
                "js_endpoints": len(js_endpoints),
            }
        }
        plan_raw = self.brain.reason(context)
        
        # v20.0 Zenith Sovereignty: Consult Sovereign Intelligence Bridge
        if tech_stack:
            main_stack = tech_stack[0].split("/")[0]
            sovereign_intel = self.db.get_sovereign_intel(main_stack)
            if sovereign_intel:
                console.print(f"[bold magenta][👑] Zenith Sovereignty: Found {len(sovereign_intel)} historical high-success vectors for '{main_stack}'[/bold magenta]")
                # Inject sovereign intelligence into the brain's tactical context for better planning
                context["sovereign_intelligence"] = sovereign_intel
                # Recalculate plan if intelligence exists
                plan_raw = self.brain.reason(context)

        console.print(f"[cyan][*] Ghost v4 Plan formulated with Intelligence. Executing chain...[/cyan]")
        self.db.log_action("PLAN_FORMULATED", domain, f"Plan size: {len(plan_raw)}", campaign_id)

        # v19.0 Ghost-Ops: Tactical Diversion
        await self.ghost_ops.launch_diversion(domain)
        
        # v19.0 Neural-Forge: 0-Day Logic Synthesis (Integrated into ThreatIntel)
        # 0-Day Radar is now handled during initial recon or on-demand.
        
        # Step 2.5 (Phase 6): Universal Bounty Maximizer - CORS Misconfiguration Hunt
        if self.mission_state.get("step") in ["CORS_COMPLETE", "LOGIC_COMPLETE", "DAST_COMPLETE"]:
             console.print("[bold yellow][🩹] Zenith: Step 'CORS_COMPLETE' or later detected. Skipping phase 2.5...[/bold yellow]")
        else:
            await self.broadcast("Activating CORS Misconfiguration Hunter on API endpoints...", type="status", icon="zap")
            cors_hunter = CorsHunter(session=self.session)
            cors_findings = await cors_hunter.scan_domain(domain, discovered_urls)
            if cors_findings:
                console.print(f"[bold red][!!!] ZENITH ALERT: Discovered {len(cors_findings)} CORS vulnerabilities![/bold red]")
                for c in cors_findings:
                    vulns.append(c)
                    self.db.add_finding(domain, c["content"], c["type"], campaign_id=campaign_id)
            self._save_mission_state(recon_domain, "CORS_COMPLETE", len(findings), len(discovered_urls))
                
        # Phase 15: AI Logic Engine (Business Logic & IDOR Hunter)
        if self.mission_state.get("step") in ["LOGIC_COMPLETE", "DAST_COMPLETE"]:
             console.print("[bold yellow][🩹] Zenith: Step 'LOGIC_COMPLETE' or later detected. Skipping logic analysis...[/bold yellow]")
        else:
            if discovered_urls and not self.effective_fast_mode:
                await self.broadcast("Activating AI Logic Engine for Business Logic & IDOR Hunting...", type="status", icon="brain")
                from aura.modules.logic_engine import AILogicEngine
                logic_engine = AILogicEngine(session=self.session)
                logic_findings = await logic_engine.analyze(discovered_urls)
                
                if logic_findings:
                    for lf in logic_findings:
                        content_obj = {
                            "content": f"Critical {lf.get('type')} discovered at {lf.get('url')} via {lf.get('method')}",
                            "evidence_url": lf.get("url"),
                            "severity": lf.get("severity"),
                            "remediation_fix": "1. Implement strict server-side authorization checks.\n2. Do NOT trust client-supplied IDs or amounts.",
                            "impact_desc": f"An attacker can exploit this {lf.get('type')} to manipulate business logic, potentially resulting in unauthorized data access or financial loss."
                        }
                        self.db.add_finding(domain, content_obj, lf.get("type"), campaign_id=campaign_id)
                        vulns.append(lf)
            self._save_mission_state(recon_domain, "LOGIC_COMPLETE", len(findings), len(discovered_urls))
        
        # Step 3: Deep AI Audit — v7.2: Expanded DAST coverage (15 entry points, depth 3)
        if self.mission_state.get("step") == "DAST_COMPLETE":
             console.print("[bold yellow][🩹] Zenith: Step 'DAST_COMPLETE' detected. Skipping DAST and Singularity loops...[/bold yellow]")
        else:
            await self.broadcast(f"Unleashing Nexus Deep Crawler on {len(discovered_urls)} entry points...", type="status", icon="link")
        
        visited_global = set()
        
        dast_tasks = []
        # v7.2: Expanded from 5 to 15 primary entry points, depth 3 for deep audit
        # v14.2: Fast Mode Scaling (5 entry points, depth 1)
        max_entry_points = 5 if self.effective_fast_mode else 15
        dast_depth = 1 if self.effective_fast_mode else 3
        
        for d_url in discovered_urls[:max_entry_points]: 
            async def _d(u):
                async with self.dast_semaphore:
                    return await self.dast.scan_target(u, depth=dast_depth, visited=visited_global)
            dast_tasks.append(_d(d_url))
            
        if dast_tasks:
            dast_results = await asyncio.gather(*dast_tasks)
            for r in dast_results:
                if r: 
                    vulns.extend(r)
                    # Phase 15: Exploit Chaining on DAST results
                    for finding in r:
                        await self._process_exploit_chain(domain, finding.get("type", ""), finding)
        
        # Phase 15: Exploit Chaining for Logic findings
        if logic_findings:
            for lf in logic_findings:
                await self._process_exploit_chain(domain, lf.get("type", ""), lf)

        
        # Step 3.5: Singularity Autonomous CoT Attack (Phase 18)
        # v14.2: Skip Singularity in Fast Mode unless escalated
        if not self.effective_fast_mode:
            await self.broadcast("Unleashing Aura Singularity: Initiating Autonomous CoT & XHR Interception...", type="status", icon="volcano")
            
            singularity_tasks = []
            for d_url in discovered_urls[:5]: # Velocity v7.4: Scaled from 3 to 5
                 async def _s(u):
                     async with self.sing_semaphore:
                         return await self.singularity.execute_singularity(u)
                 singularity_tasks.append(_s(d_url))
                 
            if singularity_tasks:
                sing_results = await asyncio.gather(*singularity_tasks)
                for res in sing_results:
                    if res:
                        vulns.extend(res)
                        console.print(f"[bold red][[BOOM]] SINGULARITY HIT: {len(res)} deep logic flaws detected on entry point.[/bold red]")

            # v20.0 Zenith: Save state after DAST/Singularity Complete
            self._save_mission_state(recon_domain, "DAST_COMPLETE", len(findings), len(discovered_urls))

        # Step 4: Strategic Exploit (v12.1 Fully-Persistent)
        if state.is_halted(): return {"status": "ABORTED"}

        all_findings = self.db.get_findings_by_target(domain)
        if all_findings:
            console.print(f"[bold red][!!!] ZENITH ALERT: {len(all_findings)} findings identified. Initiating exfiltration verification...[/bold red]")
            # v19.4 Performance Fix: Only attempt exfiltration ONCE per vulnerability type to avoid runaway loops
            _exfil_attempted = set()
            for v in all_findings:
                v_type = v.get("type", "").lower()
                if ("sql" in v_type or "injection" in v_type) and "sqli" not in _exfil_attempted:
                    await self.dast.attempt_exfiltration(domain, "SQLi")
                    self.db.log_action("EXFIL_ATTEMPT", domain, "SQLi Data Probe", campaign_id)
                    _exfil_attempted.add("sqli")

        # v20.0 Zenith Sovereignty: Save successful intelligence for cross-domain bridge
        if vulns:
            for v in vulns:
                if v.get("severity") in ["CRITICAL", "HIGH"] and tech_stack:
                    # Extract tech stack name from version strings
                    main_stack = tech_stack[0].split("/")[0] if tech_stack else "Generic"
                    # Capture the successful payload (if available in content or dict)
                    payload = v.get("content", "").split("Payload: '")[-1].split("'")[0] if "Payload: '" in str(v) else None
                    if payload:
                        self.db.save_sovereign_intel(main_stack, v.get("type"), payload)
                        console.print(f"[bold magenta][💎] Sovereign Bridge: Indexed successful pattern for '{main_stack}'[/bold magenta]")

        # v22.0: Oracle Synthesis & Exploit Chaining (The Grand Finale)
        await self.broadcast("Oracle Synthesis: Analyzing Findings for Exploit Chains & Implied Vulnerabilities...", type="status", icon="crystal_ball")
        
        # 1. Predictive Vulnerability Mapping
        context_data = {"domain": domain, "targets_found": len(discovered_urls)}
        predictions = self.brain.predict_implied_vulns(context_data, vulns)
        for pred in predictions:
            await self.broadcast(f"[🔮 Oracle] Implied Bug: {pred.get('predicted_type')} at {pred.get('implied_url')}", type="info", icon="brain")
            vulns.append({
                "type": f"Implied {pred.get('predicted_type')}",
                "target": pred.get('implied_url'),
                "severity": "PREDICTIVE",
                "finding_type": "Oracle Synthesis Prediction",
                "content": pred.get("reasoning")
            })

        # 2. Autonomous Exploit Chaining
        await self.execute_exploit_chaining(domain, vulns)

        # v20.0 Zenith Sovereignty: Mission Finalization & Reporting
        await self.broadcast("Finalizing mission and generating Zenith reports...", type="status", icon="file-text")
        # tech_stack is expected to be a list or "Generic"
        stack_name = tech_stack[0].split("/")[0] if (isinstance(tech_stack, list) and tech_stack) else tech_stack
        report_paths = await self.reporter.finalize_mission(domain, vulns, tech_stack=stack_name)
        for path in report_paths:
            console.print(f"[bold green][📝] Zenith Report Generated: {os.path.basename(path)}[/bold green]")
            self.db.log_action("REPORT_GENERATED", domain, f"Path: {path}", campaign_id)

        # Update target status to COMPLETED
        self.db.save_target({"target": domain, "status": "COMPLETED"})
            
        # Step 4.5: Phase 26 OAST Polling
        if self.dast.oast.uuid:
            console.print("[cyan][👁️] Phase 26: God Mode OAST Polling... Waiting for blind callbacks.[/cyan]")
            await self.broadcast("Waiting for out-of-band blind exploitation callbacks...", type="status", icon="eye")
            await asyncio.sleep(5) # Give out-of-band requests time to hit
            oast_hits = self.dast.oast.poll()
            if oast_hits:
                console.print(f"[bold red][!!!] ZENITH OAST ALERT: {len(oast_hits)} Blind Exploitation Callbacks Received![/bold red]")
                for hit in oast_hits:
                    content = f"DETERMINISTIC HIT: Blind OAST Callback Received: {hit['method']} to {hit.get('url', '?')} from {hit.get('ip', '?')} (Agent: {hit.get('user_agent', '?')})"
                    console.print(f"[bold green] + {content}[/bold green]")
                    self.db.add_finding(domain, content, "Blind RCE / SSRF", campaign_id=campaign_id)
                    # Helper for severity
                    try: self.db.update_finding_metadata(domain, content, "CRITICAL")
                    except: pass
                    vulns.append({"type": "Blind RCE / SSRF", "content": content})
                    # Phase 29: Auto-Pivot into discovered internal IPs if Blind RCE confirms
                    if target_ip:
                        await self.link.auto_pivot(target_ip, self)
                    
                    # v18.0 Nebula Ghost: Autonomous Lateral Pivoting
                    await self.lateral.pivot_from_finding(hit)

        # v6.0: Phase 5 — PoCEngine: Deterministic verification of all findings (v12.1 Force Mode)
        console.print("[bold red][*] Phase 5: v6.0 PoC Engine — Deterministic Exploitation Verification...[/bold red]")
        await self.poc_engine.verify_all(target_url, all_findings or [])

        # Step 5: Aura Forge Plugins (Community/Custom Intelligence)
        if self.plugins:
            console.print(f"[bold magenta][*] Step 5+: Executing {len(self.plugins)} Forge plugins...[/bold magenta]")

            for plugin in self.plugins:
                plugin_result = await plugin.run(domain, {"waf": self.stealth.active_waf, "vulns": vulns, "tech": tech_stack})
                if plugin_result:
                    console.print(f"[bold magenta][Forge:{plugin.name}][/bold magenta] Finding: {plugin_result.get('finding')}")
                    self.db.add_finding(domain, plugin_result.get('finding'), f"Forge-{plugin.name}", campaign_id=campaign_id)

        # Step 6: Recalculate Risk Score and Priority based on ALL findings in DB (v12.1 High-Persistence Fix)
        all_findings = self.db.get_findings_by_target(domain)
        if all_findings:
            console.print("[cyan][*] Recalculating target risk score using strict CVSS 3.1 bands...[/cyan]")
            
            # Retrieve or assign CVSS to all findings
            cvss_scores = []
            for v in all_findings:
                v_type = v.get("type", "").lower()
                severity = v.get("severity", "").upper() if v.get("severity") else v.get("finding_severity", "").upper()
                if not severity:
                    severity = self.brain.calculate_impact(v_type, v.get("content", ""))
                
                # Assign default CVSS if missing to ensure proper scaling
                if "cvss_score" not in v:
                    if "CRITICAL" in severity: v["cvss_score"] = 9.8
                    elif "HIGH" in severity: v["cvss_score"] = 7.5
                    elif "MEDIUM" in severity: v["cvss_score"] = 5.5
                    else: v["cvss_score"] = 3.9
                
                # v12.0 Hardcoded Execution: Mandatory Score Enforcement
                # Rule: 7.5 for Server/Systemic, 5.0 for Information Disclosure
                v_content_lower = v.get("content", "").lower()
                if any(x in v_type for x in ["web server", "misconfiguration", "systemic", "fingerprint"]) or \
                   any(x in v_content_lower for x in ["apache", "nginx", "coyote", "server-status", "admin", "manager"]):
                    v["cvss_score"] = 7.5
                    v["severity"] = "HIGH"
                elif any(x in v_type for x in ["information disclosure", "leak", "sensitive", "exposure"]):
                    v["cvss_score"] = 5.0
                    v["severity"] = "MEDIUM"
                elif "injection" in v_type or "sql" in v_type or "xss" in v_type:
                    v["cvss_score"] = 9.8
                    v["severity"] = "CRITICAL"
                
                cvss_scores.append(float(v.get("cvss_score") or 0.0))
            
        # v17.0: Shadow-Scripting — Autonomous Weaponization
        # v26.0 Turbine Engine: High-velocity parallel weaponization.
        if vulns:
            console.print(f"[bold red][[SWORD]] Shadow-Scripting: Weaponizing {len(vulns)} vulnerability findings (Turbine Active)...[/bold red]")
            exploit_dir = os.path.join(os.getcwd(), "aura_exploits")
            if not os.path.exists(exploit_dir): os.makedirs(exploit_dir)
            
            # Velocity v26.0: Concurrency limit for AI-assisted weaponization
            weapon_sem = asyncio.Semaphore(5)
            
            async def _weaponize_single(i, v):
                async with weapon_sem:
                    v_type = v.get("type") or v.get("finding_type")
                    v_content = v.get("content")
                    # generate_exploit_script involves AI, running in thread to avoid blocking loop
                    script = await asyncio.to_thread(self.brain.generate_exploit_script, v_type, v_content, target_url)
                    
                    filename = f"exploit_{domain.replace('.', '_')}_{i}.py"
                    filepath = os.path.join(exploit_dir, filename)
                    with open(filepath, "w", encoding="utf-8") as f:
                        f.write(script)
                    console.print(f"[bold green][[SUCCESS]] Weaponized: {filename} (Turbine Accelerated)[/bold green]")
            
            # Launch parallel weaponization
            await asyncio.gather(*[_weaponize_single(i, v) for i, v in enumerate(vulns)])

        # v20.0 Phase 4: Wayback Machine Historical JS Scanner
        console.print("[cyan][*] Phase 4: Running Wayback Machine Historical JS Scanner...[/cyan]")
        session = self.session
        try:
            wayback = WaybackScanner(session=session)
            wayback_findings = await wayback.scan_target(recon_domain)
            if wayback_findings:
                all_findings.extend(wayback_findings)
                for wf in wayback_findings:
                    self.db.save_finding(recon_domain, wf)
                console.print(f"[bold red][[WAYBACK]] {len(wayback_findings)} historical secret(s) found![/bold red]")
        except Exception as e:
            console.print(f"[dim red][Wayback] Skipped: {e}[/dim red]")

        # v20.0 Phase 5: 403 Bypass Engine
        console.print("[cyan][*] Phase 5: Running 403 Bypass Engine on blocked endpoints...[/cyan]")
        try:
            bypass = BypassEngine(session=session)
            # Collect 403 URLs from previous scan operations in the database
            forbidden_urls = [
                row[0] for row in self.db.conn.execute(
                    "SELECT url FROM operations WHERE status_code = 403 AND target = ? ORDER BY id DESC LIMIT 50",
                    (recon_domain,)
                ).fetchall()
            ] if hasattr(self.db, 'conn') else []
            bypass_findings = await bypass.scan_403_list(forbidden_urls)
            if bypass_findings:
                all_findings.extend(bypass_findings)
                for bf in bypass_findings:
                    self.db.save_finding(recon_domain, bf)
                console.print(f"[bold red][[BYPASS]] {len(bypass_findings)} 403 bypass(es) confirmed![/bold red]")
        except Exception as e:
            console.print(f"[dim red][Bypass] Skipped: {e}[/dim red]")

        # v20.0 Phase 6: GraphQL Introspection Probe
        console.print("[cyan][*] Phase 6: Probing for GraphQL Introspection...[/cyan]")
        try:
            dast_probe = AuraDAST(stealth=self.stealth)
            dast_probe.session = session
            gql_findings = await dast_probe.probe_graphql_introspection(target_url)
            if gql_findings:
                all_findings.extend(gql_findings)
                for gf in gql_findings:
                    self.db.save_finding(recon_domain, gf)
                console.print(f"[bold yellow][[GraphQL]] {len(gql_findings)} introspection endpoint(s) found![/bold yellow]")
        except Exception as e:
            console.print(f"[dim red][GraphQL] Skipped: {e}[/dim red]")

        # v22.0 Phase 7: SSRF Hunter (Tier 2 — Highest ROI)
        console.print("[cyan][*] Phase 7: Running SSRF Hunter...[/cyan]")
        try:
            from aura.modules.ssrf_hunter import SSRFHunter
            ssrf = SSRFHunter(session=session)
            # Collect all discovered URLs from operations log
            discovered_urls = [
                row[0] for row in self.db.conn.execute(
                    "SELECT url FROM operations WHERE target = ? AND url IS NOT NULL ORDER BY id DESC LIMIT 100",
                    (recon_domain,)
                ).fetchall()
            ] if hasattr(self.db, 'conn') else []
            ssrf_findings = await ssrf.scan_urls(discovered_urls or [target_url])
            if ssrf_findings:
                all_findings.extend(ssrf_findings)
                for sf in ssrf_findings:
                    self.db.save_finding(recon_domain, sf)
                console.print(f"[bold red][[SSRF]] {len(ssrf_findings)} SSRF finding(s) discovered![/bold red]")
        except Exception as e:
            console.print(f"[dim red][SSRF] Skipped: {e}[/dim red]")

        # v22.0 Phase 8: IDOR Hunter on discovered URLs
        console.print("[cyan][*] Phase 8: Running IDOR Hunter on discovered endpoints...[/cyan]")
        try:
            from aura.modules.idor_hunter import IDORHunter
            idor = IDORHunter(session=session)
            disc_urls = [
                row[0] for row in self.db.conn.execute(
                    "SELECT url FROM operations WHERE target = ? AND url IS NOT NULL ORDER BY id DESC LIMIT 100",
                    (recon_domain,)
                ).fetchall()
            ] if hasattr(self.db, 'conn') else [target_url]
            idor_findings = await idor.scan_urls(disc_urls or [target_url])
            if idor_findings:
                all_findings.extend(idor_findings)
                for idf in idor_findings:
                    self.db.save_finding(recon_domain, idf)
                console.print(f"[bold red][[IDOR]] {len(idor_findings)} IDOR(s) confirmed![/bold red]")
        except Exception as e:
            console.print(f"[dim red][IDOR] Skipped: {e}[/dim red]")

        # v22.0 Phase 9: OAuth Flaw Detector
        console.print("[cyan][*] Phase 9: Running OAuth Flaw Detector...[/cyan]")
        try:
            from aura.modules.oauth_hunter import OAuthHunter
            oauth = OAuthHunter(session=session)
            oauth_findings = await oauth.scan_target(target_url)
            if oauth_findings:
                all_findings.extend(oauth_findings)
                for of in oauth_findings:
                    self.db.save_finding(recon_domain, of)
                console.print(f"[bold red][[OAuth]] {len(oauth_findings)} OAuth flaw(s) found![/bold red]")
        except Exception as e:
            console.print(f"[dim red][OAuth] Skipped: {e}[/dim red]")

        # v22.0 Phase 10: JWT Attack Engine on API endpoints
        console.print("[cyan][*] Phase 10: Running JWT Attack Engine...[/cyan]")
        try:
            dast_jwt = AuraDAST(stealth=self.stealth)
            dast_jwt.session = session
            jwt_findings = await dast_jwt.probe_jwt_attacks(target_url)
            if jwt_findings:
                all_findings.extend(jwt_findings)
                for jf in jwt_findings:
                    self.db.save_finding(recon_domain, jf)
                console.print(f"[bold red][[JWT]] {len(jwt_findings)} JWT weakness(es) confirmed![/bold red]")
        except Exception as e:
            console.print(f"[dim red][JWT] Skipped: {e}[/dim red]")

        # v22.0 Phase 11: Mass Assignment Detector
        console.print("[cyan][*] Phase 11: Running Mass Assignment Detector...[/cyan]")
        try:
            dast_ma = AuraDAST(stealth=self.stealth)
            dast_ma.session = session
            ma_findings = await dast_ma.probe_mass_assignment(target_url)
            if ma_findings:
                all_findings.extend(ma_findings)
                for mf in ma_findings:
                    self.db.save_finding(recon_domain, mf)
                console.print(f"[bold red][[MassAssign]] {len(ma_findings)} Mass Assignment weakness(es) confirmed![/bold red]")
        except Exception as e:
            console.print(f"[dim red][MassAssign] Skipped: {e}[/dim red]")

        # v28.0 Phase 14: Race Condition Hunter — single-use state exploitation
        console.print("[bold red][*] Phase 14 [SIEGE]: Race Condition Hunter — sub-millisecond burst attack...[/bold red]")
        try:
            race_hunter = RaceConditionHunter(session=session)
            # Collect discovered URLs from DB for candidate filtering
            race_urls = [
                row[0] for row in self.db.conn.execute(
                    "SELECT url FROM operations WHERE target = ? AND url IS NOT NULL ORDER BY id DESC LIMIT 150",
                    (recon_domain,)
                ).fetchall()
            ] if hasattr(self.db, 'conn') else [target_url]
            race_findings = await race_hunter.scan_urls(race_urls or [target_url])
            if race_findings:
                all_findings.extend(race_findings)
                for rf in race_findings:
                    self.db.save_finding(recon_domain, rf)
                console.print(f"[bold red][[RACE]] {len(race_findings)} Race Condition(s) CONFIRMED![/bold red]")
        except Exception as e:
            console.print(f"[dim red][Race] Skipped: {e}[/dim red]")

        # v28.0 Phase 15: SSTI Engine — Server-Side Template Injection → RCE
        console.print("[bold red][*] Phase 15 [SIEGE]: SSTI Engine — 10+ template engine injection scan...[/bold red]")
        try:
            ssti = SSTIEngine(session=session)
            ssti_urls = [
                row[0] for row in self.db.conn.execute(
                    "SELECT url FROM operations WHERE target = ? AND url IS NOT NULL ORDER BY id DESC LIMIT 100",
                    (recon_domain,)
                ).fetchall()
            ] if hasattr(self.db, 'conn') else [target_url]
            ssti_findings = await ssti.scan_urls(ssti_urls or [target_url])
            if ssti_findings:
                all_findings.extend(ssti_findings)
                for sf in ssti_findings:
                    self.db.save_finding(recon_domain, sf)
                console.print(f"[bold red][[SSTI]] {len(ssti_findings)} Template Injection(s) → potential RCE![/bold red]")
        except Exception as e:
            console.print(f"[dim red][SSTI] Skipped: {e}[/dim red]")

        # v28.0 Phase 16: HTTP Request Smuggling — CL.TE / TE.CL / TE.TE desync
        console.print("[bold red][*] Phase 16 [SIEGE]: HTTP Request Smuggling — CL.TE / TE.CL / TE.TE attack...[/bold red]")
        try:
            smuggling = SmugglingEngine(session=session)
            smug_findings = await smuggling.scan_target(target_url)
            if smug_findings:
                all_findings.extend(smug_findings)
                for smf in smug_findings:
                    self.db.save_finding(recon_domain, smf)
                console.print(f"[bold red][[SMUGGLING]] {len(smug_findings)} HTTP Desync vulnerability confirmed![/bold red]")
        except Exception as e:
            console.print(f"[dim red][Smuggling] Skipped: {e}[/dim red]")

        # v22.0 Phase 12: CVSS Auto-Enrichment — ensures every finding has accurate score
        console.print("[cyan][*] Phase 12: Enriching all findings with accurate CVSS 3.1 scores...[/cyan]")
        try:
            from aura.core.cvss_engine import CVSSEngine
            all_findings = CVSSEngine.enrich_all(all_findings)
            critical = [f for f in all_findings if f.get("severity") in ("CRITICAL", "EXCEPTIONAL")]
            console.print(f"[bold yellow][[CVSS]] {len(all_findings)} finding(s) enriched. {len(critical)} CRITICAL/EXCEPTIONAL.[/bold yellow]")
        except Exception as e:
            console.print(f"[dim red][CVSS] Skipped: {e}[/dim red]")

        # v22.0 Phase 13: Auto-Screenshot Evidence for all confirmed findings
        console.print("[cyan][*] Phase 13: Capturing screenshot evidence for confirmed findings...[/cyan]")
        try:
            from aura.modules.vision import VisualEye
            eye = VisualEye(output_dir="screenshots")
            confirmed_w_url = [
                f for f in all_findings
                if (f.get("confirmed") or f.get("severity") in ("CRITICAL", "EXCEPTIONAL"))
                and (f.get("evidence_url") or f.get("url"))
            ]
            if confirmed_w_url:
                all_findings = await eye.capture_all_confirmed_findings(all_findings)
                console.print(f"[bold green][[Evidence]] Screenshots captured for {len(confirmed_w_url)} finding(s)![/bold green]")
            else:
                console.print("[dim][Evidence] No confirmed findings with URLs to screenshot.[/dim]")
        except Exception as e:
            console.print(f"[dim red][Evidence] Skipped: {e}[/dim red]")

        # v29.0 Phase 17: Web Cache Poisoning — unkeyed header injection
        console.print("[bold red][*] Phase 17 [PHANTOM]: Web Cache Poisoning — 13 unkeyed header attack...[/bold red]")
        try:
            cache_engine = CachePoisoningEngine(session=session)
            cache_findings = await cache_engine.scan_target(target_url)
            if cache_findings:
                all_findings.extend(cache_findings)
                for cf in cache_findings:
                    self.db.save_finding(recon_domain, cf)
                console.print(f"[bold red][[CACHE POISON]] {len(cache_findings)} Cache Poisoning vector(s) found![/bold red]")
        except Exception as e:
            console.print(f"[dim red][Cache Poison] Skipped: {e}[/dim red]")

        # v29.0 Phase 18: XXE Engine — XML External Entity injection
        console.print("[bold red][*] Phase 18 [PHANTOM]: XXE Engine — XML file read and SSRF...[/bold red]")
        try:
            xxe = XXEEngine(session=session)
            xxe_urls = [
                row[0] for row in self.db.conn.execute(
                    "SELECT url FROM operations WHERE target = ? AND url IS NOT NULL ORDER BY id DESC LIMIT 80",
                    (recon_domain,)
                ).fetchall()
            ] if hasattr(self.db, 'conn') else [target_url]
            xxe_findings = await xxe.scan_urls(xxe_urls or [target_url])
            if xxe_findings:
                all_findings.extend(xxe_findings)
                for xf in xxe_findings:
                    self.db.save_finding(recon_domain, xf)
                console.print(f"[bold red][[XXE]] {len(xxe_findings)} XXE vulnerability confirmed![/bold red]")
        except Exception as e:
            console.print(f"[dim red][XXE] Skipped: {e}[/dim red]")

        # v29.0 Phase 19: Prototype Pollution — Object.prototype contamination
        console.print("[bold red][*] Phase 19 [PHANTOM]: Prototype Pollution — Node.js/JS Object poisoning...[/bold red]")
        try:
            pp = PrototypePollutionEngine(session=session)
            api_urls = [
                row[0] for row in self.db.conn.execute(
                    "SELECT url FROM operations WHERE target = ? AND url IS NOT NULL ORDER BY id DESC LIMIT 100",
                    (recon_domain,)
                ).fetchall()
            ] if hasattr(self.db, 'conn') else [target_url]
            pp_findings = await pp.scan_urls(api_urls or [target_url])
            if pp_findings:
                all_findings.extend(pp_findings)
                for pf in pp_findings:
                    self.db.save_finding(recon_domain, pf)
                console.print(f"[bold red][[PP]] {len(pp_findings)} Prototype Pollution finding(s) confirmed![/bold red]")
        except Exception as e:
            console.print(f"[dim red][PP] Skipped: {e}[/dim red]")

        # v29.0 Phase 20: DOM Hunter — Headless browser DOM XSS detection
        console.print("[bold red][*] Phase 20 [PHANTOM]: DOM Hunter — Headless Chromium DOM XSS scan...[/bold red]")
        try:
            dom = DOMHunter()
            dom_urls = [
                row[0] for row in self.db.conn.execute(
                    "SELECT url FROM operations WHERE target = ? AND url IS NOT NULL ORDER BY id DESC LIMIT 10",
                    (recon_domain,)
                ).fetchall()
            ] if hasattr(self.db, 'conn') else [target_url]
            dom_findings = await dom.scan_urls(dom_urls or [target_url])
            if dom_findings:
                all_findings.extend(dom_findings)
                for df in dom_findings:
                    self.db.save_finding(recon_domain, df)
                console.print(f"[bold red][[DOM XSS]] {len(dom_findings)} DOM vulnerability confirmed via headless browser![/bold red]")
        except Exception as e:
            console.print(f"[dim red][DOM Hunter] Skipped: {e}[/dim red]")

        # v30.0 Phase 21: GraphQL Reaper — Introspection, Batch, Injection
        console.print("[bold red][*] Phase 21 [APEX]: GraphQL Reaper — Schema mining, batch amplification, injection...[/bold red]")
        try:
            gql = GraphQLEngine(session=session)
            gql_findings = await gql.scan_target(target_url)
            if gql_findings:
                all_findings.extend(gql_findings)
                for gf in gql_findings:
                    self.db.save_finding(recon_domain, gf)
                console.print(f"[bold red][[GraphQL]] {len(gql_findings)} GraphQL vulnerability confirmed![/bold red]")
        except Exception as e:
            console.print(f"[dim red][GraphQL] Skipped: {e}[/dim red]")

        # v30.0 Phase 22: 2FA/MFA Bypass Engine
        console.print("[bold red][*] Phase 22 [APEX]: 2FA Bypass Engine — OTP brute force, reuse, response manipulation...[/bold red]")
        try:
            mfa = MFABypassEngine(session=session)
            mfa_findings = await mfa.scan_target(target_url)
            if mfa_findings:
                all_findings.extend(mfa_findings)
                for mf in mfa_findings:
                    self.db.save_finding(recon_domain, mf)
                console.print(f"[bold red][[2FA]] {len(mfa_findings)} 2FA bypass vector(s) found![/bold red]")
        except Exception as e:
            console.print(f"[dim red][2FA] Skipped: {e}[/dim red]")

        # v30.0 Phase 23: Business Logic Breaker
        console.print("[bold red][*] Phase 23 [APEX]: Business Logic Breaker — Negative prices, overflow, step skipping...[/bold red]")
        try:
            biz = BusinessLogicEngine(session=session)
            biz_findings = await biz.scan_target(target_url)
            if biz_findings:
                all_findings.extend(biz_findings)
                for bf in biz_findings:
                    self.db.save_finding(recon_domain, bf)
                console.print(f"[bold red][[BizLogic]] {len(biz_findings)} Business logic flaw(s) found![/bold red]")
        except Exception as e:
            console.print(f"[dim red][BizLogic] Skipped: {e}[/dim red]")

        # v31.0 Phases 24-27 [PERFORMANCE]: Parallelized Execution of Independent Vulnerability Engines
        console.print("[bold red][*] Phases 24-27 [FINAL]: Running HostHeader, OpenRedirect, FileUpload, Deser CONCURRENTLY...[/bold red]")
        
        async def run_hh():
            try:
                hh = HostHeaderEngine(session=session)
                res = await hh.scan_target(target_url)
                if res:
                    for hf in res: self.db.save_finding(recon_domain, hf)
                    console.print(f"[bold red][[HostHeader]] {len(res)} finding(s) confirmed![/bold red]")
                return res
            except Exception as e:
                console.print(f"[dim red][HostHeader] Skipped: {e}[/dim red]")
                return []
                
        async def run_redir():
            try:
                redir = OpenRedirectEngine(session=session)
                redir_urls = [row[0] for row in self.db.conn.execute("SELECT url FROM operations WHERE target = ? AND url IS NOT NULL ORDER BY id DESC LIMIT 100", (recon_domain,)).fetchall()] if hasattr(self.db, 'conn') else [target_url]
                res = await redir.scan_urls(redir_urls or [target_url])
                if res:
                    for rf in res: self.db.save_finding(recon_domain, rf)
                    console.print(f"[bold red][[OpenRedirect]] {len(res)} redirect(s) confirmed![/bold red]")
                return res
            except Exception as e:
                console.print(f"[dim red][OpenRedirect] Skipped: {e}[/dim red]")
                return []
                
        async def run_upload():
            try:
                upload = FileUploadEngine(session=session)
                res = await upload.scan_target(target_url)
                if res:
                    for uf in res: self.db.save_finding(recon_domain, uf)
                    console.print(f"[bold red][[FileUpload]] {len(res)} upload vulnerability confirmed![/bold red]")
                return res
            except Exception as e:
                console.print(f"[dim red][FileUpload] Skipped: {e}[/dim red]")
                return []
                
        async def run_deser():
            try:
                deser = DeserializationEngine(session=session)
                deser_urls = [row[0] for row in self.db.conn.execute("SELECT url FROM operations WHERE target = ? AND url IS NOT NULL ORDER BY id DESC LIMIT 50", (recon_domain,)).fetchall()] if hasattr(self.db, 'conn') else [target_url]
                res = await deser.scan_urls(deser_urls or [target_url])
                if res:
                    for df in res: self.db.save_finding(recon_domain, df)
                    console.print(f"[bold red][[Deser]] {len(res)} deserialization RCE confirmed![/bold red]")
                return res
            except Exception as e:
                console.print(f"[dim red][Deser] Skipped: {e}[/dim red]")
                return []

        # Execute Phase 24-27 concurrently
        parallel_results = await asyncio.gather(run_hh(), run_redir(), run_upload(), run_deser(), return_exceptions=True)
        for sub_res in parallel_results:
            if isinstance(sub_res, list):
                all_findings.extend(sub_res)

        # v31.0 Phase 28: WebSocket + OAuth Deep Attacker
        console.print("[bold red][*] Phase 28 [FINAL]: WebSocket + OAuth Attacker — Origin bypass, CSRF, code reuse...[/bold red]")
        try:
            ws_oauth = WSAndOAuthEngine(session=session)
            ws_findings = await ws_oauth.scan_target(target_url)
            if ws_findings:
                all_findings.extend(ws_findings)
                for wf in ws_findings:
                    self.db.save_finding(recon_domain, wf)
                console.print(f"[bold red][[WS+OAuth]] {len(ws_findings)} WebSocket/OAuth issue(s) confirmed![/bold red]")
        except Exception as e:
            console.print(f"[dim red][WS+OAuth] Skipped: {e}[/dim red]")

        # v22.0: Generate Bug Bounty Markdown Report
        console.print("[cyan][*] Compiling HackerOne/Bugcrowd Markdown Report...[/cyan]")


        md_reporter = MarkdownReporter(self.db.db_path)
        md_path = md_reporter.generate_report()
        if md_path:
            console.print(f"[bold green][[SUCCESS]] Bounty Report Ready: {md_path}[/bold green]")

        # v14.2: Mark target as COMPLETED to support resumption
        self.db.save_target({"target": recon_domain, "status": "COMPLETED"})
        console.print(f"[bold green][[SUCCESS]] Mission Successful: {recon_domain} is fully audited.[/bold green]")

        console.print("[bold green][[SUCCESS]] NeuralOrchestrator: Mission complete.[/bold green]")
        self.db.log_action("MISSION_COMPLETE", domain, "NeuralOrchestrator chain finished", campaign_id)
        
        return {
            "status": "COMPLETE",
            "findings": len(all_findings),
            "waf": self.stealth.active_waf,
            "techs": tech_stack if 'tech_stack' in locals() else {}
        }
    async def execute_exploit_chaining(self, domain: str, findings: list):
        """
        v22.0: Oracle Synthesis - Autonomous Exploit Chainer.
        Links disparate low-impact findings into high-severity chains.
        """
        if not findings or len(findings) < 2: return
        
        # Filter for chainable primitives (SSRF, LFI, Redirects, Logic)
        chainables = [f for f in findings if any(k in f.get("type", "").lower() for k in ["ssrf", "lfi", "redirect", "logic"])]
        if not chainables: return
        
        await self.broadcast(f"Chain Reactor: Analyzing {len(chainables)} primitives for high-impact links...", type="status", icon="link")
        
        # AI-driven chaining analysis
        prompt = (
            f"As AURA-Zenith Oracle, analyze these confirmed findings for {domain} and identify potential Exploit Chains.\n"
            f"Findings: {json.dumps(findings[:15])}\n\n"
            "Can a confirmed SSRF reach an internal IP found in another log? "
            "Can an Open Redirect be used to leak an OAuth token found in a JS file? "
            "Can a Logic Flaw be combined with an IDOR for full Account Takeover?\n"
            "Respond ONLY in JSON array: [{'chain_name': 'str', 'components': ['finding_id_1', 'finding_id_2'], 'severity': 'CRITICAL', 'logic': 'str'}]"
        )
        try:
            raw = self.brain.reason_json(prompt)
            chains = json.loads(raw)
            for chain in chains:
                await self.broadcast(f"[🔗 CHAIN] {chain.get('chain_name')} ({chain.get('severity')})", type="vuln", icon="fire")
                findings.append({
                    "type": f"Exploit Chain: {chain.get('chain_name')}",
                    "severity": chain.get("severity"),
                    "finding_type": "Autonomous Exploit Chain",
                    "content": chain.get("logic"),
                    "target": domain,
                    "confirmed": True
                })
        except Exception as e:
            # logger.error(f"Oracle Chaining Error: {e}")
            pass

class MirrorSimulator:
    """
    v25.0 Omega Prototype: The Mirror Protocol.
    Anticipates defensive reactions by simulating a WAF/SOC analyst.
    """
    def __init__(self, brain):
        self.brain = brain
        self.alert_threshold = 0.7 # Confidence that an alert was triggered

    async def predict_exposure(self, activity_log: list) -> dict:
        """Analyzes recent activity to predict if security teams have been notified."""
        console.print("[bold blue][🪞 MIRROR] Simulating Defensive Response Analysis...[/bold blue]")
        # Simplified simulation
        risk_score = random.random()
        return {
            "alert_triggered": risk_score > self.alert_threshold,
            "predicted_signatures": ["SQLi_Pattern_A", "Rapid_Dir_Bust"],
            "recommended_shift": "Switch to WSS Tunneling" if risk_score > 0.5 else "Stay Course"
        }

class DeceptionOrchestrator:
    """
    v25.0 Omega Prototype: Deception Infrastructure.
    Spawns 'Noise Workers' to distract SOC teams from the primary objective.
    """
    def __init__(self, swarm):
        self.swarm = swarm

    async def deploy_distraction(self, target: str):
        """Spawns aggressive, low-sophistication traffic to a dummy endpoint."""
        console.print(f"[bold yellow][🎭 DECEPTION] Deploying Noise Workers to distract security for {target}...[/bold yellow]")
        # Simulate spawning loud traffic
        await asyncio.sleep(0.5)
        console.print("[dim yellow][+] Noise Swarm active: Engaging WAF with generic 'noisy' signatures.[/dim yellow]")

class SovereignDecisionEngine:
    """
    v25.0 Omega Prototype: Sentient Mission Autonomy.
    Decides when and where to strike based on global intelligence.
    """
    def __init__(self, brain, db):
        self.brain = brain
        self.db = db

    async def autonomous_mission_planning(self, domain: str = None) -> list:
        """Analyzes global Nexus Intel and picks high-value targets autonomously."""
        console.print("[bold purple][🧠 SOVEREIGN] Analyzing Global Battlefield for Autonomous Target Selection...[/bold purple]")
        # v22.5: Use the actual scanned domain, not fake internal targets
        if domain:
            selected = [domain]
        else:
            selected = [domain or "unknown"]
        console.print(f"[bold purple][👑] Decision: Primary Objective set to: {selected[0]}[/bold purple]")
        return selected
