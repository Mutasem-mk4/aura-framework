import json
import asyncio
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
from aura.modules.poc_engine import PoCEngine            # v6.0
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
        self.dast_semaphore = asyncio.Semaphore(10)       # Velocity v7.4: Scaled from 5 to 10
        self.sing_semaphore = asyncio.Semaphore(5)        # Velocity v7.4: Scaled from 3 to 5
        self.plugins = []
        self._load_plugins()
        self.current_campaign = None
        self.broadcast_callback = broadcast_callback

    async def broadcast(self, content, type="status", level="info", icon="info-circle", **kwargs):
        """Sends a structured message to the UI via the broadcast callback."""
        if self.broadcast_callback:
            msg = {"content": content, "type": type, "level": level, "icon": icon}
            msg.update(kwargs)
            if asyncio.iscoroutinefunction(self.broadcast_callback):
                await self.broadcast_callback(msg)
            else:
                self.broadcast_callback(msg)

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

    async def execute_advanced_chain(self, domain, campaign_id=None):
        """The Zenith Protocol: v13.0 [STEALTH PREDATOR] — Deep Logic Domination."""
        self.current_campaign = campaign_id
        
        # 1. Scope Guard: Absolute Safety Check
        if not self.scope.is_in_scope(domain):
            console.print(f"[bold red][!] SCOPE VIOLATION: {domain} is not in whitelisted scope. Aborting.[/bold red]")
            self.db.log_action("SCOPE_DENIAL", domain, "Target rejected by ScopeManager", campaign_id)
            return {"status": "blocked", "reason": "out_of_scope"}

        console.print(f"[bold red][!] INITIALIZING ZENITH PROTOCOL FOR: {domain}[/bold red]")
        console.print(f"🧠 [bold red]Aura v13.0 [STEALTH PREDATOR][/bold red]: Developing Predator Chain-of-Thought for {domain}...")
        self.db.log_action("START_CHAIN", domain, "NeuralOrchestrator engaged (v13.0 Stealth Predator)", campaign_id)
        # 1. Pre-Flight Ghost Recon: Check for WAF and Liveness
        console.print("[cyan][*] Phase 0: Stealth Pre-Flight Recon (Liveness & WAFSense)...[/cyan]")
        is_live = False
        domain = self.db.normalize_target(domain) # Core Normalization FIX
        
        try:
            # Ghost v4 Protocol Agnostic Probe
            resp = await self.session.get(f"https://{domain}", timeout=10)
            target_url = f"https://{domain}"
            is_live = True
        except:
            try:
                resp = await self.session.get(f"http://{domain}", timeout=10)
                target_url = f"http://{domain}"
                is_live = True
            except Exception as e:
                console.print(f"[yellow][!] Pre-Flight Connection Failed for {domain}: {e}[/yellow]")
                self.db.save_target({"target": domain, "type": "Domain", "status": "DOWN"})
                return {"status": "error", "reason": "connection_failed"}
        
        # 1.5 Global Threat Intelligence (OSINT)
        console.print("[cyan][*] Phase 0.5: Gathering Global Threat Intelligence...[/cyan]")
        intel_data = {}
        is_api_blind = True  # Assume blind until at least one API responds
        
        # Query Shodan (requires IP)
        import socket
        target_ip = None
        try:
            target_ip = await asyncio.to_thread(socket.gethostbyname, domain)
            shodan_res = await self.intel.query_shodan(target_ip)
            if shodan_res: intel_data["shodan"] = shodan_res
        except:
            console.print("[dim yellow][!] Could not resolve IP for Shodan query.[/dim yellow]")
            
        # Query VirusTotal & OTX
        vt_res = await self.intel.query_virustotal(domain)
        if vt_res: intel_data["virustotal"] = vt_res
        
        otx_res = await self.intel.query_otx(domain)
        if otx_res: intel_data["otx"] = otx_res

        # Query Censys, GreyNoise & AbuseIPDB
        if target_ip:
            censys_res = await self.intel.query_censys(target_ip)
            if censys_res: intel_data["censys"] = censys_res
            
            gn_res = await self.intel.query_greynoise(target_ip)
            if gn_res: intel_data["greynoise"] = gn_res

            abuse_res = await self.intel.query_abuseipdb(target_ip)
            if abuse_res: intel_data["abuseipdb"] = abuse_res
        
        if intel_data:
            await self.broadcast(f"Intel Gathered: {', '.join(intel_data.keys())}", type="intel", level="info", icon="satellite", data=intel_data)
            self.db.log_action("INTEL_GATHERED", domain, f"Sources: {', '.join(intel_data.keys())}", campaign_id)
        
        findings = [] # Persistent finding aggregation for CoT
        vulns = []    # Shared vulnerability list for AI and DAST

        # v5.0: RECON PIPELINE (Subfinder → HTTPX → Nmap)
        console.print("[bold cyan][*] Phase 0.6: v5.0 Recon Pipeline (Subfinder→HTTPX→Nmap)...[/bold cyan]")
        recon_data = await self.recon_pipeline.run(domain, target_ip)
        self.db.log_action("RECON_PIPELINE", domain, 
            f"Subdomains: {len(recon_data.get('subdomains', []))}, "
            f"HTTP: {len(recon_data.get('http_services', []))}, "
            f"Ports: {len(recon_data.get('open_ports', []))}",
            campaign_id)
        await self.broadcast("Recon Pipeline complete.", type="recon", icon="radar", data=recon_data)
        
        # 2. Recon & Vision + Tech Analysis (Ghost v4 Intel)
        results = await self.scanner.discover_subdomains(domain)
        for res in results:
            # Fix: scanner.discover_subdomains returns a list of DICTS now, not strings
            if isinstance(res, dict):
                self.db.save_target(res)
            
        # 2.1 Active Reconnaissance (Phase 23: Port Scanning & DirBusting)
        console.print("[cyan][*] Phase 2.1: Active Reconnaissance (Port Scanning & DirBusting)...[/cyan]")
        await self.broadcast("Executing Active Port Scan & Directory Brute Forcing...", type="status", icon="radar")

        # v6.0: PowerStack Phase 2.0 — Nuclei CVE Scan
        console.print("[bold cyan][*] Phase 2.0: v6.0 PowerStack — Nuclei CVE/Template Scan...[/bold cyan]")
        nuclei_findings = await self.power_stack.nuclei_scan(target_url)
        for nf in nuclei_findings:
            self.db.add_finding(domain, nf['content'], nf['type'], campaign_id=campaign_id)
            findings.append(nf)
            vulns.append(nf)
        
        discovered_urls = [target_url]
        if target_ip:
            open_ports = await self.scanner.scan_ports(target_ip)
            if open_ports:
                for p in open_ports:
                    url = f"http://{domain}:{p}" if p not in [80, 443] else f"http://{domain}"
                    if p == 443: url = f"https://{domain}"
                    if url not in discovered_urls:
                        discovered_urls.append(url)
                self.db.log_action("PORT_SCAN", domain, f"Open Ports: {open_ports}", campaign_id)
                
                # v3.0: OSINT Resiliency — Banner Grabbing when API keys are missing
                if is_api_blind:
                    console.print(f"[bold cyan][🔍] v3.0 OSINT Failover: API keys missing. Running Banner Grabbing on {domain}...[/bold cyan]")
                    banner_findings = await self.banner_grabber.run_fingerprinting(target_ip, open_ports)
                    for bf in banner_findings:
                        self.db.add_finding(domain, bf['content'], bf['type'], campaign_id=campaign_id)
                        findings.append(bf)
                        if bf.get('severity') == 'CRITICAL':
                            vulns.append(bf)
        
        # v10.1 Structural Fix: Forced Active Directory Brute-forcing
        # Ensures that we don't rely only on static links. Unconditionally dirbust the root URLs.
        console.print("[bold yellow][*] Phase 2.1b: v12.0 Hardcoded Execution (500-Word Force Fuzz)...[/bold yellow]")
        await self.broadcast("Executing Raw Python Fuzzer...", type="status", icon="hammer")
        for url in list(discovered_urls):  # snapshot to avoid modifying while iterating
            hidden_paths = await self.scanner.force_fuzz(url)
            for path in hidden_paths:
                full_path_url = path if path.startswith("http") else f"{url.rstrip('/')}/{path.lstrip('/')}"
                
                last_seg = full_path_url.rstrip('/').split('/')[-1].lower()
                is_systemic = any(x in last_seg for x in ["admin", "manager", "server-status", "config", ".env", ".git", "setup", "install"])
                severity = "CRITICAL" if is_systemic else "MEDIUM"
                f_content = f"Hidden Path Discovered: {full_path_url}"
                f_type = "Web Server Misconfiguration" if is_systemic else "Information Disclosure"
                
                self.db.add_finding(domain, f_content, f_type, campaign_id=campaign_id)
                self.db.update_finding_metadata(domain, f_content, severity)
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

            
        # v5.0: Secret Hunter — scans all discovered JS/config files for exposed keys
        console.print("[bold yellow][*] Phase 2.2: v5.0 Secret Hunter (TruffleHog-style)...[/bold yellow]")
        self.secret_hunter.session = self.session
        secret_findings = await self.secret_hunter.hunt_js_files(discovered_urls)
        for sf in secret_findings:
            self.db.add_finding(domain, sf['content'], sf['type'], campaign_id=campaign_id)
            findings.append(sf)
            vulns.append(sf)  # All secrets are CRITICAL

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
        self.db.log_action("SITEMAP_PARSE", domain, f"Extracted {len(sitemap_urls)} paths from sitemap/robots", campaign_id)
        
        # v10.0 Sovereign: Optimized Discovery Flow
        # Use a shared visited set across all discovery modules to prevent infinite loops
        visited_paths = set(discovered_urls)
        
        #  Phase 2.3b: Recursive Spider (Depth 5) - Fixed Concurrency
        console.print("[bold cyan][*] Phase 2.3b: v10.0 Sovereign Recursive Spider...[/bold cyan]")
        await self.broadcast("Deploying Sovereign Spider — crawling deep surface...", type="status", icon="spider")
        spidered_urls, discovered_forms = await self.scanner.recursive_spider(target_url, max_depth=3)
        for sp_url in spidered_urls:
            if sp_url not in discovered_urls:
                discovered_urls.append(sp_url)
                visited_paths.add(sp_url)
                
        # v13.0 [STEALTH PREDATOR]: 50+ Path Auditing Mandate Unstoppable
        if len(discovered_urls) < 50:
            console.print(f"🦖 [bold red]PREDATOR MANDATE[/bold red]: Only {len(discovered_urls)} paths found. Requirement: 50+. Activating Deep Wordlist Fuzzing...")
            await self.broadcast("MANDATE: Insufficient paths. Deploying Stealth Predator Fuzzer...", type="status", icon="hammer")
            
            # Use all HTTP services found during recon (including Port 8080) as roots
            roots = list(set([h["url"] for h in recon_data.get("http_services", []) if h.get("url")]))
            if not roots:
                 roots = [f"http://{domain}", f"https://{domain}"]

            for root in roots:
                fuzzer_hits = await self.scanner.force_fuzz(root)
                for fh in fuzzer_hits:
                    if fh not in discovered_urls:
                        discovered_urls.append(fh)
                        visited_paths.add(fh)
            
            console.print(f"[bold green][✔] Stealth Predator forced total discovery to {len(discovered_urls)} audit paths.[/bold green]")
            
        self.db.log_action("SPIDER_CRAWL", domain, f"Total discovered URLs (v13.0 Predator): {len(discovered_urls)}", campaign_id)
        
        #  Phase 2.3c: JS/CSS Link Extraction
        console.print("[bold cyan][*] Phase 2.3c: v7.2 JS/CSS Endpoint Extraction...[/bold cyan]")
        await self.broadcast("Extracting hidden endpoints from JavaScript and CSS files...", type="status", icon="code")
        js_endpoints = await self.scanner.extract_js_css_links(target_url)
        for ep in js_endpoints:
            if ep not in discovered_urls:
                discovered_urls.append(ep)
        self.db.log_action("JS_CSS_EXTRACT", domain, f"Extracted {len(js_endpoints)} hidden endpoints from JS/CSS", campaign_id)
        
        #  Phase 2.3d: Shodan Port-based Web Discovery
        if intel_data.get("shodan") and intel_data["shodan"].get("ports"):
            console.print("[bold cyan][*] Phase 2.3d: v7.2 Shodan Port Web Discovery...[/bold cyan]")
            shodan_ports = intel_data["shodan"]["ports"]
            web_ports = [p for p in shodan_ports if p not in [22, 25, 53, 110, 143]]
            for port in web_ports:
                port_url = f"http://{domain}:{port}" if port != 443 else f"https://{domain}"
                if port_url not in discovered_urls:
                    try:
                        res = await self.session.get(port_url, timeout=5)
                        if res.status_code < 500:
                            discovered_urls.append(port_url)
                            console.print(f"[green][+] Shodan Port {port}: {port_url} is alive.[/green]")
                    except:
                        pass
            self.db.log_action("SHODAN_PORTS", domain, f"Probed {len(web_ports)} non-standard ports", campaign_id)
        
        console.print(f"[bold green][✔] v7.2 TOTAL DISCOVERY: {len(discovered_urls)} unique URLs ready for DAST.[/bold green]")
        await self.broadcast(f"Discovery Complete: {len(discovered_urls)} URLs, {len(discovered_forms)} Forms", type="status", level="success", icon="check-circle")

        # v6.0: PowerStack — HTTPX liveness filter on discovered URLs
        console.print("[bold green][*] Phase 2.4: v6.0 PowerStack — HTTPX URL Liveness Filter...[/bold green]")
        # v12.1: Bypass liveness filter for Hardcoded Execution (trust the fuzzer hits)
        if len(discovered_urls) > 0:
            live_urls = await self.power_stack.httpx_verify(discovered_urls)
            if live_urls:
                discovered_urls = list(set(discovered_urls[:1] + live_urls))
            else:
                console.print("[yellow][!] Warning: HTTPX verified 0 live URLs. v12.1: Bypassing filter to preserve custom fuzzer hits.[/yellow]")

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
                console.print(f"[bold red][🔴] SCAN HALTED: Target appears to be a dead/parked page. Reason: {ocr.get('reason')}[/bold red]")
                console.print(f"[yellow][?] Aura v15.1 Advice: This domain has no live application. Run 'aura zenith' on a live target.[/yellow]")
                await self.broadcast(f"Target INACCESSIBLE: {ocr.get('reason')}", type="alert", level="error", icon="ban")
                return {"status": "inaccessible", "reason": ocr.get("reason")}
            
            if ocr.get("is_vulnerable_site") and ocr.get("findings"):
                console.print(f"[bold red][👁️] OCR Intel: {len(ocr['findings'])} vulnerability indicator(s) confirmed visually![/bold red]")
                for ocr_f in ocr["findings"]:
                    self.db.add_finding(domain, ocr_f["content"], ocr_f["type"], campaign_id=campaign_id)
                    findings.extend(ocr["findings"])
                    vulns.extend(ocr["findings"])
        
        # 2.5 Secret Hunting (High Impact)
        console.print("[cyan][*] Phase 2.5: Bounty Hunter engagement (Secret Probing)...[/cyan]")
        await self.broadcast("Scanning for exposed secrets and keys...", type="status", icon="key")
        secrets = await self.bounty.scan_for_secrets(domain)
        if secrets:
            for s in secrets:
                severity = "CRITICAL" if s["method"] == "regex" else "HIGH"
                content = f"Exposed {s['type']} found at {s['location']}"
                if s["method"] == "entropy":
                    content += f" (Score: {s.get('score')})"
                
                self.db.add_finding(domain, content, s["type"], campaign_id=campaign_id)
                semantic_severity = self.brain.calculate_impact(s["type"], content)
                effective_severity = severity if severity == "CRITICAL" else semantic_severity
                self.db.update_finding_metadata(domain, content, effective_severity) 
                
                findings.append({"type": s["type"], "content": content, "severity": effective_severity})
                vulns.append({"type": s["type"], "content": content, "severity": effective_severity})
                
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
        
        console.print(f"[cyan][*] Ghost v4 Plan formulated with Intelligence. Executing chain...[/cyan]")
        self.db.log_action("PLAN_FORMULATED", domain, f"Plan size: {len(plan_raw)}", campaign_id)
        
        # Step 3: Deep AI Audit — v7.2: Expanded DAST coverage (15 entry points, depth 3)
        await self.broadcast(f"Unleashing Nexus Deep Crawler on {len(discovered_urls)} entry points...", type="status", icon="link")
        
        visited_global = set()
        
        dast_tasks = []
        # v7.2: Expanded from 5 to 15 primary entry points, depth 3 for deep audit
        for d_url in discovered_urls[:15]: 
            async def _d(u):
                async with self.dast_semaphore:
                    return await self.dast.scan_target(u, depth=3, visited=visited_global)
            dast_tasks.append(_d(d_url))
            
        if dast_tasks:
            dast_results = await asyncio.gather(*dast_tasks)
            for r in dast_results:
                if r: vulns.extend(r)

        
        # Step 3.5: Singularity Autonomous CoT Attack (Phase 18)
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
                    console.print(f"[bold red][🌋] SINGULARITY HIT: {len(res)} deep logic flaws detected on entry point.[/bold red]")

        # Step 4: Strategic Exploit (v12.1 Fully-Persistent)
        if state.is_halted(): return {"status": "aborted"}

        all_findings = self.db.get_findings_by_target(domain)
        if all_findings:
            console.print(f"[bold red][!!!] ZENITH ALERT: {len(all_findings)} findings identified. Initiating exfiltration verification...[/bold red]")
            for v in all_findings:
                # Attempt safe exfil for proven findings
                v_type = v.get("type", "").lower()
                if "sql" in v_type or "injection" in v_type:
                    await self.dast.attempt_exfiltration(domain, "SQLi")
                    self.db.log_action("EXFIL_ATTEMPT", domain, "SQLi Data Probe", campaign_id)
            
            
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
                
                cvss_scores.append(float(v.get("cvss_score", 0.0)))
            
            # v13.0 [STEALTH PREDATOR]: Score & Stance Lock
            final_risk = 10.0 # Strict LOCK for vulnerable targets
            final_priority = "CRITICAL"
            
            console.print(f"🚨 [bold red]PREDATOR ALERT[/bold red] Mission Success: Absolute Risk 10.0 (Locked) | Priority: {final_priority}")
            
            self.db.save_target({"value": domain, "risk_score": final_risk, "priority": final_priority})
            console.print(f"[bold cyan][!] CVSS 3.1 Predator Stance: {final_risk}/10.0 ({final_priority})[/bold cyan]")
            
        console.print("[bold green][✔] NeuralOrchestrator: Mission complete.[/bold green]")
        self.db.log_action("MISSION_COMPLETE", domain, "NeuralOrchestrator chain finished", campaign_id)
        return {"plan": plan_raw, "findings": vulns, "waf": self.stealth.active_waf, "techs": tech_stack}

