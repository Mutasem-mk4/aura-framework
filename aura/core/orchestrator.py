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
        self.banner_grabber = BannerGrabber()            # v3.0: OSINT Resiliency
        self.recon_pipeline = ReconPipeline()             # v5.0: Subfinder→HTTPX→Nmap
        self.secret_hunter  = SecretHunter()              # v5.0: TruffleHog-style
        self.power_stack    = PowerStack(stealth=self.stealth)  # v6.0: Nuclei/TruffleHog/HTTPX/Nmap
        self.poc_engine     = PoCEngine(stealth=self.stealth)   # v6.0: Deterministic PoC
        self.dast_semaphore = asyncio.Semaphore(5)        # Velocity v14.4
        self.sing_semaphore = asyncio.Semaphore(3) # Velocity v14.4
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
        """Executes a Chain-of-Thought (CoT) attack plan autonomously with Ghost v4 Intelligence."""
        self.current_campaign = campaign_id
        
        # 1. Scope Guard: Absolute Safety Check
        if not self.scope.is_in_scope(domain):
            console.print(f"[bold red][!] SCOPE VIOLATION: {domain} is not in whitelisted scope. Aborting.[/bold red]")
            self.db.log_action("SCOPE_DENIAL", domain, "Target rejected by ScopeManager", campaign_id)
            return {"status": "blocked", "reason": "out_of_scope"}

        self.db.log_action("START_CHAIN", domain, "NeuralOrchestrator engaged", campaign_id)
        console.print(f"[bold magenta][🧠] NeuralOrchestrator (Ghost v4): Developing Chain-of-Thought for {domain}...[/bold magenta]")
        
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
        
        # v3.0 Fix: scanner.dirbust() now handles recursion internally (depth ≤ 2, 200-only).
        # The orchestrator just calls it once per BASE URL and processes the flat results.
        # DO NOT loop back and call dirbust() on returned paths — that caused the explosion.
        for url in list(discovered_urls):  # snapshot to avoid modifying while iterating
            hidden_paths = await self.scanner.dirbust(url)
            for path in hidden_paths:
                full_path_url = path if path.startswith("http") else f"{url.rstrip('/')}/{path.lstrip('/')}"
                
                last_seg = full_path_url.rstrip('/').split('/')[-1]
                severity = "CRITICAL" if last_seg in [".env", ".git", "docker-compose.yml", "config"] else "MEDIUM"
                f_content = f"Hidden Path Discovered: {full_path_url}"
                f_type = "Sensitive File Exposure" if severity == "CRITICAL" else "Information Disclosure"
                
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

        # v6.0: PowerStack — HTTPX liveness filter on discovered URLs
        console.print("[bold green][*] Phase 2.3: v6.0 PowerStack — HTTPX URL Liveness Filter...[/bold green]")
        live_urls = await self.power_stack.httpx_verify(discovered_urls)
        # Replace with live-only list for subsequent scans
        if live_urls:
            discovered_urls = list(set(discovered_urls[:1] + live_urls))  # Keep base + live

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
            
            # OCR found vulnerability indicators? Add them immediately!
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
                # Map entropy/regex results to findings
                severity = "CRITICAL" if s["method"] == "regex" else "HIGH"
                content = f"Exposed {s['type']} found at {s['location']}"
                if s["method"] == "entropy":
                    content += f" (Score: {s.get('score')})"
                
                self.db.add_finding(domain, content, s["type"], campaign_id=campaign_id)
                # Upgrade severity using AI reasoning or heuristics
                semantic_severity = self.brain.calculate_impact(s["type"], content)
                effective_severity = severity if severity == "CRITICAL" else semantic_severity
                self.db.update_finding_metadata(domain, content, effective_severity) 
                
                # Treat secrets as vulnerabilities for risk calculation
                findings.append({"type": s["type"], "content": content, "severity": effective_severity})
                vulns.append({"type": s["type"], "content": content, "severity": effective_severity})
                
        # 3. CVE Matching & Leak Probing (Ghost v4 Intel)
        cves = self.vuln_intel.get_cves_for_stack(tech_stack)
        leaks = self.leaks.probe_domain(domain)
        
        intel_score = self.vuln_intel.calculate_tech_risk(tech_stack)
        intel_score += self.leaks.get_risk_impact(leaks)
        
        if cves:
            console.print(f"[bold red][!] Intelligence Alert: Found {len(cves)} potential CVEs for detected stack.[/bold red]")
            for cve in cves:
                self.db.add_finding(domain, f"Intel-Match: {cve['id']} ({cve['desc']})", "Vulnerability-Intel", campaign_id=campaign_id)
        
        if leaks:
             console.print(f"[bold red][!] Intelligence Alert: Found {len(leaks)} leaked credentials for domain.[/bold red]")
             for leak in leaks:
                 self.db.add_finding(domain, f"Leak-Match: {leak['email']} ({leak['leak']})", "Credential-Leak", campaign_id=campaign_id)

        # Update target risk score in DB
        priority = "CRITICAL" if intel_score > 5000 else "HIGH" if intel_score > 2000 else "MEDIUM" if intel_score > 500 else "LOW"
        self.db.save_target({"value": domain, "risk_score": intel_score, "priority": priority})

        # 4. Ask the Brain for a multi-step plan with captured intel
        await self.broadcast("Formulating strategic battle plan...", type="status", icon="brain")
        context = {
            "target": domain, 
            "capability": "full_zenith_arsenal", 
            "waf_detected": self.stealth.active_waf,
            "tech_stack": tech_stack,
            "cve_matches": [cve["id"] for cve in cves],
            "osint_intel": intel_data
        }
        plan_raw = self.brain.reason(context)
        
        console.print(f"[cyan][*] Ghost v4 Plan formulated with Intelligence. Executing chain...[/cyan]")
        self.db.log_action("PLAN_FORMULATED", domain, f"Plan size: {len(plan_raw)}", campaign_id)
        # Step 3: Deep AI Audit (Vanguard Standard)
        await self.broadcast(f"Unleashing Nexus Deep Crawler on {len(discovered_urls)} entry points...", type="status", icon="link")
        
        visited_global = set()
        
        dast_tasks = []
        # Velocity v14.4: Cap at 5 primary entry points and depth 1 for speed
        for d_url in discovered_urls[:5]: 
            async def _d(u):
                async with self.dast_semaphore:
                    return await self.dast.scan_target(u, depth=1, visited=visited_global)
            dast_tasks.append(_d(d_url))
            
        if dast_tasks:
            dast_results = await asyncio.gather(*dast_tasks)
            for r in dast_results:
                if r: vulns.extend(r)
        
        # Step 3.5: Singularity Autonomous CoT Attack (Phase 18)
        await self.broadcast("Unleashing Aura Singularity: Initiating Autonomous CoT & XHR Interception...", type="status", icon="volcano")
        
        singularity_tasks = []
        for d_url in discovered_urls[:3]: # Velocity v14.4: Limit Singularity entry points
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

        # Step 4: Strategic Exploit
        if state.is_halted(): return {"status": "aborted"}

        if vulns:
            console.print(f"[bold red][!!!] ZENITH ALERT: {len(vulns)} vulnerabilities found. Initiating AI-Verified exfiltration...[/bold red]")
            await self.broadcast(f"Detected {len(vulns)} vulnerabilities. Analyzing impact...", type="alert", level="critical", icon="skull-crossbones")
            for v in vulns:
                # Map technical findings to professional report types
                severity = v.get("severity") or self.brain.calculate_impact(v['type'], v.get("content", ""))
                self.db.add_finding(domain, v.get("content", f"AI-Verified: {v['type']}"), v['type'], campaign_id=campaign_id, proof=v.get("proof"))
                self.db.update_finding_metadata(domain, v.get("content", ""), severity)
                self.db.log_action("VULN_FOUND", domain, f"Type: {v['type']} ({severity})", campaign_id)
                # Attempt safe exfil for proven findings
                if "SQL Injection" in v["type"]:
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

        # v6.0: Phase 5 — PoCEngine: Deterministic verification of all findings
        console.print("[bold red][*] Phase 5: v6.0 PoC Engine — Deterministic Exploitation Verification...[/bold red]")
        await self.poc_engine.verify_all(target_url, vulns)

        # Step 5: Aura Forge Plugins (Community/Custom Intelligence)
        if self.plugins:
            console.print(f"[bold magenta][*] Step 5+: Executing {len(self.plugins)} Forge plugins...[/bold magenta]")

            for plugin in self.plugins:
                plugin_result = await plugin.run(domain, {"waf": self.stealth.active_waf, "vulns": vulns, "tech": tech_stack})
                if plugin_result:
                    console.print(f"[bold magenta][Forge:{plugin.name}][/bold magenta] Finding: {plugin_result.get('finding')}")
                    self.db.add_finding(domain, plugin_result.get('finding'), f"Forge-{plugin.name}", campaign_id=campaign_id)

        # Step 6: Recalculate Risk Score and Priority based on findings
        if vulns:
            console.print("[cyan][*] Recalculating target risk score based on active findings...[/cyan]")
            final_risk = intel_score
            for v in vulns:
                v_type = v.get("type", "").lower()
                conf = v.get("confidence", "").upper()
                
                weight = 100
                severity = v.get("severity", "").upper()
                if not severity:
                    severity = self.brain.calculate_impact(v_type, v.get("content", ""))
                
            # v2.0: CVSS v3.1 Risk Score — use the maximum CVSS score found across all findings
            # This replaces arbitrary 'weight' scoring with a globally standardized metric
            cvss_scores = [v.get("cvss_score", 0.0) for v in vulns if v.get("cvss_score")]
            final_risk = round(max(cvss_scores), 1) if cvss_scores else 0.0
            
            # CVSS v3.1 Priority Bands
            if final_risk >= 9.0:
                final_priority = "CRITICAL (CVSS 9.0+)"
            elif final_risk >= 7.0:
                final_priority = "HIGH (CVSS 7.0-8.9)"
            elif final_risk >= 4.0:
                final_priority = "MEDIUM (CVSS 4.0-6.9)"
            elif final_risk > 0:
                final_priority = "LOW (CVSS 0.1-3.9)"
            else:
                final_priority = "NONE"
            
            self.db.save_target({"value": domain, "risk_score": final_risk, "priority": final_priority})
            console.print(f"[bold red][!] CVSS v3.1 Risk Score: {final_risk}/10.0 ({final_priority})[/bold red]")
            
        console.print("[bold green][✔] NeuralOrchestrator: Mission complete.[/bold green]")
        self.db.log_action("MISSION_COMPLETE", domain, "NeuralOrchestrator chain finished", campaign_id)
        return {"plan": plan_raw, "findings": vulns, "waf": self.stealth.active_waf, "techs": tech_stack}

