import asyncio
import os
import shutil
import json
import random
from rich.console import Console

console = Console()

class FfufEngine:
    """
    v21.0 The Go-Arsenal: Ffuf Fuzzing Engine
    Replaces the pure-Python DirBuster with the blazing-fast Go binary `ffuf`.
    Integrates deeply with the custom SecLists `raft-large` dictionary.
    """
    def __init__(self):
        import shutil
        def find_ffuf():
            path = shutil.which("ffuf")
            if path: return path
            go_path = os.path.expanduser("~/go/bin/ffuf.exe")
            if os.path.exists(go_path): return go_path
            return None
            
        self._ffuf_path = find_ffuf()
        self._has_ffuf = self._ffuf_path is not None
        
        # Wordlist configuration (Phase 1 legacy)
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.wordlist_dir = os.path.join(base_dir, "resources", "wordlists")
        self.assetnote_dir = os.path.join(self.wordlist_dir, "assetnote")
        self.default_wordlist = os.path.join(self.wordlist_dir, "raft-large-directories.txt")
        self.wordlist_path = self.default_wordlist
        
        # Load Assetnote Manifest
        self.manifest = {}
        manifest_path = os.path.join(self.assetnote_dir, "manifest.json")
        if os.path.exists(manifest_path):
            with open(manifest_path, "r") as f:
                self.manifest = json.load(f).get("mappings", [])
        
        if not os.path.exists(self.wordlist_path):
            console.print("[dim red][!] SecLists wordlist not found. Ffuf will fail without a dictionary.[/dim red]")
            
        self.user_agents = [
             "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
             "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
             "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        ]

    async def run_fuzz(self, target_url: str, tech_stack: list = None, fast_mode: bool = False, swarm_mode: bool = False) -> list[str]:
        """
        Executes an ultra-fast FFUF attack.
        Automatically selects the best wordlist based on the tech_stack.
        """
        if not self._has_ffuf:
            console.print("[dim yellow][!] FFUF binary not found on PATH. Ensure FFUF is installed for Phase 4 speeds![/dim yellow]")
            return []
            
        # v22.0 Assetnote Intelligence: Select optimal wordlist
        selected_wordlist = self.default_wordlist
        if tech_stack:
            for tech in tech_stack:
                for mapping in self.manifest:
                    if mapping["tech"].lower() in str(tech).lower():
                        potential_path = os.path.join(self.assetnote_dir, mapping["wordlist"])
                        if os.path.exists(potential_path):
                            selected_wordlist = potential_path
                            console.print(f"[bold cyan][⚡] ASSETNOTE INTELLIGENCE: Optimized target detected ({tech}). Matching wordlist: {mapping['wordlist']}[/bold cyan]")
                            break
                if selected_wordlist != self.default_wordlist:
                    break
        
        if not os.path.exists(selected_wordlist):
            console.print(f"[dim red][!] Wordlist missing: {selected_wordlist}. Falling back to default.[/dim red]")
            selected_wordlist = self.default_wordlist
            
        # v27.0: Context-Aware Smart Wordlists (AI Generated)
        ai_wordlist = []
        if tech_stack:
            from aura.core.brain import AuraBrain
            brain = AuraBrain()
            if brain.enabled:
                prompt = (
                    f"Generate a highly specific, deeply hidden bug bounty directory fuzzing wordlist "
                    f"for a target running: {', '.join(tech_stack)}. "
                    f"Focus on configuration files, backup files, exposed API endpoints, and development debug panels specific to this stack. "
                    f"Return ONLY the raw paths, one per line. No markdown formatting, no explanations. Max 50 paths."
                )
                try:
                    console.print(f"[cyan][🧠] AI BRAIN: Synthesizing Context-Aware Smart Wordlist for {tech_stack}...[/cyan]")
                    ai_response = await asyncio.to_thread(brain._call_ai, prompt)
                    if ai_response:
                        ai_paths = [p.strip().strip('`').strip('/') for p in ai_response.splitlines() if p.strip() and not p.startswith('#')]
                        ai_wordlist = [path for path in ai_paths if 1 < len(path) < 50]
                        console.print(f"[bold magenta][⚡] SHIVA ENGINE: Injected {len(ai_wordlist)} AI-Generated Target-Specific Paths into fuzz queue![/bold magenta]")
                except Exception as e:
                    pass
            
        if not os.path.exists(selected_wordlist):
            return []

        from aura.core import state
        if target_url:
            from urllib.parse import urlparse as _up
            _h = _up(target_url).netloc
            if state.is_dns_failed(_h):
                console.print(f"[dim yellow][!] Ffuf skipped: Target host is in DNS global failure state.[/dim yellow]")
                return []

        # Ensure trailing slash for FUZZ keyword
        url = target_url.rstrip('/') + "/FUZZ"
        console.print(f"[bold red][🔥] FFUF ENGINE: Launching hyper-speed DirBuster against {target_url}[/bold red]")

        # Determine slicing based on mode
        limit = 5000
        if swarm_mode:
            limit = 500
        elif fast_mode:
            limit = 1500

        # Create a temporary sliced wordlist for ffuf to read
        temp_wordlist = os.path.join(self.wordlist_dir, "temp_fuzz.txt")
        try:
            # v22.3 Robust Read: Try UTF-8-sig (supports BOM) then UTF-8
            raw_data = None
            for enc in ["utf-8-sig", "utf-8", "latin-1"]:
                try:
                    with open(selected_wordlist, "r", encoding=enc) as f:
                        raw_data = f.readlines()
                        break
                except UnicodeDecodeError: continue
            
            if not raw_data:
                console.print(f"[dim red][!] Failed to read wordlist with any encoding.[/dim red]")
                return []

            with open(temp_wordlist, "w", encoding="utf-8", newline="\n") as f_out:
                count = 0
                
                # v27.0: Inject AI Smart Wordlist at the very top (highest priority)
                for path in ai_wordlist:
                    f_out.write(path + "\n")
                    count += 1
                    
                for line in raw_data:
                    if count >= limit: break
                    clean = line.strip().strip('/')
                    if clean and not clean.startswith("#"):
                        f_out.write(clean + "\n")
                        count += 1
            
            if not os.path.exists(temp_wordlist) or os.path.getsize(temp_wordlist) == 0:
                console.print(f"[dim red][!] Sliced wordlist is empty. Skipping Ffuf.[/dim red]")
                return []
        except Exception as e:
            console.print(f"[dim red][!] Failed to slice wordlist: {e}[/dim red]")
            return []

        discovered_urls = []
        import tempfile
        out_file = tempfile.mktemp(suffix=".json")
        
        try:
            ua = random.choice(self.user_agents)
            
            # -ac: Auto-calibrate filtering (skips false positives!)
            # -t: threads (throttle in swarm mode)
            # -c: color
            # -maxtime: global timeout
            threads = "40" if swarm_mode else "150"
            
            cmd = [
                self._ffuf_path, 
                "-w", temp_wordlist,
                "-u", url,
                "-t", threads,
                "-H", f"User-Agent: {ua}",
                "-ac", # Automatically calibrate filtering based on a random fake request
                "-s",  # Silent mode
                "-o", out_file,
                "-of", "json",
                "-dns", "8.8.8.8", # v27.0: Fix "DNS global failure state"
                "-maxtime", "300" 
            ]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            
            await proc.wait()
            
            if os.path.exists(out_file):
                with open(out_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for item in data.get("results", []):
                        hit_url = item.get("url")
                        status = item.get("status")
                        if hit_url and status in [200, 301, 302, 403]:
                             discovered_urls.append(hit_url)
                             console.print(f"[green][+] FFUF Predator Hit: {hit_url} ({status})[/green]")
                             
            return discovered_urls

        except Exception as e:
            console.print(f"[dim red][!] FFUF encountered an error: {e}[/dim red]")
            return []
        finally:
            # Cleanup
            if os.path.exists(temp_wordlist):
                try: os.remove(temp_wordlist)
                except: pass
            if os.path.exists(out_file):
                try: os.remove(out_file)
                except: pass
