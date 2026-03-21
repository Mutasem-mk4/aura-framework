import asyncio
import json
import os
import tempfile
import shutil
from rich.console import Console
from aura.core import state

from aura.ui.formatter import console

class NucleiEngine:
    """
    v35.0: The Heavy Artillery.
    Leverages ProjectDiscovery's Nuclei for massive CVE scanning and template-based exploitation.
    """
    
    def __init__(self):
        self.nuclei_path = self._find_nuclei()
        self.is_installed = bool(self.nuclei_path)
        if not self.is_installed:
            console.print("[bold red][!] Nuclei Engine: 'nuclei' binary not found in PATH or ~/go/bin. CVE scanning will be disabled.[/bold red]")
            console.print("[dim yellow]    Hint: Install it with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest[/dim yellow]")
            
    def _find_nuclei(self) -> str | None:
        path = shutil.which("nuclei")
        if path: return path
        go_path = os.path.expanduser("~/go/bin/nuclei.exe")
        if os.path.exists(go_path): return go_path
        go_path_unix = os.path.expanduser("~/go/bin/nuclei")
        if os.path.exists(go_path_unix): return go_path_unix
        return None

    async def scan(self, target: str) -> list:
        if not self.is_installed:
            return []
            
        console.print(f"[bold cyan][☢️ Nuclei Engine] Launching deep CVEs & Misconfiguration scan on {target}...[/bold cyan]")
        
        # Temp file for JSONL output
        fd, tmp_path = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        
        findings = []
        try:
            from aura.core import state
            
            # Base stealth flags
            stealth_flags = [
                "-rl", "5",       # Rate limit to 5 req/sec
                "-c", "2",        # Max concurrency 2
                "-timeout", "10", # 10s connection timeout
                "-delay", "2"     # 2 second delay between requests
            ]
            
            # Apply dynamic User-Agent via custom headers or random agent
            # We'll use Nuclei's built in header flag or random-agent
            stealth_flags.extend(["-random-agent"])
            for header, val in state.CUSTOM_HEADERS.items():
                stealth_flags.extend(["-H", f"{header}: {val}"])

            cmd = [
                self.nuclei_path,
                "-u", target,
                # Limiting to high impact templates to keep scans fast and relevant for bounty
                "-t", "cves,vulnerabilities,misconfiguration,exposures",
                "-jsonl", "-silent",
                "-o", tmp_path
            ]
            
            if not state.FAST_MODE:
                cmd.extend(stealth_flags)
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Wait for nuclei to finish. This might take a while, but it's parallelized internally by nuclei.
            await proc.communicate()
            
            # Read and parse JSONL output
            if os.path.exists(tmp_path) and os.path.getsize(tmp_path) > 0:
                with open(tmp_path, "r", encoding="utf-8") as f:
                    for line in f:
                        if not line.strip(): continue
                        try:
                            data = json.loads(line)
                            finding = self._parse_nuclei_finding(data, target)
                            if finding:
                                findings.append(finding)
                        except json.JSONDecodeError:
                            continue
                        
            if findings:
                console.print(f"[bold red][☢️ Nuclei] Discovered {len(findings)} vulnerabilities via templates![/bold red]")
            else:
                console.print(f"[dim][☢️ Nuclei] Clean: No vulnerabilities found via selected templates.[/dim]")
                
        except Exception as e:
            console.print(f"[dim red][☢️ Nuclei Engine] Error running nuclei: {e}[/dim red]")
        finally:
            if os.path.exists(tmp_path):
                try: os.remove(tmp_path)
                except: pass
                
        return findings

    def _parse_nuclei_finding(self, data: dict, target: str) -> dict:
        info = data.get("info", {})
        metadata = info.get("metadata", {})
        
        severity = info.get("severity", "medium").upper()
        # Filter out purely informational or low findings if desired, but we'll keep them for completeness
        
        name = info.get("name", "Nuclei Generic Finding")
        description = info.get("description", "No description provided.")
        template_id = data.get("template-id", "")
        
        # Format a professional evidence string
        evidence = f"Nuclei Template ID: {template_id}\nAttack Name: {name}\n\nDescription: {description}\n\nMatched URL: {data.get('matched-at', '')}"
        
        poc_link = ""
        # Provide curl command as PoC if available
        if "curl-command" in data:
            evidence += f"\n\nCurl Extract (Reproduction):\n```bash\n{data['curl-command']}\n```"
            poc_link = data["curl-command"]
        else:
            poc_link = data.get("matched-at", "")

        cvss_score = metadata.get("cvss-score", 0.0)
        
        return {
            "type": f"Nuclei - {template_id}",
            "finding_type": "CVE/Misconfiguration (Nuclei)",
            "severity": severity,
            "owasp": "A06:2021 – Vulnerable and Outdated Components",
            "mitre": "T1190 – Exploit Public-Facing Application",
            "content": evidence,
            "url": data.get("matched-at", target),
            "confirmed": True,
            "poc_evidence": evidence,
            "cvss_score": cvss_score,
            "poc_link": poc_link
        }
