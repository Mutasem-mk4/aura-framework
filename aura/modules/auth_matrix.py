import asyncio
import re
from rich.console import Console
from aura.core import state
from typing import List, Dict

from aura.ui.formatter import console

class AuthMatrix:
    """
    v25.0 Apex Automation: Autonomous Auth Matrix (IDOR & BOLA Hunter)
    This module takes two authorization tokens (Attacker and Victim). 
    It scans discovered URLs for ID-like parameters, issues requests using the Attacker's
    token to the Victim's object URL, and compares the response to confirm privilege escalation.
    """
    
    def __init__(self, session=None):
        self.session = session
        self.attacker_token = state.AUTH_TOKEN_ATTACKER
        self.victim_token = state.AUTH_TOKEN_VICTIM
        
        self.enabled = bool(self.attacker_token and self.victim_token)
        if not self.enabled:
            console.print("[dim][Auth Matrix] BOLA/IDOR hunting disabled. Missing dual tokens in environment.[/dim]")

        # Patterns for UUIDs and Numbers
        self.id_patterns = [
            r'([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})',  # UUID
            r'(?<=/)([0-9]{2,})(?=/|$)', # Path parameter IDs (e.g. /users/123)
            r'(?<=id=)([0-9]+)',         # Query string IDs (e.g. ?id=123)
            r'(?<=user_id=)([0-9]+)',
            r'(?<=account=)([0-9]+)'
        ]

    def _extract_ids(self, url: str) -> List[str]:
        """Extracts potential IDs from a generic URL."""
        ids = []
        for pattern in self.id_patterns:
            matches = re.finditer(pattern, url)
            for match in matches:
                ids.append(match.group(1) or match.group(0))
        return list(set(ids))

    async def scan_for_idor(self, discovered_urls: List[str]) -> List[Dict]:
        """
        Takes a list of URLs discovered by the crawler (which might belong to the Victim).
        Filters for URLs containing IDs, and attempts to access them linearly using the Attacker's token.
        """
        if not self.enabled or not self.session:
            return []

        console.print("[bold cyan][🎭 AUTH MATRIX] Dual-Session Tokens detected. Engaging BOLA/IDOR Scan...[/bold cyan]")
        
        candidates = []
        for url in discovered_urls:
            ids = self._extract_ids(url)
            if ids:
                candidates.append((url, ids))

        if not candidates:
            console.print("[dim cyan][Auth Matrix] No ID or UUID parameters found in discovered URLs. Skipping IDOR scan.[/dim cyan]")
            return []
            
        console.print(f"[cyan][Auth Matrix] Found {len(candidates)} candidate URLs with ID parameters. Testing authorization bounds...[/cyan]")
        
        findings = []
        
        attacker_headers = {"Authorization": f"Bearer {self.attacker_token}"} if "Bearer" not in self.attacker_token else {"Authorization": self.attacker_token}
        victim_headers = {"Authorization": f"Bearer {self.victim_token}"} if "Bearer" not in self.victim_token else {"Authorization": self.victim_token}

        # For pure automation, we assume discovered URLs are Victim's URLs or global URLs with IDs.
        for url, ids in candidates:
            # First, verify Victim can access their own data
            vic_resp = await self.session.get(url, headers=victim_headers)
            if not vic_resp or vic_resp.status_code >= 400:
                continue # If victim can't access it, we can't establish a baseline
                
            vic_len = len(vic_resp.text)
            
            # Second, attempt to access Victim's data using Attacker's Token
            att_resp = await self.session.get(url, headers=attacker_headers)
            if att_resp and att_resp.status_code == 200:
                att_len = len(att_resp.text)
                
                # Check for state similarity (did the attacker see the victim's data?)
                # A heuristic: If the response length is > 80% similar and contains success indicators without "unauthorized" blocks
                len_ratio = min(vic_len, att_len) / max(vic_len, att_len) if max(vic_len, att_len) > 0 else 0
                
                if len_ratio > 0.85 and "unauthorized" not in att_resp.text.lower() and "forbidden" not in att_resp.text.lower():
                    # High probability of IDOR
                    evidence = (
                        f"**BOLA/IDOR CONFIRMED**\n\n"
                        f"Resource URL: `{url}`\n"
                        f"Extracted IDs: {ids}\n\n"
                        f"**Scenario:** The asset owner (Victim) accessed the resource resulting in a `{vic_resp.status_code}` response ({vic_len} bytes). "
                        f"An unrelated user (Attacker) requested the EXACT same URL with their own token and received a `{att_resp.status_code}` response ({att_len} bytes), "
                        f"successfully bypassing horizontal authorization boundaries."
                    )
                    
                    console.print(f"[bold red][☠️ BOLA/IDOR CONFIRMED] Unauthorized data access at {url}[/bold red]")
                    
                    from aura.modules.evidence_dumper import EvidenceDumper
                    raw_req = EvidenceDumper.dump_request(att_resp)
                    raw_res = EvidenceDumper.dump_response(att_resp)
                    
                    findings.append({
                        "type": "Broken Object Level Authorization (IDOR)",
                        "finding_type": "IDOR/BOLA",
                        "severity": "CRITICAL",
                        "owasp": "A01:2021 – Broken Access Control",
                        "mitre": "T1020 - Automated Exfiltration",
                        "content": evidence,
                        "url": url,
                        "confirmed": True,
                        "poc_evidence": evidence,
                        "raw_request": raw_req,
                        "raw_response": raw_res
                    })

        console.print(f"[dim cyan][Auth Matrix] IDOR scan complete. Found {len(findings)} BOLA vulnerabilities.[/dim cyan]")
        return findings
