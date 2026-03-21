import asyncio
import json
import logging
from typing import Dict, List, Any, Optional
from rich.console import Console

from aura.core.brain import AuraBrain

logger = logging.getLogger("aura")
from aura.ui.formatter import console

class LogicHunter:
    """
    v37.0: The Business Logic Engine (AI Taint Analysis)
    Designed to intercept state-changing requests and use Gemini to generate BOLA, IDOR, 
    and Business Logic manipulation payloads (e.g. negative prices, parameter pollution).
    """
    def __init__(self, session):
        self.session = session
        self.brain = AuraBrain()

    async def scan_mutations(self, target_url: str, method: str, body_str: str, headers: Dict[str, str] = None) -> List[Dict]:
        """Scans a specific state-changing request by generating and sending logic-flaw payloads."""
        if not self.brain.enabled:
            return []

        console.print(f"[bold magenta][⚡] Logic Hunter: Analyzing {method} {target_url}...[/bold magenta]")
        
        # Step 1: Synthesize context for the AI
        schema_context = f"Method: {method}\nURL: {target_url}\nHeaders: {json.dumps(headers or {})}\nBody: {body_str}"
        
        # Step 2: Use the newly introduced BUSINESS_LOGIC_PROMPT defined in brain.py
        payloads = self._generate_logic_payloads(schema_context)
        if not payloads:
            return []
            
        console.print(f"[magenta][*] Logic Hunter: AI generated {len(payloads)} logic-mutant payloads. Executing...[/magenta]")
        
        findings = []
        for payload_str in payloads:
            f = await self._execute_and_verify(target_url, method, payload_str, headers)
            if f:
                findings.append(f)
                
        return findings

    def _generate_logic_payloads(self, schema_context: str) -> List[str]:
        """Calls AuraBrain to generate specialized malicious bodies."""
        prompt = (
            f"You are AURA Logic Hunter. Analyze this HTTP request and return a JSON array of strings, "
            f"where each string is a strictly valid JSON body mutant designed to test for Business Logic Flaws.\n"
            f"Focus on:\n"
            f"1. IDOR/BOLA (Change IDs to bypass authorization).\n"
            f"2. Financial bypass (Negative quantities, high/low limits).\n"
            f"3. Mass Assignment (Add 'is_admin': true, 'role': 1, 'account_balance': 9999).\n"
            f"4. Type Confusion (Send arrays instead of strings).\n\n"
            f"Request Context:\n{schema_context[:2000]}\n\n"
            f"Return ONLY valid JSON array of JSON string bodies, e.g. [\"{{\\\"id\\\": 2}}\", \"{{\\\"qty\\\": -1}}\"]. No markdown, no explanations."
        )
        
        try:
            raw_response = self.brain._call_ai(prompt, use_cache=False) # Always generate fresh logic
            if not raw_response:
                return []
            
            # Ensure it's a valid JSON array
            response_text = raw_response.strip()
            if response_text.startswith("```json"):
                response_text = response_text[7:-3].strip()
            elif response_text.startswith("```"):
                response_text = response_text[3:-3].strip()

            mutations = json.loads(response_text)
            if isinstance(mutations, list):
                return [m if isinstance(m, str) else json.dumps(m) for m in mutations]
            return []
        except Exception as e:
            logger.error(f"Logic Hunter AI parsing failed: {e}")
            return []

    async def _execute_and_verify(self, url: str, method: str, payload_str: str, headers: Dict) -> Optional[Dict]:
        """Sends the mutated request and checks if the backend accepted the manipulated state."""
        try:
            req_headers = dict(headers) if headers else {}
            req_headers['Content-Type'] = 'application/json'
            
            async with self.session.request(method, url, data=payload_str, headers=req_headers, timeout=10) as r:
                body = await r.text()
                
                # Logic Flaw Detection Heuristics:
                # 1. 200/201 OK on negative/malformed data that should be rejected
                # 2. Returning administrative keys in the body
                # 3. Successful JSON response with changed state and no "error" or "invalid" keys
                
                if r.status in [200, 201]:
                    body_lower = body.lower()
                    if "error" not in body_lower and "invalid" not in body_lower:
                        return {
                            "type": "Business Logic Vulnerability",
                            "severity": "HIGH",
                            "content": f"Logic bypass successful via Payload: {payload_str}\nStatus: {r.status}\nResponse snippet: {body[:300]}"
                        }
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            logger.debug(f"Logic Hunter connection error: {e}")
        return None
