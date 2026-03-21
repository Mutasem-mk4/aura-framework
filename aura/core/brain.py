import logging
import json
import random
import os
import re
import asyncio
import time
from typing import Dict, Any, Optional, List

import httpx
from google import genai
from rich.console import Console
from aura.core import state

from aura.ui.formatter import console

logger = logging.getLogger("aura")

class AuraBrain:
    """The 'Sentient' intelligence layer powered by Gemini for strategic offensive reasoning."""
    
    SYSTEM_PROMPT = (
        "You are AURA-Zenith Singularity, the ultimate autonomous offensive AI agent. "
        "Your mission is to perform deep, chain-of-thought (CoT) security analysis. "
        "You don't just fuzz inputs; you intercept network traffic, analyze DOM structures, "
        "and identify complex logic flaws (BOLA, IDOR, Privilege Escalation). "
        "You maintain tactical memory of all probes to refine your strategy iteratively. "
        "When generating payloads, you provide 3 levels of escalation, including Ghost v6 fragmented evasion. "
        "Respond ONLY in requested formats. Always be technical, concise, and lethal."
    )

    REASONING_PATTERNS = {
        "admin": "Administrative panels are entry points for lateral movement and credential harvesting. Recommendation: Brute-force discovery of sub-directories (/admin, /wp-admin) or check for default credentials.",
        "jenkins": "Jenkins instances often contain CI/CD secrets and SSH keys. If accessed, it could lead to a full Supply Chain compromise.",
        "api": "Unprotected APIs often suffer from Broken Object Level Authorization (BOLA). Recommendation: Fuzz endpoints for IDOR vulnerabilities and parameter pollution.",
        "logic_flaw": "State-changing APIs (POST/PUT) handling quantities, prices, or roles can be bypassed. Mutate numeric values to negative/overflow bounds and append highly privileged boolean flags.",
        "staging": "Staging environments are often less protected than production and may contain legacy data, debug symbols, or weaker auth configs.",
        "docker": "Exposed Docker registries or sockets can lead to container escape and host takeover. Check for /v2/_catalog.",
        "vpn": "VPN endpoints are high-value targets for initial access. Recommendation: Check for known CVEs in the underlying software (Pulse Secure, Fortinet, etc.) and perform credential stuffing.",
        "idor": "IDOR vulnerabilities occur when an application provides direct access to objects based on user-supplied input. Recommendation: Mutate resource IDs to access other users' data.",
        "bola": "BOLA (Broken Object Level Authorization) is critical in modern APIs. Recommendation: Attempt to access, modify, or delete resources belonging to other users by manipulating object IDs in requests.",
        "race_condition": "Race conditions occur when multiple processes access shared data concurrently. Recommendation: Concurrent requests to state-changing endpoints like /withdraw, /transfer, or /redeem."
    }

    def __init__(self):
        self.enabled = False
        self.tactical_memory: List[str] = [] # Phase 18: Tactical Memory
        self.payload_cache: Dict[str, str] = {}  # Initialize payload cache for Level 1 & 2
        self.ai_cache: Dict[str, str] = {} # v19.2: General AI query cache
        self.active_provider: Optional[str] = None
        
        # Zero-Cost Local AI (Ollama) - MANDATORY PRIORITY
        ollama_host = state.OLLAMA_HOST or os.environ.get("OLLAMA_HOST")
        if ollama_host:
            self.enabled = True
            self.active_provider = "ollama"
            ollama_model = state.OLLAMA_MODEL or os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:7b")
            logger.info(f"AuraBrain Singularity: Local Ollama Engine online at {ollama_host} (model: {ollama_model})")
        
        # Primary Gemini SDK - Fallback
        gemini_key = state.GEMINI_API_KEY or os.environ.get("GEMINI_API_KEY")
        if gemini_key:
            try:
                self.client = genai.Client(api_key=gemini_key)
                self.enabled = True
                if not self.active_provider:
                    self.active_provider = "gemini"
                logger.info("AuraBrain Singularity: Gemini Engine initialized as fallback.")
            except Exception as e:
                logger.debug(f"AuraBrain: Optional Gemini init failed: {e}")
        
        # OpenRouter Free Mode - Fallback
        if state.OPENROUTER_API_KEY:
            self.enabled = True
            if not self.active_provider:
                self.active_provider = "openrouter"
            logger.info("AuraBrain Singularity: OpenRouter Free-Tier Engine available.")

    def _call_ai(self, prompt, system_instruction=None, use_cache=True):
        """v25.0 OMEGA: Multi-Model Router with local-first priority."""
        if not self.enabled: return None
        if use_cache and prompt in self.ai_cache:
            return self.ai_cache[prompt]

        # Strategic Order: Ollama (Local) -> Gemini -> OpenRouter
        providers = []
        if state.OLLAMA_HOST: providers.append("ollama")
        if state.GEMINI_API_KEY: providers.append("gemini")
        if state.OPENROUTER_API_KEY: providers.append("openrouter")

        # Ensure the currently active provider is tried first if it's in our valid list
        if self.active_provider and self.active_provider in providers:
            providers.remove(self.active_provider)
            providers.insert(0, self.active_provider)

        for provider in providers:
            try:
                res = None
                if provider == "ollama":
                    res = self._call_ollama(prompt, system_instruction, use_cache)
                elif provider == "gemini":
                    res = self._call_gemini_sdk(prompt, system_instruction, use_cache)
                elif provider == "openrouter":
                    # Try all models in the stack
                    for model_id in state.ZENITH_FREE_STACK:
                        res = self._call_openrouter_free(model_id, prompt, system_instruction, use_cache)
                        if res: break
                
                if res:
                    if use_cache: self.ai_cache[prompt] = res
                    return res
            except Exception as e:
                logger.warning(f"AuraBrain: Provider '{provider}' failed: {e}. Failing over...")
                continue
        
        return None

    def _call_gemini_sdk(self, prompt, system_instruction=None, use_cache=True):
        """Direct Gemini SDK call."""
        max_retries = 2
        for attempt in range(max_retries):
            try:
                response = self.client.models.generate_content(
                    model=state.GEMINI_MODEL,
                    contents=prompt,
                    config={'system_instruction': system_instruction or self.SYSTEM_PROMPT}
                )
                if not response or not response.text: continue
                res_text = response.text.strip().replace("```json", "").replace("```", "").strip()
                return res_text
            except Exception as e:
                if "400" in str(e) or "API key not valid" in str(e) or "401" in str(e):
                    logger.warning(f"AuraBrain: Gemini API Key Invalid/Expired (400). Circuit Breaker Activated, Disabling AI...")
                    self.enabled = False
                    return None
                if attempt == max_retries - 1:
                    logger.error(f"AuraBrain: Gemini SDK Error: {e}")
                    break
                time.sleep(1 + random.uniform(0.1, 0.5))
        return None

    def _call_openrouter_free(self, model_id, prompt, system_instruction=None, use_cache=True):
        """OpenRouter Free API interaction via HTTP."""
        url = "https://openrouter.ai/api/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {state.OPENROUTER_API_KEY}",
            "HTTP-Referer": "https://github.com/Mutasem-mk4/Aura",
            "Content-Type": "application/json"
        }
        payload = {
            "model": model_id,
            "messages": [
                {"role": "system", "content": system_instruction or self.SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ]
        }
        try:
            with httpx.Client(timeout=state.NETWORK_TIMEOUT) as client:
                resp = client.post(url, headers=headers, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    res_text = data['choices'][0]['message']['content'].strip()
                    res_text = res_text.replace("```json", "").replace("```", "").strip()
                    return res_text
        except Exception:
            pass
        return None

    def _call_ollama(self, prompt, system_instruction=None, use_cache=True):
        """v25.0 OMEGA: Local Ollama Engine with 300s timeout."""
        url = f"{state.OLLAMA_HOST}/api/generate"
        payload = {
            "model": state.OLLAMA_MODEL,
            "prompt": f"{system_instruction or self.SYSTEM_PROMPT}\n\nUser: {prompt}\nAI:",
            "stream": False
        }
        try:
            # v25.0: Extended timeout for deep reasoning
            with httpx.Client(timeout=300) as client:
                resp = client.post(url, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    res_text = data.get('response', '').strip()
                    res_text = res_text.replace("```json", "").replace("```", "").strip()
                    return res_text
                else:
                    logger.warning(f"Ollama returned HTTP {resp.status_code}: {resp.text[:200]}")
        except httpx.ConnectError:
            self.enabled = False
            console.print(f"[bold yellow][!] Ollama Offline:[/bold yellow] Cannot reach {state.OLLAMA_HOST}. Circuit Breaker Activated.")
            logger.error(f"Ollama connection refused at {state.OLLAMA_HOST}. Ensure Ollama is running: `ollama serve`")
        except httpx.TimeoutException:
            self.enabled = False
            console.print(f"[bold yellow][!] Ollama Timeout:[/bold yellow] Model [cyan]{state.OLLAMA_MODEL}[/cyan] took too long. Circuit Breaker Activated.")
            logger.error(f"Ollama inference timed out for model {state.OLLAMA_MODEL}")
        except Exception as e:
            logger.error(f"Ollama inference failed (Unexpected Error): {e}")
        return None

    def autonomous_plan(self, url: str, dom_context: str, network_context: list) -> dict:
        """Ghost v6: Autonomous Chain-of-Thought planning with Sentinel-G Resilience."""
        if not self.enabled: return {"plan": "Standard Fuzzing", "reasoning": "AI Offline"}
        
        prompt = (
            f"As AURA-Zenith, analyze the state of {url}.\n"
            f"DOM: {dom_context[:1500]}\n"
            f"Network: {network_context[:10]}\n"
            f"Memory: {self.tactical_memory[-5:]}\n\n"
            "Build a CoT plan focusing on Logic Flaws, API Auth, and Data Exposure. "
            "Respond ONLY in JSON: {'plan': 'str', 'target_vector': 'str', 'reasoning': 'str'}"
        )
        try:
            raw = self._call_ai(prompt)
            plan = self._clean_json(raw)
            if plan.get("plan"):
                self.tactical_memory.append(f"Planned: {plan.get('target_vector')}")
                return plan
            return {"plan": "Fallback Recon", "target_vector": "Unknown", "reasoning": "AI Connectivity Degraded"}
        except Exception:
            return {"plan": "Fallback Recon", "target_vector": "Unknown", "reasoning": "AI Connectivity Degraded"}

    def reason(self, target_context: dict) -> str:
        """Analyzes a target and provides strategic advice using AI or fallback rules."""
        target_value = target_context.get("target", "").lower()
        
        if self.enabled:
            try:
                prompt = (
                    f"Analyze this target context and generate a strategic offensive 'Battle Plan'.\n"
                    f"Context: {target_context}\n"
                    "Focus on specific attack vectors based on the tech stack and risk score.\n"
                    "Provide concise actionable recommendations."
                )
                res = self._call_ai(prompt)
                if res: return res
            except Exception as e:
                logger.warning(f"AuraBrain: AI query failed, falling back to rules. Error: {e}")

        insights = []
        for pattern, explanation in self.REASONING_PATTERNS.items():
            if pattern in target_value:
                insights.append(explanation)

        if not insights:
            return "General reconnaissance target. Recommendation: Perform port scanning and service enumeration to identify potential attack surface."
        
        return "\n\n".join(insights)

    def reason_json(self, prompt: str, system_instruction: Optional[str] = None) -> str:
        """v5.1 / v19.4: Synchronized JSON reasoning natively supporting Ollama."""
        if not self.enabled: return "[]"

        try:
            raw_response = self._call_ai(prompt, system_instruction=system_instruction)
            if not raw_response: return "[]"
                
            raw = raw_response.strip().replace("```json", "").replace("```", "").strip()
            if not (raw.startswith("[") or raw.startswith("{")): return "[]"
                
            import re
            raw = re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', raw)
            try:
                json.loads(raw)   # validate
            except Exception: return "[]"
            return raw
        except Exception as e:
            logger.error(f"AuraBrain JSON Reason: {e}")
            return "[]"

    def validate_vulnerability(self, finding_type: str, content: str, target: str) -> dict:
        """v33 Zenith: Second Opinion layer. Validates if a finding is likely a False Positive."""
        if not self.enabled: return {"valid": True, "confidence": "unknown", "reason": "AI Offline"}
        
        prompt = (
            f"As AURA-Zenith Security Oracle, validate this finding for {target}.\n"
            f"Type: {finding_type}\n"
            f"Finding Data: {content}\n\n"
            "Analyze if this is a high-confidence vulnerability or a false positive (e.g., informative only, non-exploitable error, standard behavior).\n"
            "Respond ONLY in JSON: {'valid': boolean, 'confidence': 'low/med/high', 'reason': 'str', 'improved_poc': 'str'}"
        )
        try:
            raw = self._call_ai(prompt, use_cache=True)
            return self._clean_json(raw)
        except Exception: 
            return {"valid": True, "confidence": "high", "reason": "Validation Error (Defaulting to Trust)"}

    def find_exploit_path(self, context: str) -> str:
        """Suggests a sequence of actions to exploit a discovered vulnerability."""
        if not self.enabled: return "Manual verification required."
        prompt = f"Given this security context: {context}\nGenerate a step-by-step exploit path for a professional report."
        try: 
            res = self._call_ai(prompt)
            return res if res else "Manual verification required."
        except: 
            return "See PoC steps in finding details."

    def validate_behavior(self, payload: str, url: str, delay_ms: int, length: int, status: int, body: str) -> Dict[str, Any]:
        """Deep behavioral analysis for Blind vulnerabilities and WAF evasion indicators."""
        if not self.enabled: return {"vulnerable": False}
        
        prompt = (
            f"As a Red Team AI, analyze this response behavior for a payload: '{payload}' on {url}.\n"
            f"Observed Latency: {delay_ms}ms | Content Length: {length} | Status: {status}\n"
            f"Response Snippet:\n{body[:800]}\n\n"
            "Is there any suspicious behavior? High latency (>3s) often indicates Blind SQLi or Command Injection. "
            "Respond ONLY in JSON: {'vulnerable': boolean, 'suspect': boolean, 'type': 'string', 'confidence': 'string', 'reason': 'string'}"
        )
        try:
            raw = self._call_ai(prompt, use_cache=True)
            if not raw: return {"vulnerable": False}
            return self._clean_json(raw)
        except Exception: return {"vulnerable": False}

    def _clean_json(self, text):
        """Helper to extract and parse JSON from AI responses."""
        import re
        match = re.search(r'(\{.*\})', text, re.DOTALL)
        if match:
            try: return json.loads(match.group(1))
            except: pass
        match = re.search(r'(\[.*\])', text, re.DOTALL)
        if match:
            try: return json.loads(match.group(1))
            except: pass
        try: return json.loads(text.strip())
        except: return {"vulnerable": False}

    def analyze_parameter_semantics(self, parameters: dict) -> list:
        """Phase 27: Analyzes parameter keys and values to suggest business logic attacks."""
        if not self.enabled or not parameters: return []
        
        prompt = (
            f"As AURA Singularity, analyze these HTTP parameters for business logic flaws (IDOR, BOLA, Privilege Escalation, Price Manipulation).\n"
            f"Parameters: {parameters}\n\n"
            "Identify parameters that look like IDs, roles, prices, permissions, or boolean flags. "
            "Suggest 1-3 specific manipulations to bypass logic or escalate privileges. "
            "Respond ONLY in JSON array: [{'parameter': 'name', 'payload': 'value', 'type': 'Logic Injection', 'reason': 'string'}]"
        )
        try:
            raw = self._call_ai(prompt)
            parsed = self._clean_json(raw)
            return parsed if isinstance(parsed, list) else []
        except Exception: return []

    def synthesize_workflow(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        v38.0 OMEGA: Autonomous Workflow Generator.
        Translates a list of discovered endpoints into a structured LogicFuzzer workflow.
        """
        if not self.enabled or not endpoints:
            return []

        console.print(f"[bold cyan]🧠 [Brain] Synthesizing autonomous workflow for {len(endpoints)} endpoints...[/bold cyan]")
        
        prompt = (
            "As AURA-Zenith, analyze these endpoints and synthesize a stateful security workflow (JSON).\n"
            "Combine related endpoints into a logical sequence (e.g., login -> profile -> update).\n"
            "Assign 'fuzz_params' and 'fuzz_types' (sqli, xss, logic, auth_bypass) based on parameter names.\n"
            f"Endpoints: {json.dumps(endpoints[:20])}\n\n"
            "Respond ONLY with a JSON array of steps, where each step follows this structure:\n"
            "{"
            "  'id': 'unique_id', 'method': 'GET/POST', 'path': '/path', "
            "  'name': 'readable_name', 'fuzz_params': [], 'fuzz_types': []"
            "}"
        )
        
        try:
            raw = self._call_ai(prompt, use_cache=False)
            workflow = self._clean_json(raw)
            return workflow if isinstance(workflow, list) else []
        except Exception as e:
            logger.error(f"AuraBrain Workflow Synthesis failed: {e}")
            return []

    def analyze_business_logic(self, request_data: dict, response_data: dict) -> list:
        """v15.0: Deep analysis of HTTP transactions for complex business logic flaws."""
        if not self.enabled: return []
        
        prompt = (
            f"As AURA-Zenith, perform a Deep Logic Audit on this transaction:\n"
            f"Request: {request_data}\n"
            f"Response: {response_data}\n\n"
            "Identify signs of Price Manipulation, IDOR/BOLA, State-Machine violations, or Race Conditions.\n"
            "Respond ONLY with a JSON array: [{'type': 'Logic Flaw', 'severity': 'HIGH/CRITICAL', 'reason': 'str', 'remediation': 'str'}]"
        )
        try:
            raw = self._call_ai(prompt)
            return self._clean_json(raw)
        except Exception as e:
            logger.error(f"AuraBrain Logic Audit: {e}")
            return []

    def suggest_waf_evasion(self, waf_type: str) -> str:
        """Phase 28: GPT-driven recommendation for bypassing specific WAFs."""
        if not self.enabled: return "Use standard URL encoding."
        
        prompt = (
            f"As AURA-Zenith, recommend a technical evasion technique to bypass {waf_type} WAF.\n"
            "Focus on: encoding, whitespace, comment nesting, or header smuggling.\n"
            "Respond ONLY with a short technical description."
        )
        try: return self._call_ai(prompt)
        except: return "Use polymorphism and fragmented payloads."

    async def self_heal_mutation(self, original_payload: str, response_code: int, response_body: str, response_headers: dict, attempt: int, waf_type: str = None) -> str:
        """v19.0 The Singularity: Adaptive Synthesis Feedback Loop."""
        if not self.enabled: return original_payload
        block_analysis = self.analyze_waf_block(response_code, response_headers, response_body)
        
        prompt = (
            f"As AURA-Zenith Singularity, your payload was BLOCKED by a WAF ({waf_type or 'Unknown'}).\n"
            f"Original Payload: {original_payload}\n"
            f"Block Analysis: {block_analysis}\n"
            "Generate a 'Singularity' mutated payload that bypasses this filter.\n"
            "Respond ONLY with the new raw payload string."
        )
        try:
            mutated = await asyncio.to_thread(self._call_ai, prompt)
            if mutated: return mutated
        except Exception: pass
        return original_payload + "/*" + str(random.randint(100,999)) + "*/"

    def analyze_waf_block(self, status: int, headers: dict, body: str) -> str:
        low_body = body.lower()
        if "captcha" in low_body or "challenge" in low_body: return "WAF Javascript Challenge detected."
        if status == 429 or "rate limit" in low_body: return "Dynamic Rate Limiting triggered."
        if "sql" in low_body or "injection" in low_body: return "Signature match: Injection attempt detected."
        if "cf-ray" in headers: return "Cloudflare Firewall active."
        return "Generic security policy violation."

    def generate_exploit_script(self, finding_type: str, finding_content: str, target_url: str) -> str:
        """v17.0: Shadow-Scripting Weaponization Engine."""
        prompt = (
            f"As AURA-Zenith Shadow-Scripting, generate a full, standalone Python exploit script for:\n"
            f"Finding Type: {finding_type}\n"
            f"Details: {finding_content}\n"
            f"Target URL: {target_url}\n"
            "Return ONLY the raw Python code without markdown code blocks."
        )
        try:
            code = self._call_ai(prompt)
            if "```python" in code: code = code.split("```python")[-1].split("```")[0]
            elif "```" in code: code = code.split("```")[-1].split("```")[0]
            return code.strip()
        except Exception as e: return f"# [!] Failed to generate shadow-script: {e}"

    def generate_graphql_attack(self, schema: str) -> str:
        if not self.enabled: return 'mutation { login(user: "admin", pass: "\' OR 1=1--") { token } }'
        prompt = f"Analyze this GraphQL schema and generate a malicious mutation: {schema[:2000]}"
        try: return self._call_ai(prompt)
        except: return 'mutation { login(user: "admin") { token } }'

    def is_input_relevant(self, name: str, vuln_type: str) -> bool:
        name = name.lower()
        irrelevant_sql = ["color", "width", "height", "font", "theme", "css", "style"]
        if vuln_type == "SQLi" and any(x in name for x in irrelevant_sql): return False
        irrelevant_xss = ["token", "uuid", "timestamp", "date"]
        if vuln_type == "XSS" and any(x == name for x in irrelevant_xss): return False
        return True

    def calculate_impact(self, finding_type: str, content: str) -> str:
        if self.enabled:
            prompt = f"Analyze finding severity: Type: {finding_type}, Content: {content}"
            try:
                res = self._call_ai(prompt, system_instruction="Respond ONLY with: CRITICAL, HIGH, MEDIUM, or LOW.")
                if res in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]: return res
            except: pass
        if any(x in finding_type.lower() for x in ["injection", "rce", "ssrf", "idor", "lfi"]): return "CRITICAL"
        if any(x in finding_type.lower() for x in ["xss", "secret", "token", "key"]): return "HIGH"
        return "MEDIUM"

    def generate_payload(self, vuln_type: str, tech_stack: str, level: int = 2, oast_url: str = None) -> str:
        if not self.enabled: return "fallback_payload"
        prompt = f"Generate Level {level} payload for {vuln_type} on {tech_stack}. OAST: {oast_url}"
        try: return self._call_ai(prompt)
        except: return "fallback_payload_simple"

    def predict_implied_vulns(self, context: dict, existing_findings: list) -> list:
        if not self.enabled: return []
        prompt = f"Predict implied vulns: Context: {context}, Findings: {json.dumps(existing_findings[:10])}"
        try:
            raw = self._call_ai(prompt, use_cache=True)
            parsed = self._clean_json(raw)
            return parsed if isinstance(parsed, list) else []
        except: return []

    def synthesize_detection_plugin(self, tech_info: str, target_desc: str) -> str:
        if not self.enabled: return ""
        prompt = f"Synthesize Python 3 function detect_vulnerability(session, url) for: {tech_info}, {target_desc}"
        try:
            raw = self._call_ai(prompt, use_cache=False)
            return raw.replace("```python", "").replace("```", "").strip()
        except: return ""

    async def model_state(self, traffic_logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """v51.0 OMEGA: Reconstructs the target's state machine from proxy logs."""
        if not self.enabled: return {}
        
        # Summarize logs to fit context (taking the first 20 transactions for now)
        summary = []
        for log in traffic_logs[:20]:
            summary.append({
                "method": log["method"],
                "url": log["url"],
                "status": log["response_stats"],
                "keys": list(json.loads(log["request_body"]).keys()) if log["request_body"].startswith("{") else []
            })
            
        prompt = (
            "Analyze these intercepted HTTP logs and reconstruct the application's state model.\n"
            f"Logs: {json.dumps(summary)}\n\n"
            "Identify:\n"
            "1. Authentication dependencies (which endpoints require a token from where?)\n"
            "2. State transitions (e.g., Login -> Cart -> Checkout)\n"
            "3. Sensitive parameters for fuzzing.\n"
            "Respond ONLY in JSON: {'states': [], 'transitions': [], 'suggested_fuzz_points': []}"
        )
        try:
            raw = await asyncio.to_thread(self._call_ai, prompt)
            return self._clean_json(raw)
        except Exception: return {}

    async def verify_strategy(self, strategy: Dict[str, Any], context: str) -> bool:
        """v3.0 Omega: The Consensus Oracle. Cross-verifies AI strategy across multiple models."""
        if not self.enabled: return True # Default to trust if AI offline
        
        prompt = (
            "As an independent Security Auditor, verify the following offensive strategy for technical validity.\n"
            f"Context: {context}\n"
            f"Proposed Strategy: {json.dumps(strategy)}\n\n"
            "Does this strategy make sense technically? Is it free from hallucinations? "
            "Respond ONLY in JSON: {'valid': boolean, 'confidence': 'str', 'reason': 'str'}"
        )
        
        # Trigger Consensus Vote: Use a DIFFERENT provider than the active one if possible
        providers = []
        if state.OLLAMA_HOST: providers.append("ollama")
        if state.GEMINI_API_KEY: providers.append("gemini")
        if state.OPENROUTER_API_KEY: providers.append("openrouter")
        
        verification_provider = next((p for p in providers if p != self.active_provider), self.active_provider)
        
        try:
            logger.info(f"[🧠] Consensus Oracle: Verifying via {verification_provider}")
            raw = await asyncio.to_thread(self._call_ai, prompt, use_cache=False)
            audit = self._clean_json(raw)
            return audit.get("valid", False)
        except Exception:
            return True # Fallback to trust if verification fails

    async def reconstruct_openapi(self, traffic_logs: List[Dict[str, Any]]) -> str:
        """v51.0 OMEGA: Generates a partial OpenAPI spec from captured traffic."""
        if not self.enabled: return ""
        
        prompt = (
            "Based on the following intercepted traffic logs, generate a partial OpenAPI 3.0 specification in YAML format.\n"
            f"Logs: {json.dumps(traffic_logs[:15])}\n\n"
            "Return ONLY the raw YAML spec."
        )
        try:
            return await asyncio.to_thread(self._call_ai, prompt)
        except Exception: return ""

    def generate_triage_guide(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """v3.0 Omega - Beginner Enablement: Explains a finding to a newcomer."""
        if not self.enabled: return {}
        
        prompt = (
            "As the AURA Mentor, explain this security finding to a beginner.\n"
            f"Finding: {json.dumps(finding)}\n\n"
            "Respond ONLY in JSON with these keys:\n"
            "1. 'technical_explanation': (simple breakdown of what happened),\n"
            "2. 'business_impact': (why this costs the company money or reputation),\n"
            "3. 'manual_verification_steps': (list[str] of actions the user should take in Burp or browser),\n"
            "4. 'educational_tip': (a short lesson about this vuln class)"
        )
        try:
            raw = self._call_ai(prompt)
            return self._clean_json(raw)
        except Exception: return {}
