import logging
import json
import random
import os
import re
import asyncio
from typing import Dict, Any, Optional

import httpx
from google import genai
from aura.core import state

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
        "api": "Unprotected APIs often suffer from Broken Object Level Authorization (BOLA). Recommendation: Fuzz endpoints for IDOR vulnerabilities.",
        "logic_flaw": "State-changing APIs (POST/PUT) handling quantities, prices, or roles can be bypassed. Mutate numeric values to negative bounds and append highly privileged boolean flags.",
        "staging": "Staging environments are often less protected than production and may contain legacy data or debug symbols.",
        "docker": "Exposed Docker registries or sockets can lead to container escape and host takeover.",
        "vpn": "VPN endpoints are high-value targets for initial access. Recommendation: Check for known CVEs in the underlying software (Pulse Secure, Fortinet, etc.)."
    }

    def __init__(self):
        self.enabled = False
        self.tactical_memory = [] # Phase 18: Tactical Memory
        self.payload_cache = {}  # Initialize payload cache for Level 1 & 2
        self.ai_cache = {} # v19.2: General AI query cache
        if state.AI_PROVIDER == "gemini" and state.GEMINI_API_KEY:
            try:
                self.client = genai.Client(api_key=state.GEMINI_API_KEY)
                self.enabled = True
                logger.info("AuraBrain Singularity: Gemini Engine online (SDK v1).")
            except Exception as e:
                logger.error(f"AuraBrain: Failed to initialize Gemini: {e}")
        elif state.AI_PROVIDER == "openrouter" and state.OPENROUTER_API_KEY:
            self.openrouter_key = state.OPENROUTER_API_KEY
            self.enabled = True
            logger.info(f"AuraBrain Singularity: OpenRouter Engine online ({state.OPENROUTER_MODEL}).")

    def _call_ai(self, prompt, system_instruction=None, use_cache=True):
        """v19.2/v22.1: Multi-Model AI Router - Redirects to Gemini SDK or OpenRouter HTTP."""
        if not self.enabled: return None
        if use_cache and prompt in self.ai_cache:
            return self.ai_cache[prompt]

        if state.AI_PROVIDER == "gemini":
            return self._call_gemini_sdk(prompt, system_instruction, use_cache)
        else:
            return self._call_openrouter(prompt, system_instruction, use_cache)

    def _call_gemini_sdk(self, prompt, system_instruction=None, use_cache=True):
        """Standard Gemini SDK call with retry logic."""
        import random
        import time
        max_retries = 5
        for attempt in range(max_retries):
            try:
                response = self.client.models.generate_content(
                    model=state.GEMINI_MODEL,
                    contents=prompt,
                    config={'system_instruction': system_instruction or self.SYSTEM_PROMPT}
                )
                res_text = response.text.strip().replace("```json", "").replace("```", "").strip()
                if use_cache: self.ai_cache[prompt] = res_text
                return res_text
            except Exception as e:
                if "quota" in str(e).lower(): break
                if attempt == max_retries - 1: break
                time.sleep((2 ** attempt) + random.uniform(0.1, 1.0))
        return None

    def _call_openrouter(self, prompt, system_instruction=None, use_cache=True):
        """v22.1: OpenRouter HTTP Implementation (OpenAI Compatibility)."""
        url = "https://openrouter.ai/api/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.openrouter_key}",
            "HTTP-Referer": "https://github.com/Mutasem-mk4/Aura", # Required by OpenRouter
            "X-Title": "Aura Zenith Singularity",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": state.OPENROUTER_MODEL,
            "messages": [
                {"role": "system", "content": system_instruction or self.SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ]
        }
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                with httpx.Client(timeout=state.NETWORK_TIMEOUT) as client:
                    resp = client.post(url, headers=headers, json=payload)
                    resp.raise_for_status()
                    data = resp.json()
                    res_text = data['choices'][0]['message']['content'].strip()
                    res_text = res_text.replace("```json", "").replace("```", "").strip()
                    if use_cache: self.ai_cache[prompt] = res_text
                    return res_text
            except Exception as e:
                logger.warning(f"OpenRouter Attempt {attempt+1} Failed: {e}")
                import time
                time.sleep(2 + attempt)
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
            plan = json.loads(raw)
            self.tactical_memory.append(f"Planned: {plan.get('target_vector')}")
            return plan
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

    def reason_json(self, prompt: str, system_instruction: str = None) -> str:
        """v5.1 / v19.4: Synchronized JSON reasoning using google-genai SDK (matches _call_ai)."""
        if not self.enabled: return "[]"

        try:
            response = self.client.models.generate_content(
                model=state.GEMINI_MODEL,
                contents=prompt,
                config={'system_instruction': system_instruction or self.SYSTEM_PROMPT}
            )
            if not response or not response.text:
                return "[]"
            raw = response.text.strip().replace("```json", "").replace("```", "").strip()
            if not (raw.startswith("[") or raw.startswith("{")):
                return "[]"
            # v19.4: Strip invalid JSON escape sequences before parsing
            import re
            raw = re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', raw)
            try:
                json.loads(raw)   # validate
            except Exception:
                return "[]"
            return raw
        except Exception as e:
            logger.error(f"AuraBrain JSON Reason: {e}")
            return "[]"

    def analyze_behavior(self, url: str, payload: str, delay_ms: int, length: int, status: int, body: str) -> dict:
        """Deep behavioral analysis for Blind vulnerabilities and WAF evasion indicators."""
        if not self.enabled: return {"vulnerable": False}
        
        prompt = (
            f"As a Red Team AI, analyze this response behavior for a payload: '{payload}' on {url}.\n"
            f"Observed Latency: {delay_ms}ms | Content Length: {length} | Status: {status}\n"
            f"Response Snippet:\n{body[:800]}\n\n"
            "Is there any suspicious behavior? High latency (>3s) often indicates Blind SQLi or Command Injection. "
            "Structural changes (Length delta > 500) indicate potential bypass or information leak. "
            "Respond ONLY in JSON: {'vulnerable': boolean, 'suspect': boolean, 'type': 'string', 'confidence': 'string', 'reason': 'string'}"
        )
        try:
            raw = self._call_ai(prompt, use_cache=True)
            if not raw: return {"vulnerable": False}
            
            # Use smart extraction
            return self._clean_json(raw)
        except Exception:
            # Suppress logs for cleaner CLI
            return {"vulnerable": False}

    def _clean_json(self, text):
        """Helper to extract and parse JSON from AI responses."""
        import re
        # Try finding dictionary
        match = re.search(r'(\{.*\})', text, re.DOTALL)
        if match:
            try: return json.loads(match.group(1))
            except: pass
        # Try finding array
        match = re.search(r'(\[.*\])', text, re.DOTALL)
        if match:
            try: return json.loads(match.group(1))
            except: pass
        # Try raw
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
        except Exception:
            return []

    def analyze_business_logic(self, request_data: dict, response_data: dict) -> list:
        """v15.0: Deep analysis of HTTP transactions for complex business logic flaws (BOLA, Price Manip, etc)."""
        if not self.enabled: return []
        
        prompt = (
            f"As AURA-Zenith, perform a Deep Logic Audit on this transaction:\n"
            f"Request: {request_data}\n"
            f"Response: {response_data}\n\n"
            "Identify signs of:\n"
            "1. Price/Amount Manipulation (client-side controls)\n"
            "2. IDOR/BOLA (look for numeric IDs in URL/Body versus session tokens)\n"
            "3. State-Machine violations (e.g., skipping payment steps, bypassing MFA)\n"
            "4. Race Condition potential (state changes without unique nonces/tokens)\n\n"
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
            "Focus on: encoding (double URL, unicode), whitespace manipulation, comment nesting (SQL), or header smuggling. "
            "Respond ONLY with a short technical description."
        )
        try:
            return self._call_ai(prompt)
        except:
            return "Use polymorphism and fragmented payloads."

    async def self_heal_mutation(self, original_payload: str, response_code: int, response_body: str, response_headers: dict, attempt: int, waf_type: str = None) -> str:
        """
        v19.0 The Singularity: Adaptive Synthesis Feedback Loop.
        Analyzes the WAF rejection and triggers NeuralForge/AI to create a bypass.
        """
        if not self.enabled: return original_payload
        
        # Analyze headers for specific WAF signatures or rate limit indicators
        block_analysis = self.analyze_waf_block(response_code, response_headers, response_body)
        
        prompt = (
            f"As AURA-Zenith Singularity, your previous payload was BLOCKED by a WAF ({waf_type or 'Unknown'}).\n"
            f"Original Payload: {original_payload}\n"
            f"Response Code: {response_code}\n"
            f"Block Analysis: {block_analysis}\n"
            f"Mutation Attempt: {attempt}\n\n"
            "Analyze the rejection reason. Use your internal knowledge of Cloudflare/Akamai/AWS WAF signatures. "
            "Generate a 'Singularity' mutated payload that bypasses this filter. "
            "Think step-by-step: Should you use double encoding? Comment nesting? Null byte truncation? Non-standard HTTP headers?\n"
            "Respond ONLY with the new raw payload string."
        )
        try:
            # v19.0: We use _call_ai for CoT mutation logic
            mutated = await asyncio.to_thread(self._call_ai, prompt)
            if mutated:
                logger.info(f"Singularity Mutation Success: {original_payload} -> {mutated}")
                return mutated
        except Exception as e:
            logger.error(f"Singularity Mutation Failed: {e}")
            
        # Fallback to simple polymorphism
        return original_payload + "/*" + str(random.randint(100,999)) + "*/"

    def analyze_waf_block(self, status: int, headers: dict, body: str) -> str:
        """Heuristic analysis of WAF response to determine blocking reason."""
        low_body = body.lower()
        if "captcha" in low_body or "challenge" in low_body:
            return "WAF Javascript Challenge/Captcha detected."
        if status == 429 or "rate limit" in low_body:
            return "Dynamic Rate Limiting triggered."
        if "sql" in low_body or "injection" in low_body:
            return "Signature match: Injection attempt detected."
        
        # Check for WAF-specific headers
        if "cf-ray" in headers: return "Cloudflare Firewall active."
        if "x-akamai" in str(headers).lower(): return "Akamai WAF active."
        
        return "Generic security policy violation."

    def generate_exploit_script(self, finding_type: str, finding_content: str, target_url: str) -> str:
        """
        v17.0: Shadow-Scripting
        Autonomously generates a standalone Python exploit script for a specific finding.
        """
        prompt = (
            f"As AURA-Zenith Shadow-Scripting Engine, generate a full, standalone Python exploit script (using requests or curl_cffi) for:\n"
            f"Finding Type: {finding_type}\n"
            f"Details: {finding_content}\n"
            f"Target URL: {target_url}\n"
            "The script must be professional, include clear documentation, and attempt to verify the exploit non-destructively.\n"
            "Return ONLY the raw Python code without markdown code blocks."
        )
        try:
            # Ghost v5: AI-assisted weaponization
            code = self.reason_json(prompt)
            # Clean possible markdown wrap
            if "```python" in code:
                code = code.split("```python")[-1].split("```")[0]
            elif "```" in code:
                code = code.split("```")[-1].split("```")[0]
            return code.strip()
        except Exception as e:
            return f"# [!] Failed to generate shadow-script: {e}"

    def generate_graphql_attack(self, schema: str) -> str:
        """Phase 30: AI-driven GraphQL mutation fuzzing based on schema analysis."""
        if not self.enabled: return 'mutation { login(user: "admin", pass: "' + "' OR 1=1--" + '") { token } }'
        
        prompt = (
            f"As AURA Singularity, analyze this GraphQL schema and generate a malicious mutation or query.\n"
            f"Schema Fragment: {schema[:2000]}\n\n"
            "Identify sensitive mutations like 'updateUser', 'resetPassword', 'deleteRecord', 'transfer'. "
            "Generate a 'lethal' GraphQL payload to exploit potential logic flaws or injection.\n"
            "Return ONLY the raw GraphQL string."
        )
        try:
            return self._call_ai(prompt)
        except Exception as e:
            logger.error(f"AuraBrain GraphQL: {e}")
            return 'mutation { login(user: "admin") { token } }'

    def is_input_relevant(self, name: str, vuln_type: str) -> bool:
        """Phase 30: Heuristic check to see if an input name is relevant for a vuln type."""
        name = name.lower()
        irrelevant_sql = ["color", "width", "height", "font", "theme", "css", "style"]
        if vuln_type == "SQLi" and any(x in name for x in irrelevant_sql):
            return False
            
        irrelevant_xss = ["token", "uuid", "timestamp", "date"]
        # Note: 'id' might be vulnerable to IDOR but here we check for XSS reflection
        if vuln_type == "XSS" and any(x == name for x in irrelevant_xss):
            return False
            
        return True

    def calculate_impact(self, finding_type: str, content: str) -> str:
        """Phase 31: Analyzes a finding to determine professional severity."""
        content_low = content.lower()
        type_low = finding_type.lower()
        
        # 1. AI-Driven deep reasoning (if available)
        if self.enabled:
            # We use a summarized prompt for speed
            prompt = (
                f"As AURA Singularity, analyze this security finding and assign a professional severity: CRITICAL, HIGH, MEDIUM, or LOW.\n"
                f"Finding Type: {finding_type}\n"
                f"Finding Content: {content}\n\n"
                "Return ONLY the severity name."
            )
            try:
                res = self._call_ai(prompt, system_instruction="Respond ONLY with: CRITICAL, HIGH, MEDIUM, or LOW.")
                if res in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                    return res
            except: pass

        # 2. Heuristic Fallback (Logical/Deterministic rules)
        high_impact_paths = [
            "/backup", "/db", "/phpmyadmin", "/config", "/setup", "/.env", "/settings", 
            "/admin", "/login", "/mysql", "/sql", "/backup.zip", "/config.php", "/web.config",
            "/.git", "/.svn", "/.ds_store", "/dvwa", "/vuln", "/test", "/dev"
        ]
        
        # If any high-impact keyword is in the content/path and it's info disclosure or discovered path
        if "path" in type_low or "disclosure" in type_low or "discovered" in type_low:
            if any(path in content_low for path in high_impact_paths):
                return "CRITICAL"
        
        # Injection and high-impact vulns
        if any(x in type_low for x in ["injection", "rce", "ssrf", "idor", "lfi"]):
            return "CRITICAL"
            
        if any(x in type_low for x in ["xss", "secret", "token", "key", "access", "auth"]):
            return "HIGH"
            
        return "MEDIUM"

    def generate_payload(self, vuln_type: str, tech_stack: str, level: int = 2, oast_url: str = None) -> str:
        """v15.1: Semantic Stack-Mapping - Generates tech-specific payloads for maximum impact."""
        if not self.enabled: return "fallback_payload"
        
        prompt = (
            f"As AURA-Zenith, generate a high-impact Level {level} payload for: {vuln_type}.\n"
            f"Target Stack: {tech_stack}\n"
            f"OAST URL (if any): {oast_url}\n\n"
            "Requirements:\n"
            "- Bypass modern WAFs (use polymorphism/encoding if level > 2).\n"
            "- Target specific weaknesses in the identified stack (e.g., if Tomcat, use path traversal variants).\n"
            "Respond ONLY with the payload string."
        )
        try:
            return self._call_ai(prompt)
        except:
            return "fallback_payload_simple"
    def predict_implied_vulns(self, context: dict, existing_findings: list) -> list:
        """
        v22.0: Oracle Synthesis - Predictive Vulnerability Engine.
        Analyzes existing findings and architectural patterns to predict 'Implied' vulnerabilities.
        """
        if not self.enabled: return []
        
        prompt = (
            f"As AURA-Zenith Oracle, analyze these confirmed findings and environmental context:\n"
            f"Context: {context}\n"
            f"Existing Findings: {json.dumps(existing_findings[:10])}\n\n"
            "By identifying patterns in inconsistent naming, technology versions, and server headers, "
            "predict 1-3 'Implied' vulnerabilities that are likely to exist but haven't been scanned yet. "
            "Think laterally: if there is an IDOR in /api/v1, is it implied in /api/beta? "
            "If SSRF is confirmed, is an internal metadata leak implied?\n"
            "Respond ONLY in JSON array: [{'predicted_type': 'str', 'implied_url': 'str', 'confidence': 'str', 'reasoning': 'str'}]"
        )
        try:
            raw = self._call_ai(prompt, use_cache=True)
            if not raw: return []
            parsed = self._clean_json(raw)
            return parsed if isinstance(parsed, list) else []
        except Exception as e:
            logger.error(f"AuraBrain IDOR Logic JSON Reason: {e}")
            return []
    def synthesize_detection_plugin(self, tech_info: str, target_desc: str) -> str:
        """
        v24.0 Sovereign Hegemony: Autonomous Plugin Synthesis.
        Generates custom Python detection logic for unknown technologies or specific CVEs.
        """
        if not self.enabled: return ""
        
        prompt = (
            f"As AURA-Zenith AI, synthesize a HIGH-STAKES Python 3 function to detect a vulnerability in this specific target:\n"
            f"Tech Stack/Context: {tech_info}\n"
            f"Target Details: {target_desc}\n\n"
            "Requirements:\n"
            "1. Function name MUST be 'detect_vulnerability(session, url)'.\n"
            "2. Use 'await session.get(url)' or 'await session.post(url)'.\n"
            "3. Return a dictionary with 'vulnerable': bool, 'details': str if found.\n"
            "4. DO NOT use external libraries besides typing, json, re, asyncio.\n"
            "5. Respond ONLY with the Python code block, no markdown formatting if possible, "
            "but if you use backticks I will strip them. Code must be ready to execute via exec()."
        )
        try:
            raw = self._call_ai(prompt, use_cache=False)
            if not raw: return ""
            # Clean backticks if present
            clean_code = raw.replace("```python", "").replace("```", "").strip()
            return clean_code
        except Exception as e:
            logger.error(f"Plugin Synthesis Error: {e}")
            return ""
