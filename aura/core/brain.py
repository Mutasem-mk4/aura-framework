import logging
import json
import random
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
        "staging": "Staging environments are often less protected than production and may contain legacy data or debug symbols.",
        "docker": "Exposed Docker registries or sockets can lead to container escape and host takeover.",
        "vpn": "VPN endpoints are high-value targets for initial access. Recommendation: Check for known CVEs in the underlying software (Pulse Secure, Fortinet, etc.)."
    }

    def __init__(self):
        self.enabled = False
        self.tactical_memory = [] # Phase 18: Tactical Memory
        self.payload_cache = {}  # Initialize payload cache for Level 1 & 2
        self.ai_cache = {} # v19.2: General AI query cache
        if state.GEMINI_API_KEY:
            try:
                self.client = genai.Client(api_key=state.GEMINI_API_KEY)
                self.enabled = True
                logger.info("AuraBrain Singularity: Gemini Engine online (SDK v1).")
            except Exception as e:
                logger.error(f"AuraBrain: Failed to initialize Gemini: {e}")

    def _call_ai(self, prompt, system_instruction=None, use_cache=True):
        """v19.2: Sentinel-G AI Resurrection - Enhanced retry logic with exponential backoff & caching."""
        if use_cache and prompt in self.ai_cache:
            return self.ai_cache[prompt]

        max_retries = 5 # Increased for higher resilience
        for attempt in range(max_retries):
            try:
                response = self.client.models.generate_content(
                    model=state.GEMINI_MODEL,
                    contents=prompt,
                    config={'system_instruction': system_instruction or self.SYSTEM_PROMPT}
                )
                res_text = response.text.strip().replace("```json", "").replace("```", "").strip()
                if use_cache:
                    self.ai_cache[prompt] = res_text
                return res_text
            except Exception as e:
                err_str = str(e).lower()
                # If it's a quota or safety filter, don't retry as aggressively
                if "quota" in err_str or "safety" in err_str:
                    logger.error(f"Sentinel-G Blocked: {e}")
                    break
                
                if attempt == max_retries - 1:
                    logger.error(f"Sentinel-G Final Failure: {e}")
                    break
                
                wait_time = (2 ** attempt) + random.uniform(0.1, 1.0)
                logger.warning(f"Sentinel-G Retry ({attempt+1}/{max_retries}) in {wait_time:.1f}s: {e}")
                import time
                time.sleep(wait_time)
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
            import json
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
                response = self.client.models.generate_content(
                    model=state.GEMINI_MODEL,
                    contents=prompt,
                    config={'system_instruction': self.SYSTEM_PROMPT}
                )
                return response.text
            except Exception as e:
                logger.warning(f"AuraBrain: Gemini query failed, falling back to rules. Error: {e}")

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
            if raw.startswith("[") or raw.startswith("{"):
                return raw
            return "[]"
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
            import json
            return json.loads(raw)
        except Exception as e:
            logger.error(f"AuraBrain Behavior: {e}")
            return {"vulnerable": False}

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
            response = self.client.models.generate_content(
                model=state.GEMINI_MODEL,
                contents=prompt,
                config={'system_instruction': self.SYSTEM_PROMPT}
            )
            import json
            raw = response.text.strip().replace("```json", "").replace("```", "")
            return json.loads(raw)
        except Exception as e:
            logger.error(f"AuraBrain Semantics: {e}")
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
            response = self.client.models.generate_content(
                model=state.GEMINI_MODEL,
                contents=prompt,
                config={'system_instruction': self.SYSTEM_PROMPT}
            )
            import json
            raw = response.text.strip().replace("```json", "").replace("```", "")
            return json.loads(raw)
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

    def self_heal_mutation(self, original_payload: str, response_code: int, response_body: str, attempt: int) -> str:
        """v16.0 Omni-Sovereign: Self-Healing Exploit Loop. Mutates payload based on rejection feedback."""
        if not self.enabled: return original_payload
        
        prompt = (
            f"As AURA-Zenith, your previous payload was BLOCKED.\n"
            f"Original Payload: {original_payload}\n"
            f"Response Code: {response_code}\n"
            f"Response Snippet: {response_body[:500]}\n"
            f"Mutation Attempt: {attempt}\n\n"
            "Anaylze the rejection reason. Is it a signature match? A rate limit? A structural filter?\n"
            "Generate a MUTATED version of the payload that bypasses this filter. "
            "Use advanced techniques: Junk data injection, non-standard encoding, case-variation, or logical splitting.\n"
            "Respond ONLY with the new raw payload string."
        )
        try:
            return self._call_ai(prompt)
        except:
            # Fallback to simple polymorphism
            return original_payload + "/*" + str(random.randint(100,999)) + "*/"

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
            response = self.client.models.generate_content(
                model=state.GEMINI_MODEL,
                contents=prompt,
                config={'system_instruction': self.SYSTEM_PROMPT}
            )
            return response.text.strip().replace("```graphql", "").replace("```", "")
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
                response = self.client.models.generate_content(
                    model=state.GEMINI_MODEL,
                    contents=prompt,
                    config={'count': 1}
                )
                res = response.text.strip().upper()
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
