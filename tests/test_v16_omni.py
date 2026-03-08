import asyncio
import unittest
from unittest.mock import MagicMock, patch
from aura.core.brain import AuraBrain
from aura.modules.logic_engine import LogicBlueprinter

class TestOmniSovereignV16(unittest.IsolatedAsyncioTestCase):
    
    def setUp(self):
        self.brain = AuraBrain()
        self.brain.enabled = True
        self.logic = LogicBlueprinter(self.brain)

    @patch('aura.core.brain.AuraBrain._call_ai')
    async def test_self_heal_mutation(self, mock_ai):
        """Verify that Aura mutates payload on block."""
        mock_ai.return_value = "' UNION SELECT 1,2,3-- (Mutated)"
        
        mutation = self.brain.self_heal_mutation("' OR 1=1--", 403, "Forbidden by Cloudflare", 1)
        
        self.assertIn("(Mutated)", mutation)
        print("[+] Self-Heal Mutation Verified: Payload adapted based on 403 feedback.")

    async def test_logic_blueprinting(self):
        """Verify that the state machine identifies critical segments."""
        urls = [
            "http://test.com/home",
            "http://test.com/cart",
            "http://test.com/checkout/payment",
            "http://test.com/checkout/success"
        ]
        await self.logic.blueprint_target(urls)
        vectors = self.logic.identify_state_skipping_vectors()
        
        self.assertTrue(any("State Skip" in v for v in vectors))
        print(f"[+] Logic Blueprinting Verified: Identified {len(vectors)} potential state-skip vectors.")

if __name__ == "__main__":
    unittest.main()
