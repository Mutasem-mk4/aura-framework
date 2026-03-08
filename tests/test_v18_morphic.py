import asyncio
import unittest
import time
from unittest.mock import MagicMock, patch
from aura.core.stealth import StealthEngine, AuraSession, MorphicEngine

class TestMorphicStealthV18(unittest.IsolatedAsyncioTestCase):
    
    def setUp(self):
        self.stealth = StealthEngine()
        self.session = AuraSession(self.stealth)
        self.session.brain.enabled = True

    async def test_morphic_jitter(self):
        """Verify that jitter is applied when WAF is active."""
        self.stealth.active_waf = "Cloudflare"
        start_time = time.time()
        
        # We mock the sleep to speed up test but verify it's called
        with patch('time.sleep') as mock_sleep:
            self.session.morphic.apply_morphic_jitter()
            self.assertTrue(mock_sleep.called)
        print("[+] Morphic Jitter verified: Bio-inspired delay applied.")

    def test_morphic_headers(self):
        """Verify that headers are morphed to match a session template."""
        original_headers = {"User-Agent": "Aura/1.0", "X-Scanner": "True"}
        morphed = self.session.morphic.get_morphic_headers(original_headers)
        
        self.assertIn("Referer", morphed)
        self.assertNotEqual(morphed["User-Agent"], "Aura/1.0")
        print(f"[+] Morphic Headers verified: Masked as {self.session.morphic.current_template['name']}.")

if __name__ == "__main__":
    unittest.main()
