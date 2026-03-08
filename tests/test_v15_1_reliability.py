import asyncio
import unittest
from unittest.mock import MagicMock, patch
from aura.core.brain import AuraBrain
from aura.modules.dast_v2 import AuraSingularity

class TestReliabilityV15(unittest.IsolatedAsyncioTestCase):
    
    def setUp(self):
        self.brain = AuraBrain()
        self.brain.enabled = True
        self.singularity = AuraSingularity()

    @patch('google.genai.Client')
    async def test_ai_resurrection(self, mock_client):
        """Verify that Sentinel-G retries on AI failure."""
        mock_model = MagicMock()
        # Simulate 2 failures then a success
        mock_model.generate_content.side_effect = [
            Exception("Transient Timeout"),
            Exception("Overloaded"),
            MagicMock(text='{"plan": "Test Plan", "target_vector": "API", "reasoning": "Success after retries"}')
        ]
        mock_client.return_value.models = mock_model
        self.brain.client = mock_client.return_value
        
        plan = self.brain.autonomous_plan("http://test.com", "<html></html>", [])
        
        self.assertEqual(plan['target_vector'], "API")
        self.assertEqual(mock_model.generate_content.call_count, 3)
        print("[+] AI Resurrection Verified: Success after 2 retries.")

    async def test_navigation_guard_simulation(self):
        """
        Note: This is a logic test. Real browser testing requires playwright environment.
        We verify the logic flow in a simulated environment if possible, 
        but here we'll just check if the methods exist and symbols are correct.
        """
        self.assertTrue(has_attr := hasattr(self.singularity, "_fragmented_attack"))
        print(f"[+] Navigation Guard internal symbols verified: {has_attr}")

if __name__ == "__main__":
    unittest.main()
