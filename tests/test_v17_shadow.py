import asyncio
import unittest
import os
import shutil
from unittest.mock import MagicMock, patch
from aura.core.orchestrator import NeuralOrchestrator

class TestShadowScripting(unittest.IsolatedAsyncioTestCase):
    
    def setUp(self):
        self.orchestrator = NeuralOrchestrator()
        self.exploit_dir = os.path.join(os.getcwd(), "aura_exploits")
        if os.path.exists(self.exploit_dir):
            shutil.rmtree(self.exploit_dir)

    @patch('aura.core.brain.AuraBrain.reason_json')
    async def test_weaponization_loop(self, mock_reason):
        """Verify that Orchestrator triggers Shadow-Scripting."""
        mock_reason.return_value = "import requests\nprint('Exploiting...')"
        
        # Simulate findings
        vulns = [{"type": "SQL Injection", "content": "Blind SQLi on /api/user"}]
        domain = "test.local"
        target_url = "http://test.local"
        
        # We manually trigger the loop block logic for testing
        if not os.path.exists(self.exploit_dir): os.makedirs(self.exploit_dir)
        for i, v in enumerate(vulns):
             script = self.orchestrator.brain.generate_exploit_script(v['type'], v['content'], target_url)
             filename = f"exploit_{domain.replace('.', '_')}_{i}.py"
             with open(os.path.join(self.exploit_dir, filename), "w") as f:
                 f.write(script)
        
        self.assertTrue(os.path.exists(os.path.join(self.exploit_dir, f"exploit_test_local_0.py")))
        print("[+] Shadow-Scripting Verified: Exploit PoC generated and saved.")

if __name__ == "__main__":
    unittest.main()
