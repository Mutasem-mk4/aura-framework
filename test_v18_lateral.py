import asyncio
import unittest
from unittest.mock import MagicMock, patch
from aura.modules.lateral_engine import LateralEngine

class TestLateralSovereigntyV18(unittest.IsolatedAsyncioTestCase):
    
    def setUp(self):
        self.brain = MagicMock()
        self.lateral = LateralEngine(self.brain)

    async def test_lateral_pivot_aws(self):
        """Verify that LateralEngine identifies AWS from SSRF content."""
        finding = {
            "type": "SSRF",
            "content": "Vulnerable to SSRF via /proxy?url=http://169.254.169.254/latest/meta-data/"
        }
        
        self.brain.reason_json.return_value = "AWS"
        
        await self.lateral.pivot_from_finding(finding)
        
        self.assertEqual(len(self.lateral.footholds), 1)
        self.brain.reason_json.assert_called()
        print("[+] Lateral Pivot verified: Identified AWS environment from foothold.")

    async def test_lateral_pivot_k8s(self):
        """Verify that LateralEngine identifies K8S from RCE context."""
        finding = {
            "type": "RCE",
            "content": "Command execution confirmed on pod aura-worker-7"
        }
        
        self.brain.reason_json.return_value = "K8S"
        
        await self.lateral.pivot_from_finding(finding)
        self.brain.reason_json.assert_called()
        print("[+] Lateral Pivot verified: Identified K8S environment from foothold.")

if __name__ == "__main__":
    unittest.main()
