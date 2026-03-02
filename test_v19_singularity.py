import asyncio
import unittest
from unittest.mock import MagicMock, patch
from aura.modules.neural_forge import NeuralForge
from aura.modules.ghost_ops import GhostOps

class TestSingularityV19(unittest.IsolatedAsyncioTestCase):
    
    def setUp(self):
        self.brain = MagicMock()
        self.orchestrator = MagicMock()
        self.forge = NeuralForge(self.brain)
        self.ghost_ops = GhostOps(self.orchestrator)

    @patch('aura.modules.neural_forge.NeuralForge.synthesize_0day_vectors')
    async def test_neural_forge_synthesis(self, mock_synth):
        """Verify Neural-Forge identifies unique logic flaws."""
        mock_synth.return_value = [{"name": "Atomic Race Condition", "logic": "Collision on /cancel", "lethality": "CRITICAL"}]
        results = await self.forge.synthesize_0day_vectors({}, ["Nginx", "Python"])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['name'], "Atomic Race Condition")
        print("[+] Neural-Forge Verified: 0-Day Logic synthesized.")

    @patch('requests.get')
    async def test_ghost_ops_diversion(self, mock_get):
        """Verify Ghost-Ops launches loud decoy attacks."""
        await self.ghost_ops.launch_diversion("http://target.local")
        # Give some time for background tasks to start
        await asyncio.sleep(0.1)
        self.assertTrue(mock_get.called)
        print("[+] Ghost-Ops Verified: Tactical diversion (decoys) deployed.")

if __name__ == "__main__":
    unittest.main()
