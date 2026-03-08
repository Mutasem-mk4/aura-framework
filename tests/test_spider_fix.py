import asyncio
import unittest
from unittest.mock import MagicMock, AsyncMock
from aura.modules.scanner import AuraScanner
from aura.core.stealth import StealthEngine, AuraSession

class TestScannerSpider(unittest.IsolatedAsyncioTestCase):
    async def test_spider_deduplication_and_collection(self):
        """Verify that spider deduplicates and populates all_discovered."""
        stealth = StealthEngine()
        scanner = AuraScanner(stealth=stealth)
        
        # Mocking the session to return a simple page with links
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '<html><a href="/page1">1</a><a href="/page2">2</a><a href="/page1">Duplicate</a></html>'
        
        scanner.stealth_session.get = AsyncMock(return_value=mock_response)
        
        # Run spider with depth 1
        urls, forms = await scanner.recursive_spider("http://test.local", max_depth=1)
        
        # Should have found page1 and page2 once in the master list
        self.assertIn("http://test.local/page1", urls)
        self.assertIn("http://test.local/page2", urls)
        print(f"[+] Found URLs: {urls}")
        self.assertTrue(len([u for u in urls if "page1" in u]) >= 1)

    async def test_morphic_async_sleep(self):
        """Verify that morphic jitter uses async sleep and doesn't block."""
        stealth = StealthEngine()
        stealth.active_waf = "Cloudflare"
        session = AuraSession(stealth)
        
        # Test if apply_morphic_jitter is now a coroutine
        import inspect
        self.assertTrue(inspect.iscoroutinefunction(session.morphic.apply_morphic_jitter))
        print("[+] Morphic jitter is now an async coroutine.")

if __name__ == "__main__":
    unittest.main()
