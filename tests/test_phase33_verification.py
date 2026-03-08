import asyncio
import json
from unittest.mock import MagicMock, patch
from aura.core.brain import AuraBrain
from aura.core import state

async def test_openrouter_integration():
    """Verifies that AuraBrain can use OpenRouter as a provider."""
    print("[*] Testing OpenRouter Integration (Phase 33)...")
    
    # 1. Setup state for OpenRouter
    state.AI_PROVIDER = "openrouter"
    state.OPENROUTER_API_KEY = "sk-or-test-key"
    state.OPENROUTER_MODEL = "openai/gpt-4o"
    
    brain = AuraBrain()
    
    # 2. Mock httpx.Client.post
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "choices": [
            {
                "message": {
                    "content": "{\"vulnerable\": true, \"type\": \"SQL Injection\", \"reason\": \"Timed out\"}"
                }
            }
        ]
    }
    mock_response.raise_for_status = MagicMock()
    
    with patch("httpx.Client.post", return_value=mock_response) as mock_post:
        # 3. Trigger an AI call
        result = brain.analyze_behavior(
            url="http://test.com",
            payload="' OR 1=1",
            delay_ms=5000,
            length=100,
            status=200,
            body="OK"
        )
        
        # 4. Verify mock call
        mock_post.assert_called()
        args, kwargs = mock_post.call_args
        payload = kwargs.get("json")
        
        print(f"[+] OpenRouter Model used: {payload['model']}")
        assert payload["model"] == "openai/gpt-4o"
        assert "Authorization" in kwargs.get("headers")
        
        # 5. Verify result parsing
        print(f"[+] Result: {result}")
        assert result["vulnerable"] is True
        assert result["type"] == "SQL Injection"

    print("\n[SUCCESS] Phase 33 OpenRouter Integration Verified.")

if __name__ == "__main__":
    asyncio.run(test_openrouter_integration())
