import json
import logging
from typing import Dict, List, Optional
import requests

logger = logging.getLogger("aura")

class NeuralArsenal:
    """The AI-driven engine for crafting unique, polymorphic payloads and strategies."""
    
    def __init__(self, provider: str = "ollama", base_url: str = "http://localhost:11434"):
        self.provider = provider
        self.base_url = base_url
        self.model = "llama3" # Default high-performance model
        self.system_prompt = (
            "You are Aura-AI, a high-tier autonomous offensive security engine. "
            "Your goal is to provide specific, technical, and actionable exploitation strategies "
            "and polymorphic payloads. Keep it professional, concise, and technical."
        )

    def generate_strategy(self, target_info: Dict) -> str:
        """Generates a custom exploitation strategy for a given target."""
        prompt = (
            f"Target: {target_info.get('value')}\n"
            f"Observed Attributes: {target_info.get('type')}, Risk Score: {target_info.get('risk_score')}\n"
            "Analyze this target and provide a 3-step exploitation strategy."
        )
        return self._query_ai(prompt)

    def craft_payload(self, target_context: str, payload_type: str = "directory_fuzz") -> str:
        """Generate a unique payload based on the target context."""
        prompt = (
            f"Context: {target_context}\n"
            f"Generate a list of 5 polymorphic {payload_type} payloads. "
            "Avoid common signatures. Make them creative."
        )
        return self._query_ai(prompt)

    def _query_ai(self, prompt: str) -> str:
        """Internal method to query the local AI provider."""
        if self.provider == "ollama":
            try:
                response = requests.post(
                    f"{self.base_url}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": f"{self.system_prompt}\n\nUser: {prompt}\nAssistant:",
                        "stream": False
                    },
                    timeout=30
                )
                if response.status_code == 200:
                    return response.json().get("response", "No AI response received.")
            except Exception as e:
                return f"[Fallback Logic] AI Offline. Error: {str(e)}\nRecommendation: Manual service enumeration and credential testing."
        
        return "AI Provider not supported or unreachable."
