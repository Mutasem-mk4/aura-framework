import os
import json
from aura.core.brain import AuraBrain

class AuraForgeAI:
    """The 'Genius' module for self-writing security plugins."""
    
    def __init__(self):
        self.brain = AuraBrain()
        self.plugins_dir = os.path.join(os.getcwd(), "plugins")
        if not os.path.exists(self.plugins_dir):
            os.makedirs(self.plugins_dir)

    def _generate_prompt(self, description: str) -> str:
        return f"""
YOU ARE AN ELITE OFFENSIVE SECURITY RESEARCHER. WRITE A PROFESSIONAL, HIGH-PERFORMANCE PYTHON PLUGIN FOR THE 'AURA FORGE' FRAMEWORK.

TASK: Create a plugin based on this mission objective: "{description}"

CORE ARCHITECTURE RULES:
1. CLASS STRUCTURE: Follow the template exactly. Inherit from 'AuraPlugin'.
2. IMPORTS: Use 'from aura.modules.forge.base import AuraPlugin'. Do not import nonexistent modules.
3. OUTPUT: The 'run' method MUST return a dict with a list of 'findings'.
4. FINDING FORMAT: {{"type": "Vulnerability Category", "detail": "Technical specifics", "severity": "CRITICAL|HIGH|MEDIUM|LOW", "status": "Confirmed"}}
5. STEALTH & PERFORMANCE: Use asynchronous programming ('async/await'). Implement professional error handling.

TECHNICAL GUIDANCE:
- If checking for exposed files (e.g., .env, .git), use 'aiohttp' or similar for async requests.
- If performing port analysis, focus on service identification.
- ENSURE the code is production-ready, highly optimized, and follows Python best practices (PEP8).

TEMPLATE:
from aura.modules.forge.base import AuraPlugin
import aiohttp
import asyncio

class AuraForgeGeneratedPlugin(AuraPlugin):
    @property
    def name(self): return "AI_Generated_Plugin"
    
    @property
    def description(self): return "{description}"

    @property
    def version(self): return "1.0.0"

    async def run(self, target, data=None):
        findings = []
        # MISSION LOGIC HERE (Use target as the string domain/IP)
        # Results MUST follow the finding format rule.
        return {{"findings": findings}}

RETURN ONLY THE COMPLETED PYTHON CODE. NO MARKDOWN BLOCKS. NO INTRODUCTIONS. NO EXPLANATIONS.
"""

    async def generate_plugin(self, description: str, filename: str = None) -> str:
        """Asks the brain to write a plugin and saves it to the plugins directory."""
        prompt = self._generate_prompt(description)
        
        # We use the brain's reasoning engine (which uses the underlying LLM)
        # Note: In a real scenario, this would call the LLM API directly for code generation.
        # Since we are in a simulated assistant environment, we will 'simulate' the AI writing the code 
        # or call a specific generation function if available.
        # For now, we will use the brain to generate the 'logic' and wrap it.
        
        code = self.brain.reason(prompt)
        
        # Clean the code if returned with markdown blocks
        if "```python" in code:
            code = code.split("```python")[1].split("```")[0].strip()
        elif "```" in code:
            code = code.split("```")[1].split("```")[0].strip()
            
        if not filename:
            filename = description.lower().replace(" ", "_").replace("/", "_")[:30] + "_ai.py"
        
        if not filename.endswith(".py"):
            filename += ".py"
            
        filepath = os.path.join(self.plugins_dir, filename)
        with open(filepath, "w") as f:
            f.write(code)
            
        return filepath
