import os
import sys
from dotenv import load_dotenv

# Add the current directory to sys.path to find 'aura' package
sys.path.append(os.getcwd())

load_dotenv()

from aura.core.brain import AuraBrain
from aura.core import state

brain = AuraBrain()
print(f"--- AURA BRAIN STATUS ---")
print(f"Enabled: {brain.enabled}")
print(f"Active Provider: {brain.active_provider}")
print(f"Disabled Providers: {brain.disabled_providers}")
print(f"Ollama Model: {state.OLLAMA_MODEL}")
print(f"-------------------------")

# Test a simple query
# print("Testing AI Query...")
# res = brain.reason({"target": "test site"})
# print(f"AI Response: {res[:100]}...")
