import os
import sys

# Add the project root to sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from aura.core.brain import AuraBrain
from aura.core import state

def test_fallback():
    print("[*] Testing Fallback Logic (No API Key)...")
    state.GEMINI_API_KEY = None
    brain = AuraBrain()
    result = brain.reason({"target": "jenkins.test.com"})
    print(f"Result: {result}")
    if "Jenkins instances" in result:
        print("[✔] Fallback to rules successful.")
    else:
        print("[✘] Fallback failed.")

def test_init_with_key():
    print("\n[*] Testing Init with Mock API Key...")
    state.GEMINI_API_KEY = "test_key_123"
    brain = AuraBrain()
    if brain.enabled:
        print("[✔] Gemini Engine flagged as enabled (logical check).")
    else:
        print("[✘] Gemini Engine should be enabled with key.")

if __name__ == "__main__":
    test_fallback()
    test_init_with_key()
