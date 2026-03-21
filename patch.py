import sys, re
path = r"C:\Users\User\.gemini\antigravity\scratch\aura\aura\core\orchestrator.py"
with open(path, "r", encoding="utf-8") as f:
    text = f.read()

patched = re.sub(
    r'(def __getattr__\(self,\s*name\):(?:.*?)"""[^"]+"""\s*)(async def noop)', 
    r'\1if name.startswith("__") and name.endswith("__"):\n                    raise AttributeError(f"MockEngine has no attribute {name}")\n                \2', 
    text, flags=re.DOTALL
)

if text != patched:
    with open(path, "w", encoding="utf-8") as f:
        f.write(patched)
    print("Patched successfully via regex")
else:
    print("Regex failed to match")
