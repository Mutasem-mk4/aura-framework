import py_compile
import glob

for filepath in glob.glob(r"C:\Users\User\.gemini\antigravity\scratch\aura\**\*.py", recursive=True):
    if "nexus_zenith" in filepath[-20:]: continue
    if "venv" in filepath: continue
    try:
        py_compile.compile(filepath, doraise=True)
    except Exception as e:
        print(f"ERROR: {filepath}: {e}")
