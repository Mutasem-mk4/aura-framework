import py_compile
import glob

with open("errors.log", "w", encoding="utf-8") as f1:
    for filepath in glob.glob(r"C:\Users\User\.gemini\antigravity\scratch\aura\**\*.py", recursive=True):
        if "nexus_zenith" in filepath: continue
        if "venv" in filepath: continue
        try:
            py_compile.compile(filepath, doraise=True)
        except Exception as e:
            f1.write(f"{filepath}\n")
