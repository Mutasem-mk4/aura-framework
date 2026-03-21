import sys
import os

# Add the project root to sys.path
sys.path.append(os.getcwd())

try:
    print("[*] Testing imports...")
    from aura.modules import run_ast_audit
    print("[+] run_ast_audit imported successfully.")
    
    from aura.modules import run_logic_fuzz
    print("[+] run_logic_fuzz imported successfully.")
    
    from aura.core.orchestrator import NeuralOrchestrator
    print("[+] NeuralOrchestrator imported successfully.")
    
    import aura_main
    print("[+] aura_main imported successfully.")
    
    print("[SUCCESS] All core imports are working.")
except Exception as e:
    print(f"[FAILURE] Import error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
