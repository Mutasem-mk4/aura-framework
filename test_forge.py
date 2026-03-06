import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
from aura.modules.neural_forge import NeuralForge

def test_forge():
    print("[+] Initializing Neural Forge...")
    forge = NeuralForge()
    
    base_xss = "<script>alert(1)</script>"
    print(f"\n[XSS] Mutating base payload: {base_xss}")
    xss_mutations = forge.forge_payloads(base_xss, max_variations=5)
    for i, m in enumerate(xss_mutations):
        print(f"  {i+1}: {m}")
        
    base_sqli = "' OR 1=1--"
    print(f"\n[SQLi] Mutating base payload: {base_sqli}")
    sqli_mutations = forge.forge_payloads(base_sqli, max_variations=5)
    for i, m in enumerate(sqli_mutations):
        print(f"  {i+1}: {m}")

    print("\n[POLYGLOTS] Retrieving Universal XSS Polyglots:")
    polyglots = forge.get_xss_polyglots()
    for i, p in enumerate(polyglots[:3]):  # Just print 3
        print(f"  Polyglot {i+1}: {p[:100]}...")

if __name__ == "__main__":
    test_forge()
