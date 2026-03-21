import re
import math
from aura.ui.formatter import console

def calculate_entropy(s):
    if not s: return 0
    probs = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    return - sum([p * math.log(p) / math.log(2.0) for p in probs])

SECRET_PATTERNS = [
    r'(?:[Aa][Pp][Ii]|[Kk][Ee][Yy]|[Ss][Ee][Cc][Rr][Ee][Tt])[a-zA-Z0-9_\-]*[\s:=]+[\'"]([a-zA-Z0-9\-_]{20,})[\'"]',
    r'([\'"][a-zA-Z0-9\-_+/]{40,}=?[\'"])', # Base64-like
    r'AKIA[0-9A-Z]{16}', # AWS Access Key
    r'glpat-[a-zA-Z0-9\-]{20}', # GitLab PAT
    r'-----BEGIN [A-Z ]+ PRIVATE KEY-----'
]

def scan_file(filepath):
    console.print(f"[bold cyan]🔍 AURA DEEP SECRET SCAN: {filepath}[/bold cyan]")
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            
            # Pattern Matching
            for p in SECRET_PATTERNS:
                matches = re.finditer(p, content)
                for m in matches:
                    secret = m.group()
                    entropy = calculate_entropy(secret)
                    if entropy > 3.5: # Threshold for high entropy
                        console.print(f"  [bold green][!] POTENTIAL SECRET FOUND (Entropy: {entropy:.2f})[/bold green]")
                        console.print(f"    [white]{secret[:50]}...[/white]")
            
            # General Entropy Hunt (Slow but deep)
            words = re.findall(r'[\'"]([a-zA-Z0-9\-_]{32,})[\'"]', content)
            for w in words:
                entropy = calculate_entropy(w)
                if entropy > 4.2: # Very high entropy for strings
                    console.print(f"  [bold yellow][?] HIGH ENTROPY STRING FOUND (Entropy: {entropy:.2f})[/bold yellow]")
                    console.print(f"    [white]{w}[/white]")
                    
    except Exception as e:
        console.print(f"  [red]Error: {e}[/red]")

if __name__ == "__main__":
    scan_file("C:\\Users\\User\\.gemini\\antigravity\\scratch\\aura\\main.bc0c9c49.chunk.js")
