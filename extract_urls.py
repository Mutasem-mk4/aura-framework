import re
from aura.ui.formatter import console

def extract(filepath):
    console.print(f"[bold cyan]🔍 AURA URL EXTRACTOR: {filepath}[/bold cyan]")
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = f.read()
            # Find relative paths starting with /
            paths = re.findall(r'[\'"](/[a-zA-Z0-9/\-_?=&]+)[\'"]', data)
            # Find full URLs
            urls = re.findall(r'[\'"](https?://[a-zA-Z0-9\.\-_/]+)[\'"]', data)
            
            unique_results = sorted(list(set(paths + urls)))
            
            console.print(f"[bold green][!] FOUND {len(unique_results)} UNIQUE STRINGS[/bold green]")
            with open("uber_endpoints_extracted.txt", "w") as out:
                for u in unique_results:
                    if len(u) > 8: # Filter out short noise
                        out.write(u + "\n")
                        if "admin" in u.lower() or "config" in u.lower() or "debug" in u.lower() or "internal" in u.lower():
                            console.print(f"  [bold yellow][!] SENSITIVE MATCH: {u}[/bold yellow]")
                        else:
                            pass # Too many to print all
    except Exception as e:
        console.print(f"  [red]Error: {e}[/red]")

if __name__ == "__main__":
    extract("C:\\Users\\User\\.gemini\\antigravity\\scratch\\aura\\uber_main.js")
