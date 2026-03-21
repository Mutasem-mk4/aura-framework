import asyncio
import re
import os
import json
from aura.ui.formatter import console

class SemanticScanner:
    def __init__(self, bundle_path):
        self.bundle_path = bundle_path
        self.findings = []

    def scan(self):
        console.print(f"[bold cyan]💀 AURA SEMANTIC SCANNER: ANALYZING {os.path.basename(self.bundle_path)}[/bold cyan]")
        
        if not os.path.exists(self.bundle_path):
            return []

        with open(self.bundle_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Semantic Patterns: Looking for relationships
        # 1. Config Object Mapping
        config_blocks = re.findall(r'(?:config|env|settings)\s*=\s*(\{.*?\});', content, re.DOTALL)
        for block in config_blocks:
            if "internal" in block or "staff" in block or "debug" in block:
                self.findings.append({"type": "Sensitive Config Block", "data": block[:100]})

        # 2. API Gateway Authorization Flow
        auth_calls = re.findall(r'(\w+)\.Authorization\s*=\s*[\"\']Bearer\s+([\w\-\.]{10,})[\"\']', content)
        for caller, token in auth_calls:
            self.findings.append({"type": "Hardcoded Bearer Token", "caller": caller, "token": token})

        # 3. Conditional Staff Checks
        staff_logic = re.findall(r'if\s*\((?:window\.|this\.)?(?:isStaff|isAdmin|internalUser)\)\s*\{', content)
        if staff_logic:
            self.findings.append({"type": "Staff Conditional Logic", "count": len(staff_logic)})

        return self.findings

async def main():
    # Example analysis on a previously identified bundle
    bundle = "C:\\Users\\User\\.gemini\\antigravity\\scratch\\aura\\auth_uber.js"
    scanner = SemanticScanner(bundle)
    results = scanner.scan()
    
    print(f"\n[bold green][!] SEMANTIC SCAN COMPLETE. Found {len(results)} high-value relationships.[/bold green]")
    for r in results:
        print(f"  [+] {r}")

if __name__ == "__main__":
    asyncio.run(main())
