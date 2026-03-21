from aura.core.storage import AuraStorage
import json

s = AuraStorage()
findings = s.get_all_findings()
highs = [f for f in findings if f.get("severity") in ["CRITICAL", "HIGH"]]
print(f"Total vulnerabilities captured so far: {len(highs)}")
for f in highs:
    print(f" - [{f.get('severity')}] {f.get('type')}: {f.get('url')[:60]}")
