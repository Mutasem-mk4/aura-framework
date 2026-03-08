from aura.core.storage import AuraStorage
import os

db = AuraStorage("aura_intel.db")
db.add_finding(1, "Potential SQL Injection in /login", "SQLi")
print("[+] Test finding added.")

findings = db.get_all_findings()
print(f"[+] Current findings in DB: {len(findings)}")
for f in findings:
    print(f"ID: {f['id']} | Content: {f['content']} | Status: {f['status']}")
