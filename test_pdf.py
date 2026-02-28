from aura.core.reporter import AuraReporter
import os

reporter = AuraReporter("aura_intel.db")
path = reporter.generate_pdf_report("test_aura_report.pdf")

if os.path.exists(path):
    print(f"[+] PDF Report generated successfully: {path}")
    print(f"[+] File size: {os.path.getsize(path)} bytes")
else:
    print("[!] Failed to generate PDF Report.")
