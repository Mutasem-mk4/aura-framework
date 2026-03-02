import os
import sys

# Add project root to path
sys.path.append(os.path.abspath("."))

from aura.core.reporter import AuraReporter
from aura.core.storage import AuraStorage

def test_reporting():
    db_path = "test_aura.db"
    if os.path.exists(db_path): os.remove(db_path)
    
    storage = AuraStorage(db_path)
    # Mock a target
    target_id = storage.save_target({"target": "enterprise-target.com", "type": "Domain", "risk_score": 9, "priority": "CRITICAL"})
    
    # Mock findings
    storage.add_finding("enterprise-target.com", "SQL Injection vulnerability in /api/v1/user", "SQL Injection", proof="' UNION SELECT @@version--")
    storage.add_finding("enterprise-target.com", "Sensitive .env file exposed at root", "Sensitive File Exposure")
    
    reporter = AuraReporter(db_path)
    
    print("[*] Generating HTML Report...")
    html_path = reporter.generate_report()
    print(f"[+] HTML Report generated: {html_path}")
    
    print("[*] Generating PDF Report...")
    try:
        pdf_path = reporter.generate_pdf_report()
        print(f"[+] PDF Report generated: {pdf_path}")
    except Exception as e:
        print(f"[!] PDF Report failed: {e}")

if __name__ == "__main__":
    test_reporting()
