"""
Quick test: generate a sample professional report from a simulated finding.
"""
import json
from aura.modules.ai_analyst import ProfessionalReportGenerator

# Simulate a real BOLA finding (like what idor_engine_v2 would produce)
sample_bola_finding = {
    "type": "BOLA",
    "method": "GET",
    "url": "https://www.iciparisxl.nl/api/v1/addresses/12345",
    "attacker_status": 200,
    "attacker_len": 512,
    "victim_status": 200,
    "victim_len": 487,
    "victim_body_snippet": '{"id": 12345, "user_id": 999, "email": "victim@test.com", "street": "Main St 1", "city": "Amsterdam", "phone": "+31612345678"}',
    "reason": "Both accounts received identical response — no ownership verification"
}

# Simulate an XSS finding
sample_xss_finding = {
    "type": "XSS",
    "method": "POST",
    "url": "https://www.iciparisxl.nl/api/reviews/submit",
    "severity": "High"
}

def main():
    print("Testing ProfessionalReportGenerator...")
    gen = ProfessionalReportGenerator(output_dir="./reports")

    # Generate BOLA report
    print("\n[1/2] Generating BOLA report...")
    report_md, title, severity = gen.generate_report(sample_bola_finding, platform="intigriti")
    with open("reports/test_bola_report.md", "w", encoding="utf-8") as f:
        f.write(report_md)
    print(f"✅ BOLA Report generated: reports/test_bola_report.md")
    print(f"   Title: {title}")
    print(f"   Severity: {severity}")
    print(f"   Report length: {len(report_md)} chars")

    # Generate XSS report
    print("\n[2/2] Generating XSS report...")
    report_md2, title2, severity2 = gen.generate_report(sample_xss_finding, platform="hackerone")
    with open("reports/test_xss_report.md", "w", encoding="utf-8") as f:
        f.write(report_md2)
    print(f"✅ XSS Report generated: reports/test_xss_report.md")
    print(f"   Title: {title2}")
    print(f"   Severity: {severity2}")

    print("\n✅ All tests passed! Check ./reports/test_*.md")

if __name__ == "__main__":
    main()
