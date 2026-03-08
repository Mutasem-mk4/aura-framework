import os
import sys

# Add project root to path
sys.path.append(os.path.abspath("."))

from aura.core.markdown_reporter import MarkdownReporter
from aura.core.platform_reporter import PlatformReporter

def test_reporting():
    # Test MarkdownReporter
    print("[*] Generating HackerOne Markdown Report...")
    md_reporter = MarkdownReporter()
    # It defaults to aura_intel.db because AuraStorage() defaults there if not specified
    md_path = md_reporter.generate_report()
    if md_path:
        print(f"[+] HackerOne Markdown Report generated: {md_path}")
    else:
        print("[-] HackerOne Markdown Report failed to generate (or no findings).")

    # Test PlatformReporter (Intigriti fallback)
    print("\n[*] Generating Intigriti Submissions Report...")
    pf_reporter = PlatformReporter()
    pf_path = pf_reporter.generate("intigriti")
    if pf_path:
        print(f"[+] Intigriti Submission Report generated: {pf_path}")
    else:
        print("[-] Intigriti Submission Report failed to generate (or no findings).")

if __name__ == "__main__":
    test_reporting()
