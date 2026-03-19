import sys
import os

# Añadir el directorio raíz al path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.h1_formatter import H1Formatter

def test_h1_formatter():
    target = "playtika.com"
    formatter = H1Formatter(target)
    
    findings = [
        {"url_archivo": "https://playtika.com/config.js", "tipo_secreto": "AWS_KEY"}
    ]
    fuzz_findings = [
        {"url": "https://playtika.com/robots.txt", "path": "robots.txt"}
    ]
    
    report = formatter.format_report(findings, fuzz_findings)
    
    print("--- REPORT START ---")
    print(report)
    print("--- REPORT END ---")
    
    if "Tier 1" in report and "AWS_KEY" in report and "robots.txt" in report:
        print("\n✅ Verification SUCCESS: Report generated correctly with expected content.")
    else:
        print("\n❌ Verification FAILED: Some elements are missing from the report.")

if __name__ == "__main__":
    test_h1_formatter()
