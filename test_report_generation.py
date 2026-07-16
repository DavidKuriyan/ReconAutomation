"""
Quick test script to verify the consolidated reporting pipeline works.
Generates an HTML report using ReportGenerator with the new external template.
"""

import sys
import os

# Add orchestrator directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'orchestrator'))

from modules.reporting import ReportGenerator

def main():
    target = "srcas.ac.in"
    target_id = 44  # Known target with data in the DB
    
    print(f"[*] Generating report for {target} (ID: {target_id})...")
    reporter = ReportGenerator(target, target_id)
    
    print("[*] Generating HTML report...")
    html_path = reporter.generate_html()
    print(f"[+] HTML report saved to: {html_path}")
    print(f"[+] File exists: {os.path.exists(html_path)}")
    print(f"[+] File size: {os.path.getsize(html_path)} bytes")
    
    print("[*] Generating PDF report...")
    pdf_path = reporter.generate_pdf()
    if pdf_path:
        print(f"[+] PDF report saved to: {pdf_path}")
        print(f"[+] File exists: {os.path.exists(pdf_path)}")
        print(f"[+] File size: {os.path.getsize(pdf_path)} bytes")
    else:
        print("[-] PDF generation failed (xhtml2pdf limitations expected)")
    
    print("\n[Done] Report generation completed.")
    return html_path

if __name__ == "__main__":
    main()
