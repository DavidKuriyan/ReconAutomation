"""
Full scan test script - runs the complete orchestrated scan on a target domain,
then generates HTML and PDF reports automatically.
This bypasses the interactive consent/report prompts.
"""

import sys
import os
import time

# Fix stdout encoding for Unicode emoji characters used by the orchestrator
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# Add orchestrator directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'orchestrator'))

from orchestrator import ReconEngine, DatabaseManager
from modules.reporting import ReportGenerator
from config import config, Colors


def run_full_scan(target):
    """Run a full scan on target and generate reports."""
    
    print("=" * 70)
    print("FULL SCAN TEST: " + target)
    print("=" * 70)
    
    # Setup config for testing
    config.REQUIRE_CONSENT = False  # Skip consent
    
    # Create engine with consent flag
    engine = ReconEngine(target, consent_given=True, scan_mode='full')
    engine.consent_given = True
    
    # Override prompt_reporting to proceed automatically
    def auto_report():
        """Generate both HTML and PDF reports automatically."""
        print("\n" + "=" * 70)
        print("AUTOMATIC REPORT GENERATION")
        print("=" * 70)
        
        reporter = ReportGenerator(engine.target, engine.target_id)
        
        print("[*] Generating HTML Report...")
        html_path = reporter.generate_html()
        print(f"  + HTML saved to: {html_path}")
        
        print("[*] Generating PDF Report...")
        pdf_path = reporter.generate_pdf()
        if pdf_path:
            print(f"  + PDF saved to: {pdf_path}")
        else:
            print("  [!] PDF generation failed")
            
        return html_path, pdf_path
    
    engine.prompt_reporting = auto_report
    
    # Run the scan
    try:
        start_time = time.time()
        engine.execute()
        elapsed = time.time() - start_time
        print(f"\nSCAN COMPLETED in {elapsed:.1f}s")
        print(f"  Target: {target} (ID: {engine.target_id})")
        return engine.target_id
    except Exception as e:
        print(f"\n[!] Scan failed: {e}")
        import traceback
        traceback.print_exc()
        return None


def verify_results(target, target_id):
    """Verify the scan results in the database."""
    if not target_id:
        return
    
    print("\n" + "=" * 70)
    print("VERIFYING SCAN RESULTS")
    print("=" * 70)
    
    db = DatabaseManager(config.DB_PATH)
    if not db.connect():
        print("[-] Could not connect to database")
        return
    
    try:
        cursor = db.conn.cursor()
        
        # Domain info / WHOIS
        cursor.execute("SELECT * FROM domain_info WHERE target_id=?", (target_id,))
        domain = cursor.fetchone()
        if domain:
            print("\n+ WHOIS Data:")
            print(f"  Registrar: {domain[2] if len(domain) > 2 else 'N/A'}")
            print(f"  Created: {domain[3] if len(domain) > 3 else 'N/A'}")
            print(f"  Expires: {domain[4] if len(domain) > 4 else 'N/A'}")
        else:
            print("\n  No WHOIS data found")
        
        # Technologies
        cursor.execute("SELECT name, category, version FROM technologies WHERE target_id=?", (target_id,))
        techs = cursor.fetchall()
        print("\n+ Technologies (" + str(len(techs)) + "):")
        for t in techs:
            ver = " v" + t[2] if t[2] else ""
            print(f"  * {t[0]} ({t[1]}){ver}")
        
        # Findings (tech-related)
        cursor.execute("SELECT title, severity FROM findings WHERE target_id=? AND title LIKE 'Tech Stack:%'", (target_id,))
        tech_findings = cursor.fetchall()
        print("\n+ Technology Findings (" + str(len(tech_findings)) + "):")
        for f in tech_findings[:10]:
            print(f"  [{f[1]}] {f[0]}")
        if len(tech_findings) > 10:
            print(f"  ... and {len(tech_findings) - 10} more")
        
        # All findings
        cursor.execute("SELECT severity, COUNT(*) FROM findings WHERE target_id=? GROUP BY severity", (target_id,))
        findings_summary = cursor.fetchall()
        print("\n+ All Findings Summary:")
        for severity, count in findings_summary:
            print(f"  {severity}: {count}")
        
        # Risk score
        cursor.execute("SELECT risk_score FROM targets WHERE id=?", (target_id,))
        score = cursor.fetchone()
        print(f"\n+ Risk Score: {score[0] if score else 'N/A'}/100")
        
        # SSL
        cursor.execute("SELECT valid_to, issuer FROM ssl_info WHERE target_id=?", (target_id,))
        ssl = cursor.fetchone()
        if ssl:
            print("\n+ SSL/TLS:")
            print(f"  Valid Until: {ssl[0]}")
            print(f"  Issuer: {ssl[1][:80] if ssl[1] else 'N/A'}")
        
        # Ports
        cursor.execute("SELECT port, service, protocol FROM ports WHERE target_id=?", (target_id,))
        ports = cursor.fetchall()
        if ports:
            print("\n+ Open Ports (" + str(len(ports)) + "):")
            for p in ports[:5]:
                print(f"  {p[0]}/{p[2]} ({p[1]})")
            if len(ports) > 5:
                print(f"  ... and {len(ports) - 5} more")
        
    except Exception as e:
        print(f"[-] Verification error: {e}")
    finally:
        db.close()


def find_report(target_domain):
    """Find the most recently generated report for this target."""
    reports_dir = os.path.join(os.path.dirname(__file__), 'reporter', 'reports')
    if not os.path.exists(reports_dir):
        return None
    
    html_files = [f for f in os.listdir(reports_dir) if f.endswith('.html') and target_domain in f]
    if not html_files:
        return None
    
    # Get the most recent
    html_files.sort(reverse=True)
    return os.path.join(reports_dir, html_files[0])


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "srcas.ac.in"
    
    target_id = run_full_scan(target)
    verify_results(target, target_id)
    
    # Find and report the generated HTML path
    report_path = find_report(target)
    if report_path:
        print(f"\nReport: {report_path}")
    
    print("\nFull scan test complete.")
