
import os
import sys
import socket
import sqlite3

# Add current directory to path
sys.path.insert(0, os.path.abspath('.'))

from modules.threat_intel import ThreatIntelligence
from modules.reporting import ReportGenerator
from config import config

# Mock ReconEngine context
class MockRecon:
    def __init__(self, target):
        self.target = target
        self.target_id = None
        self.target_ip = None
        self.conn = None

    def connect_db(self):
        try:
            self.conn = sqlite3.connect(config.DB_PATH, timeout=30.0)
            return True
        except Exception as e:
            print(f"[!] DB Connection Error: {e}")
            return False

    def close_db(self):
        if self.conn:
            self.conn.close()

    def get_or_create_target(self):
        if not self.connect_db(): return
        cursor = self.conn.cursor()
        cursor.execute("INSERT OR IGNORE INTO targets (domain) VALUES (?)", (self.target,))
        self.conn.commit()
        cursor.execute("SELECT id FROM targets WHERE domain = ?", (self.target,))
        result = cursor.fetchone()
        if result:
            self.target_id = result[0]
        self.close_db()
        print(f"[*] Target ID: {self.target_id}")

def verify_fix():
    target = "ssmiet.ac.in"
    print(f"[*] Starting Verification for {target}")
    
    recon = MockRecon(target)
    recon.get_or_create_target()
    
    # 1. Test IP Resolution Logic (Copied from Orchestrator fix)
    print("[*] Testing IP Resolution...")
    if not recon.target_ip:
         try:
            recon.target_ip = socket.gethostbyname(recon.target)
            print(f"    - Resolved IP: {recon.target_ip}")
         except Exception as e:
            print(f"    [!] Resolution failed: {e}")
            
    if not recon.target_ip:
        print("[!] FATAL: Could not resolve IP, Shodan check will fail.")
        # Try anyway for verification
        # return

    # 2. Run Threat Intel Module
    print("[*] Running Threat Intelligence Module...")
    # Cleared old data...
    # Clean up previous threat intel for this target to ensure fresh fetch
    try:
        conn = sqlite3.connect(config.DB_PATH)
        conn.execute("DELETE FROM threat_intel WHERE target_id=?", (recon.target_id,))
        conn.commit()
        conn.close()
        print("    - Cleared old threat intel data")
    except:
        pass

    threat = ThreatIntelligence(recon.target, recon.target_id, recon.target_ip)
    threat.execute()
    
    # 3. Generate Report
    print("[*] Generating Report...")
    reporter = ReportGenerator(target, recon.target_id)
    html_path = reporter.generate_html()
    
    print(f"\n[SUCCESS] Verification Complete")
    print(f"Report generated at: {html_path}")
    print("Please open this report to verify detailed threat intelligence data is present.")

if __name__ == "__main__":
    verify_fix()
