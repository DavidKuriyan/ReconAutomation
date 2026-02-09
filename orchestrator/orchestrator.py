"""
Orchestrator Module for Aether-Recon OSINT Framework
Coordinates the execution of all reconnaissance modules, handles database connections,
and manages the overall scan workflow with defensive coding practices.
"""

import os
import sys
import time
import sqlite3
import concurrent.futures
import socket
from urllib.parse import urlparse
from typing import List, Optional, Any

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import config, Colors
from modules.geo_intelligence import GeoIntelligence
from modules.socmint import SocialIntelligence
from modules.breach_intel import BreachIntelligence
from modules.threat_intel import ThreatIntelligence
from modules.metadata_extractor import MetadataExtractor
from modules.historical_intel import HistoricalIntelligence
from modules.search_intel import SearchIntelligence
from modules.reporting import ReportGenerator

# New Modular Imports
from modules.passive_recon import PassiveRecon
from modules.active_recon import ActiveRecon
from modules.web_analysis import WebAnalysis

# Configuration
DB_PATH = "../reporter/argus.db"

# Initialize Colorama
try:
    from colorama import init
    init(autoreset=True)
except ImportError:
    pass

class DatabaseManager:
    """
    Context manager for safe SQLite database operations.
    Handles connection opening, closing, and error logging.
    """
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = None

    def connect(self) -> bool:
        """Establish database connection with retry logic."""
        try:
            self.conn = sqlite3.connect(self.db_path, timeout=30.0)
            self.conn.execute("PRAGMA journal_mode=WAL;")
            return True
        except sqlite3.Error as e:
            print(f"{Colors.ERROR}[!] Database Connection Failed: {e}{Colors.RESET}")
            return False

    def close(self):
        """Safely close the database connection."""
        if self.conn:
            try:
                self.conn.close()
            except sqlite3.Error:
                pass
            self.conn = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

class ReconEngine:
    """
    Main engine specifically for orchestrating the scan process.
    """
    def __init__(self, target: str, consent_given: bool = False, scan_mode: str = 'full', custom_modules: List[str] = None):
        self.target = self._normalize_target(target)
        self.target_id: Optional[int] = None
        self.target_ip: Optional[str] = None
        self.consent_given = consent_given
        self.scan_mode = scan_mode
        self.custom_modules = custom_modules or []
        self.db = DatabaseManager(DB_PATH)
        
        # Instantiate sub-modules
        self.passive = PassiveRecon(self.target, 0, self.db) # ID updated later
        self.active = ActiveRecon(self.target, 0, self.db)   # ID updated later

    def _normalize_target(self, target: str) -> str:
        """Sanitize and normalize target input."""
        target = target.strip()
        if "://" in target:
             parsed = urlparse(target)
             return parsed.netloc
        return target.replace("/", "")

    def get_or_create_target(self):
        """Register the target in the database and retrieve its ID."""
        if not self.db.connect():
             print(f"{Colors.ERROR}[!] Critical: Could not connect to database.{Colors.RESET}")
             sys.exit(1)
             
        cursor = self.db.conn.cursor()
        try:
            cursor.execute("INSERT OR IGNORE INTO targets (domain) VALUES (?)", (self.target,))
            self.db.conn.commit()
            cursor.execute("SELECT id FROM targets WHERE domain = ?", (self.target,))
            result = cursor.fetchone()
            if result:
                self.target_id = result[0]
                # Update sub-modules with correct ID
                self.passive.target_id = self.target_id
                self.active.target_id = self.target_id
                
            print(f"[*] Target ID: {self.target_id}")
        except sqlite3.Error as e:
            print(f"{Colors.ERROR}[!] Failed to register target: {e}{Colors.RESET}")
        finally:
            self.db.close()

    def check_consent(self) -> bool:
        """
        Enforce ethical usage guidelines with a robust consent mechanism.
        """
        if self.consent_given:
            print(f"{Colors.INFO}[*] Consent flag provided, skipping interactive check.{Colors.RESET}")
            return True
        
        if not config.REQUIRE_CONSENT:
            return True
        
        print("\n" + "="*70)
        print(f"{Colors.BANNER}LEGAL DISCLAIMER - ETHICAL OSINT FRAMEWORK{Colors.RESET}")
        print("="*70)
        print("\nThis tool performs Open Source Intelligence gathering.")
        print(f"\n{Colors.WARNING}⚠️  WARNING: Unauthorized scanning may be ILLEGAL in your jurisdiction.{Colors.RESET}")
        print("\nYou MUST have explicit authorization to scan this target.")
        print("By proceeding, you confirm that:")
        print("  1. You have permission to scan the target domain")
        print("  2. You will use findings ethically and legally")
        print("  3. You have read ETHICAL_GUIDELINES.md")
        print("\nTo confirm, please type: 'I am authorized'")
        print("="*70)
        
        response = input(f"\n{Colors.INPUT}> {Colors.RESET}")
        
        if response.lower().strip().replace("'", "").replace('"', "") == "i am authorized":
            print(f"{Colors.SUCCESS}[✓] Consent confirmed. Proceeding...{Colors.RESET}\n")
            return True
        else:
            print(f"{Colors.ERROR}[!] Consent NOT confirmed. Exiting for safety.{Colors.RESET}")
            return False

    def log_audit(self, action: str, module_name: str = "", notes: str = ""):
        """Log actions to the audit table for accountability."""
        if not config.AUDIT_LOGGING: return
        
        if self.db.connect():
            try:
                cursor = self.db.conn.cursor()
                cursor.execute("""
                    INSERT INTO audit_log (target_id, action, module_name, consent_given, notes)
                    VALUES (?, ?, ?, ?, ?)
                """, (self.target_id, action, module_name, self.consent_given, notes))
                self.db.conn.commit()
            except sqlite3.Error:
                pass # Fail silently for audit logs to avoid disrupting scan
            finally:
                self.db.close()

    def should_run(self, module_type: str) -> bool:
        """Determine if a module should run based on the selected scan mode."""
        if self.scan_mode == 'full': return True
        if self.scan_mode == 'active': return module_type in ['active', 'search', 'threat', 'web']
        if self.scan_mode == 'passive': return module_type in ['passive', 'geo', 'email', 'meta']
        if self.scan_mode == 'custom': return module_type in self.custom_modules
        return False

    def resolve_target_ip(self):
        """Resolve target IP with error handling."""
        try:
            self.target_ip = socket.gethostbyname(self.target)
            print(f"{Colors.INFO}    - Resolved IP: {self.target_ip}{Colors.RESET}")
        except socket.gaierror:
            print(f"{Colors.WARNING}    [!] Could not resolve IP address for {self.target}{Colors.RESET}")

    def execution_wrapper(self, func, module_name: str):
        """
        Defensive wrapper for module execution.
        Captures exceptions to prevent total crash.
        """
        try:
            func()
            self.log_audit("module_success", module_name)
        except Exception as e:
            print(f"{Colors.ERROR}[!] {module_name} Failed: {e}{Colors.RESET}")
            self.log_audit("module_failure", module_name, str(e))

    def calculate_risk_score(self):
        """Calculate and update the final risk score."""
        print(f"{Colors.INFO}[*] Calculating comprehensive risk score...{Colors.RESET}")
        if not self.db.connect(): return
        
        try:
            cursor = self.db.conn.cursor()
            score = 0
            
            # 1. Findings
            cursor.execute("SELECT severity FROM findings WHERE target_id=?", (self.target_id,))
            for (severity,) in cursor.fetchall():
                if severity == 'Critical': score += 20
                elif severity == 'High': score += 10
                elif severity == 'Medium': score += 5
                elif severity == 'Low': score += 1
            
            # 2. Ports
            cursor.execute("SELECT port FROM ports WHERE target_id=?", (self.target_id,))
            critical_ports = {21, 22, 23, 25, 445, 3389}
            for (port,) in cursor.fetchall():
                score += 10 if port in critical_ports else 1
            
            # 3. Existing Threat Intel
            cursor.execute("SELECT risk_score FROM targets WHERE id=?", (self.target_id,))
            row = cursor.fetchone()
            current = row[0] if row else 0
            
            final_score = min(max(score, current), 100)
            
            cursor.execute("UPDATE targets SET risk_score = ? WHERE id = ?", (final_score, self.target_id))
            self.db.conn.commit()
            print(f"{Colors.SUCCESS}    ✓ Final Risk Score: {final_score}/100{Colors.RESET}")
            
        except Exception as e:
            print(f"{Colors.ERROR}[!] Risk calculation error: {e}{Colors.RESET}")
        finally:
            self.db.close()

    def prompt_reporting(self):
        """Interact with the user to generate reports."""
        print("\n" + "="*70)
        print("📝 REPORT GENERATION")
        print("="*70)
        print("1. HTML Report (Responsive, interactive)")
        print("2. PDF Report (Professional, printable)")
        print("3. Both")
        print("4. Skip")
        
        try:
            choice = input(f"\n{Colors.INPUT}Enter choice (1-4): {Colors.RESET}")
            reporter = ReportGenerator(self.target, self.target_id)
            
            if choice in ['1', '3']:
                print("[*] Generating HTML Report...")
                path = reporter.generate_html()
                print(f"{Colors.SUCCESS}    ✓ Saved to: {path}{Colors.RESET}")
                
            if choice in ['2', '3']:
                print("[*] Generating PDF Report...")
                path = reporter.generate_pdf()
                if path:
                    print(f"{Colors.SUCCESS}    ✓ Saved to: {path}{Colors.RESET}")
                else:
                    print(f"{Colors.WARNING}    [!] PDF generation failed (check logs){Colors.RESET}")
        except KeyboardInterrupt:
            print("\n[!] Reporting cancelled.")

    def execute(self):
        """
        Main execution flow.
        """
        print("\n" + "="*70)
        print(f"{Colors.BANNER}🛰️  AETHER-RECON v2.0 - Enhanced OSINT Framework{Colors.BANNER}")
        print("="*70)
        
        # 1. Consent
        if not self.check_consent():
            return

        # 2. Config Status
        config.print_status()
        
        # 3. Target Init
        self.get_or_create_target()
        if not self.target_id:
            return

        # 4. Phase 1: Passive Recon
        if self.should_run('passive'):
            print(f"\n{Colors.HEADER}PHASE 1: PASSIVE RECONNAISSANCE{Colors.RESET}")
            print("="*50)
            
            self.execution_wrapper(self.passive.run_whois, "WHOIS")
            self.execution_wrapper(self.passive.run_dns_enum, "DNS Enumeration")
            
            # Module: Geolocation
            if config.ENABLE_GEOLOCATION:
                print(f"{Colors.INFO}[+] Running Geolocation Intelligence...{Colors.RESET}")
                geo = GeoIntelligence(self.target, self.target_id)
                self.execution_wrapper(geo.execute, "Geolocation")
                # Update target_ip from geo if available, else resolve it manually
                if geo.target_ip:
                     self.target_ip = geo.target_ip
                else:
                     self.resolve_target_ip()
            else:
                self.resolve_target_ip()

            self.execution_wrapper(self.passive.run_ssl_analysis, "SSL Analysis")
            self.execution_wrapper(self.passive.run_subdomain_discovery, "Subdomain Discovery")
            
            # Module: Historical
            if config.ENABLE_HISTORICAL:
                 hist = HistoricalIntelligence(self.target, self.target_id)
                 self.execution_wrapper(hist.execute, "Historical Intel")

            self.execution_wrapper(self.passive.run_email_harvest, "Email Havesting")
            self.execution_wrapper(self.passive.run_smtp_analysis, "SMTP Analysis")

            # Module: Threat Intel
            if config.ENABLE_THREAT_INTEL:
                # Ensure IP is present for specific threat intel modules (Shodan)
                if not self.target_ip:
                    self.resolve_target_ip()
                    
                threat = ThreatIntelligence(self.target, self.target_id, self.target_ip)
                self.execution_wrapper(threat.execute, "Threat Intelligence")

            # Module: Breach Intel
            if config.ENABLE_BREACH_INTEL:
                # Combine harvested emails with any others found
                breach = BreachIntelligence(self.target, self.target_id, list(self.passive.discovered_emails))
                self.execution_wrapper(breach.execute, "Breach Intelligence")

        # 5. Phase 2: Active Recon
        if self.should_run('active'):
            print(f"\n{Colors.HEADER}PHASE 2: ACTIVE RECONNAISSANCE{Colors.RESET}")
            print("="*50)
            
            self.execution_wrapper(self.active.run_ping, "Ping Check")
            self.execution_wrapper(self.active.run_nmap, "Port Scan")
            self.execution_wrapper(self.active.run_tech_detect, "Tech Detection")
            self.execution_wrapper(self.active.run_dirb_lite, "Directory Busting")
            self.execution_wrapper(self.active.run_extended_web_recon, "Extended Web Recon")

            # Module: Metadata
            if config.ENABLE_METADATA:
                meta = MetadataExtractor(self.target, self.target_id)
                self.execution_wrapper(meta.execute, "Metadata Extraction")

        # 6. Phase 3: Search Intel
        if self.should_run('search') and config.ENABLE_SEARCH_INTEL:
            print(f"\n{Colors.HEADER}PHASE 3: SEARCH INTELLIGENCE{Colors.RESET}")
            print("="*50)
            search = SearchIntelligence(self.target, self.target_id)
            self.execution_wrapper(search.execute, "Search Intelligence")

        # 7. Phase 4: Web Analysis
        if self.should_run('web') and config.ENABLE_WEB_ANALYSIS:
            print(f"\n{Colors.HEADER}PHASE 4: WEB ANALYSIS{Colors.RESET}")
            print("="*50)
            web = WebAnalysis(self.target, self.target_id, self.db)
            self.execution_wrapper(web.execute, "Web Analysis")

        # 7. Finalization
        print(f"\n{Colors.SUCCESS}✓ SCAN COMPLETED SUCCESSFULLY{Colors.RESET}")
        print("="*50)
        print(f"[*] Results saved to database: {os.path.abspath(DB_PATH)}")
        
        self.calculate_risk_score()
        self.prompt_reporting()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Aether-Recon OSINT Framework')
    parser.add_argument('target', nargs='?', help='Target domain (e.g., example.com)')
    parser.add_argument('--consent-given', action='store_true', help='Skip consent prompt (Use only if authorized)')
    parser.add_argument('--mode', choices=['full', 'active', 'passive'], default='full', help='Scan mode')
    
    args = parser.parse_args()
    
    target = args.target
    scan_mode = args.mode
    
    # Interactive Mode if no target provided
    if not target:
        print(f"\n{Colors.BANNER}   ░█████╗░██████╗░░██████╗░██╗░░░██╗░██████╗{Colors.RESET}")
        print(f"{Colors.BANNER}    ██╔══██╗██╔══██╗██╔════╝░██║░░░██║██╔════╝{Colors.RESET}")
        print(f"{Colors.BANNER}    ███████║██████╔╝██║░░██╗░██║░░░██║╚█████╗░{Colors.RESET}")
        print(f"{Colors.BANNER}    ██╔══██║██╔══██╗██║░░╚██╗██║░░░██║░╚═══██╗{Colors.RESET}")
        print(f"{Colors.BANNER}    ██║░░██║██║░░██║╚██████╔╝╚██████╔╝██████╔╝{Colors.RESET}")
        print(f"{Colors.BANNER}    ╚═╝░░╚═╝╚═╝░░╚═╝░╚═════╝░░╚═════╝░╚═════╝░{Colors.RESET}")
        print(f"\n{Colors.BANNER}    Argus OSINT Framework | v2.0 | Ethical Intelligence{Colors.RESET}\n")
        
        target = input(f"{Colors.INPUT}Enter target domain (e.g., example.com): {Colors.RESET}").strip()
        if not target:
            print(f"{Colors.ERROR}[!] Target is required. Exiting.{Colors.RESET}")
            sys.exit(1)
            
        print("\n" + "="*50)
        print(f"🎯 TARGET: {target}")
        print("="*50)
        print("Select Scan Mode:")
        print("1. Active Scan (Intrusive: Ports, Directories, etc.)")
        print("2. Passive Scan (Stealth: WHOIS, DNS, OSINT)")
        print("3. Full Scan (Both Active & Passive + Search)")
        
        mode_choice = input(f"\n{Colors.INPUT}Enter choice (1-3) [default=3]: {Colors.RESET}").strip()
        
        if mode_choice == '1': scan_mode = 'active'
        elif mode_choice == '2': scan_mode = 'passive'
        else: scan_mode = 'full'

    engine = ReconEngine(target, args.consent_given, scan_mode)
    try:
        engine.execute()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Scan interrupted by user.{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.ERROR}[!] critical Framework Error: {e}{Colors.RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
