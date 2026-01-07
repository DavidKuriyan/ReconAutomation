import sys
import os
import shutil
import sqlite3
import subprocess

def check_python_version():
    v = sys.version_info
    print(f"[*] Python Version: {v.major}.{v.minor}.{v.micro}")
    if v.major < 3:
        print(" [!] Warning: Python 3 required.")

def check_dependencies():
    print("[*] Checking Dependencies...")
    required = ["requests", "dns", "OpenSSL", "jinja2"]
    missing = []
    for package in required:
        try:
            __import__(package)
            print(f" [OK] {package}")
        except ImportError:
            missing.append(package)
            print(f" [FAIL] {package}")
    
    if missing:
        print(" [!] Run: pip install -r ../reporter/requirements.txt")

def check_external_tools():
    print("[*] Checking External Tools...")
    tools = ["nmap", "subfinder", "ping"]
    for tool in tools:
        if shutil.which(tool):
             print(f" [OK] {tool} found")
        else:
             print(f" [WARN] {tool} NOT found (Functionality will be limited)")

def check_database():
    print("[*] Checking Database...")
    db_path = "../reporter/aether.db"
    if not os.path.exists(db_path):
        print(f" [FAIL] Database file not found at {db_path}")
        return

    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        
        # Check WAL Mode
        cur.execute("PRAGMA journal_mode;")
        mode = cur.fetchone()[0]
        print(f" [INFO] Journal Mode: {mode.upper()}")
        if mode.upper() != "WAL":
            print(" [WARN] WAL Mode NOT enabled. Concurrency issues may occur.")
            print("        Run 'python init_db.py' in reporter dir to fix.")
        else:
            print(" [OK] WAL Mode Active")
            
        # Check Tables
        tables = ["targets", "domain_info", "dns_records", "subdomains", "ports", "technologies", "directories", "ssl_info"]
        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        existing = [r[0] for r in cur.fetchall()]
        
        for t in tables:
            if t in existing:
                 print(f" [OK] Table '{t}' exists")
            else:
                 print(f" [FAIL] Table '{t}' MISSING")
                 
        conn.close()
    except Exception as e:
        print(f" [FAIL] DB Connection Error: {e}")

if __name__ == "__main__":
    print("=== Aether-Recon Debugger ===\n")
    check_python_version()
    print("-" * 30)
    check_dependencies()
    print("-" * 30)
    check_external_tools()
    print("-" * 30)
    check_database()
    print("\n=== End Debug ===")
