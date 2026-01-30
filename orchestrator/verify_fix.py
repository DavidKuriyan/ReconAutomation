import sys
import os

# Ensure we can import modules from current directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from orchestrator import ReconEngine
from config import config

def verify_full_integration(target="ssmiet.ac.in"):
    print(f"[*] Starting Integration Verification for {target}")
    
    # Initialize Engine in Passive Mode to test modular structure quickly
    print("[*] Initializing ReconEngine (Passive Mode)...")
    recon = ReconEngine(target, consent_given=True, scan_mode='passive')
    
    # Execute the scan
    # This tests:
    # 1. DatabaseManager connection
    # 2. Target creation
    # 3. PassiveRecon module instantiation and execution (WHOIS, DNS, etc.)
    # 4. Error handling wrappers
    try:
        recon.execute()
        print(f"\n[SUCCESS] ReconEngine.execute() completed without crashing.")
    except Exception as e:
        print(f"\n[FAIL] ReconEngine crashed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    verify_full_integration()
