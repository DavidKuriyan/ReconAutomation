"""
Configuration Management for Enhanced Aether-Recon OSINT Framework
Handles API keys, rate limiting, and module settings
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file
# Load environment variables from .env file
# Prioritize .env.local for local overrides
if os.path.exists(os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env.local')):
    load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env.local'))

load_dotenv()

class Config:
    """Central configuration for all OSINT modules"""
    
    # Database
    DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'reporter', 'argus.db')
    
    # API Keys (Optional - framework degrades gracefully without them)
    HIBP_API_KEY = os.getenv('HIBP_API_KEY', '')
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
    SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', '')
    GITHUB_TOKEN = os.getenv('GITHUB_TOKEN', '')
    OTX_API_KEY = os.getenv('OTX_API_KEY', '')
    CENSYS_API_ID = os.getenv('CENSYS_API_ID', '')
    CENSYS_API_SECRET = os.getenv('CENSYS_API_SECRET', '')
    
    # Rate Limiting (requests per second)
    RATE_LIMIT_GLOBAL = float(os.getenv('RATE_LIMIT_GLOBAL', '2.0'))
    RATE_LIMIT_VIRUSTOTAL = float(os.getenv('RATE_LIMIT_VIRUSTOTAL', '0.25'))  # 4/min on free tier
    RATE_LIMIT_SHODAN = float(os.getenv('RATE_LIMIT_SHODAN', '0.2'))  # 1/sec
    RATE_LIMIT_GITHUB = float(os.getenv('RATE_LIMIT_GITHUB', '0.5'))  # 2/sec
    RATE_LIMIT_HIBP = float(os.getenv('RATE_LIMIT_HIBP', '0.067'))  # 1 every 1.5 seconds
    
    # Module Enable/Disable
    ENABLE_GEOLOCATION = os.getenv('ENABLE_GEOLOCATION', 'true').lower() == 'true'
    ENABLE_SOCMINT = os.getenv('ENABLE_SOCMINT', 'true').lower() == 'true'
    ENABLE_BREACH_INTEL = os.getenv('ENABLE_BREACH_INTEL', 'true').lower() == 'true'
    ENABLE_THREAT_INTEL = os.getenv('ENABLE_THREAT_INTEL', 'true').lower() == 'true'
    ENABLE_METADATA = os.getenv('ENABLE_METADATA', 'true').lower() == 'true'
    ENABLE_HISTORICAL = os.getenv('ENABLE_HISTORICAL', 'true').lower() == 'true'
    ENABLE_SEARCH_INTEL = os.getenv('ENABLE_SEARCH_INTEL', 'true').lower() == 'true'
    
    # Timeouts (seconds)
    HTTP_TIMEOUT = int(os.getenv('HTTP_TIMEOUT', '10'))
    DNS_TIMEOUT = int(os.getenv('DNS_TIMEOUT', '5'))
    
    # Threading
    MAX_WORKERS_PORTS = int(os.getenv('MAX_WORKERS_PORTS', '20'))
    MAX_WORKERS_DIRS = int(os.getenv('MAX_WORKERS_DIRS', '10'))
    MAX_WORKERS_SUBDOMAINS = int(os.getenv('MAX_WORKERS_SUBDOMAINS', '5'))
    
    # Ethical Scanning
    REQUIRE_CONSENT = os.getenv('REQUIRE_CONSENT', 'true').lower() == 'true'
    AUDIT_LOGGING = os.getenv('AUDIT_LOGGING', 'true').lower() == 'true'
    
    # User Agent
    USER_AGENT = os.getenv('USER_AGENT', 'Aether-Recon/2.0 (OSINT Framework)')
    
    @classmethod
    def check_api_availability(cls):
        """Check which API keys are configured"""
        available_apis = {
            'HIBP': bool(cls.HIBP_API_KEY),
            'VirusTotal': bool(cls.VIRUSTOTAL_API_KEY),
            'Shodan': bool(cls.SHODAN_API_KEY),
            'GitHub': bool(cls.GITHUB_TOKEN),
            'OTX': bool(cls.OTX_API_KEY),
            'Censys': bool(cls.CENSYS_API_ID and cls.CENSYS_API_SECRET)
        }
        return available_apis
    
    @classmethod
    def print_status(cls):
        """Print configuration status"""
        print("\n[*] Configuration Status:")
        print(f"    - Database: {cls.DB_PATH}")
        print(f"    - Consent Required: {cls.REQUIRE_CONSENT}")
        print(f"    - Audit Logging: {cls.AUDIT_LOGGING}")
        print("\n[*] API Availability:")
        apis = cls.check_api_availability()
        for api_name, available in apis.items():
            status = "✓ Configured" if available else "✗ Not configured"
            print(f"    - {api_name}: {status}")
        print()

class Colors:
    """Cyberpunk Color Palette for CLI"""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    
    # Semantic Colors
    BANNER = BOLD + GREEN
    SUCCESS = BOLD + GREEN + "[+] " + RESET + GREEN
    ERROR = BOLD + RED + "[!] " + RESET + RED
    WARNING = BOLD + YELLOW + "[WARN] " + RESET + YELLOW
    INFO = BOLD + CYAN + "[*] " + RESET + CYAN
    INPUT = BOLD + WHITE + "[?] " + RESET + WHITE
    HEADER = BOLD + BLUE + "\n" + "="*50 + "\n" + RESET + BOLD + CYAN

# Singleton instance
config = Config()
