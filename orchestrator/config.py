"""
Configuration Management for Argus OSINT Framework
Handles API keys, rate limiting, and module settings
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file
# Prioritize .env.local for local overrides
_local_env = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env.local')
if os.path.exists(_local_env):
    load_dotenv(_local_env, override=True)

load_dotenv(override=True)

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
    
    # Passive Recon API Keys
    SECURITYTRAILS_API_KEY = os.getenv('SECURITYTRAILS_API_KEY', '')
    FULLHUNT_API_KEY = os.getenv('FULLHUNT_API_KEY', '')
    INTELX_API_KEY = os.getenv('INTELX_API_KEY', '')
    LEAKIX_API_KEY = os.getenv('LEAKIX_API_KEY', '')
    NETLAS_API_KEY = os.getenv('NETLAS_API_KEY', '')
    URLSCAN_API_KEY = os.getenv('URLSCAN_API_KEY', '')
    CHAOS_API_KEY = os.getenv('CHAOS_API_KEY', '')
    BRAVE_API_KEY = os.getenv('BRAVE_API_KEY', '')
    ZOOMEYE_API_KEY = os.getenv('ZOOMEYE_API_KEY', '')
    ONYPHE_API_KEY = os.getenv('ONYPHE_API_KEY', '')
    CRIMINALIP_API_KEY = os.getenv('CRIMINALIP_API_KEY', '')
    FOFA_EMAIL = os.getenv('FOFA_EMAIL', '')
    FOFA_API_KEY = os.getenv('FOFA_API_KEY', '')
    HUNTER_API_KEY = os.getenv('HUNTER_API_KEY', '')
    TOMBA_API_KEY = os.getenv('TOMBA_API_KEY', '')
    TOMBA_SECRET = os.getenv('TOMBA_SECRET', '')
    
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
    ENABLE_WEB_ANALYSIS = os.getenv('ENABLE_WEB_ANALYSIS', 'true').lower() == 'true'
    
    # Web Analysis Tool Paths (optional overrides)
    HTTPX_PATH = os.getenv('HTTPX_PATH', 'httpx')
    NUCLEI_PATH = os.getenv('NUCLEI_PATH', 'nuclei')
    KATANA_PATH = os.getenv('KATANA_PATH', 'katana')
    FFUF_PATH = os.getenv('FFUF_PATH', 'ffuf')
    ARJUN_PATH = os.getenv('ARJUN_PATH', 'arjun')
    GRPCURL_PATH = os.getenv('GRPCURL_PATH', 'grpcurl')
    
    # Web Analysis Settings
    RATE_LIMIT_WEB_ANALYSIS = float(os.getenv('RATE_LIMIT_WEB_ANALYSIS', '5.0'))
    MAX_WORKERS_WEB_ANALYSIS = int(os.getenv('MAX_WORKERS_WEB_ANALYSIS', '10'))
    HTTP_TIMEOUT_FAST = int(os.getenv('HTTP_TIMEOUT_FAST', '3'))
    MAX_WORKERS_GENERAL = int(os.getenv('MAX_WORKERS_GENERAL', '25'))
    
    # Port Scanning Configuration
    # Common TCP ports to scan
    COMMON_TCP_PORTS = os.getenv('COMMON_TCP_PORTS',
        '21,22,23,25,53,69,80,81,110,111,123,135,137,139,143,161,162,'
        '389,443,445,465,500,514,554,587,593,631,636,873,990,992,993,'
        '995,1025,1194,1433,1521,2049,2082,2083,2086,2087,2095,2096,'
        '3306,3389,5432,5900,5985,5986,6379,8080,8081,8443,9000,9090,10000'
    )
    # Common UDP ports to scan
    COMMON_UDP_PORTS = os.getenv('COMMON_UDP_PORTS',
        '53,67,68,69,123,135,137,138,139,161,162,389,445,500,514,520,'
        '623,631,1433,1434,1900,4500,5351,5353,49152'
    )
    # Common web ports to probe
    COMMON_WEB_PORTS = os.getenv('COMMON_WEB_PORTS',
        '80,443,8080,8443,8000,3000'
    )
    
    # Virtual Host Fuzzing Prefixes
    VHOST_PREFIXES = os.getenv('VHOST_PREFIXES',
        'www,dev,staging,test,api,admin,app,portal,mail,blog,cdn,static,assets,dashboard,panel'
    )
    
    # GraphQL endpoints to probe
    GRAPHQL_ENDPOINTS = os.getenv('GRAPHQL_ENDPOINTS',
        '/graphql,/api/graphql,/v1/graphql,/gql'
    )
    
    # Common gRPC ports
    GRPC_PORTS = os.getenv('GRPC_PORTS', '50051,9090')
    
    # HTTP/HTTPS port sets for banner grabbing
    HTTP_PORTS = os.getenv('HTTP_PORTS', '80,8080,8000,81')
    HTTPS_PORTS = os.getenv('HTTPS_PORTS', '443,8443,2083,2087,2096')
    
    # New API Keys (Optional - free tiers available)
    ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')
    IPINFO_API_KEY = os.getenv('IPINFO_API_KEY', '')
    WHOISXML_API_KEY = os.getenv('WHOISXML_API_KEY', '')
    TECHCHECKER_API_KEY = os.getenv('TECHCHECKER_API_KEY', '')
    
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
    USER_AGENT = os.getenv('USER_AGENT', 'Argus-OSINT/2.0 (Intelligence Framework)')
    
    @classmethod
    def check_api_availability(cls):
        """Check which API keys are configured"""
        available_apis = {
            'HIBP': bool(cls.HIBP_API_KEY),
            'VirusTotal': bool(cls.VIRUSTOTAL_API_KEY),
            'Shodan': bool(cls.SHODAN_API_KEY),
            'GitHub': bool(cls.GITHUB_TOKEN),
            'OTX': bool(cls.OTX_API_KEY),
            'Censys': bool(cls.CENSYS_API_ID and cls.CENSYS_API_SECRET),
            'AbuseIPDB': bool(cls.ABUSEIPDB_API_KEY),
            'IPinfo': bool(cls.IPINFO_API_KEY),
            'WhoisXML': bool(cls.WHOISXML_API_KEY),
            'TechChecker': bool(cls.TECHCHECKER_API_KEY),
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
