"""
Web Analysis Module for Aether-Recon OSINT Framework
Comprehensive web server analysis including probing, screenshots, CMS detection,
URL extraction, JavaScript analysis, API discovery, and security scanning.
"""

import os
import re
import json
import socket
import hashlib
import subprocess
import concurrent.futures
from urllib.parse import urlparse, urljoin, parse_qs
from typing import List, Dict, Set, Optional, Any, Tuple
import requests
import time

# Try importing optional dependencies
try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

try:
    import sqlite3
except ImportError:
    sqlite3 = None

# Import config
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import config, Colors

# User agents for rotation
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
]

# Common web ports to probe (reduced for speed)
COMMON_WEB_PORTS = [80, 443, 8080, 8443, 8000, 3000]

# Common virtual host prefixes (top 15 most common)
VHOST_PREFIXES = [
    'www', 'dev', 'staging', 'test', 'api', 'admin', 'app',
    'portal', 'mail', 'blog', 'cdn', 'static', 'assets', 'dashboard', 'panel'
]

# CMS signatures for detection
CMS_SIGNATURES = {
    'WordPress': [
        ('/wp-login.php', 200),
        ('/wp-admin/', [200, 302]),
        ('/wp-content/', 200),
        ('/wp-includes/', 200),
    ],
    'Drupal': [
        ('/core/misc/drupal.js', 200),
        ('/sites/default/', [200, 403]),
        ('/modules/', 200),
    ],
    'Joomla': [
        ('/administrator/', [200, 302]),
        ('/components/', 200),
        ('/media/system/', 200),
    ],
    'Magento': [
        ('/skin/frontend/', 200),
        ('/js/mage/', 200),
        ('/app/etc/local.xml', [200, 403]),
    ],
    'Shopify': [
        ('/cdn.shopify.com', 200),
    ],
    'Ghost': [
        ('/ghost/', [200, 302]),
    ],
    'Laravel': [
        ('/_debugbar/', [200, 404]),
    ],
}

# GraphQL endpoints to probe (reduced)
GRAPHQL_ENDPOINTS = ['/graphql', '/api/graphql', '/v1/graphql', '/gql']

# Common gRPC ports (reduced)
GRPC_PORTS = [50051, 9090]

# IIS shortname characters
IIS_CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789_-'


def get_random_headers(host: str) -> Dict[str, str]:
    """Generate randomized HTTP headers for evasion."""
    import random
    return {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Host': host,
        'Connection': 'keep-alive',
    }


def run_command(cmd: List[str], timeout: int = 60) -> Tuple[bool, str, str]:
    """Run external command with timeout."""
    try:
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=timeout,
            shell=True if os.name == 'nt' else False
        )
        return True, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except FileNotFoundError:
        return False, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        return False, "", str(e)


def check_tool_available(tool: str) -> bool:
    """Check if an external tool is available in PATH."""
    try:
        if os.name == 'nt':
            result = subprocess.run(['where', tool], capture_output=True, text=True)
        else:
            result = subprocess.run(['which', tool], capture_output=True, text=True)
        return result.returncode == 0
    except:
        return False


class WebAnalysis:
    """
    Comprehensive Web Analysis Module for Aether-Recon.
    
    Features:
    - Web Probing: Detect live web servers on standard and uncommon ports
    - Screenshots: Capture screenshots of web pages
    - Virtual Host Fuzzing: Identify virtual hosts by fuzzing HTTP headers
    - CMS Detection: Identify content management systems
    - URL Extraction: Collect URLs passively and actively
    - URL Pattern Analysis: Classify URLs using patterns
    - Favicon Analysis: Discover real IPs behind favicons
    - JavaScript Analysis: Extract secrets and endpoints from JS files
    - Source Map Extraction: Retrieve sensitive data from JavaScript source maps
    - GraphQL Detection: Discover GraphQL endpoints
    - Parameter Discovery: Bruteforce hidden parameters
    - WebSocket Auditing: Validate upgrade handshakes and origin handling
    - gRPC Reflection: Probe common gRPC ports for exposed service reflection
    - Fuzzing: Perform directory and parameter fuzzing
    - File Extension Sorting: Organize URLs by file extensions
    - Wordlist Generation: Create custom wordlists for fuzzing
    - Password Dictionary: Generate password dictionaries
    - IIS Shortname Scanning: Detect IIS shortname vulnerabilities
    """
    
    def __init__(self, target: str, target_id: int, db_manager):
        self.target = target
        self.target_id = target_id
        self.db = db_manager
        self.base_url = f"https://{target}"
        # OPTIMIZED: Reduced timeout for faster scanning
        self.http_timeout = 3  # Fast timeout
        self.max_workers = 25  # More parallel workers
        self.fast_mode = True  # Skip rate limiting
        
        # Collected data
        self.live_servers: List[Dict] = []
        self.discovered_urls: Set[str] = set()
        self.discovered_params: Set[str] = set()
        self.js_files: Set[str] = set()
        self.js_secrets: List[Dict] = []
        self.cms_detected: Optional[str] = None
        self.vhosts: Set[str] = set()
        self.graphql_endpoints: List[str] = []
        self.websocket_findings: List[Dict] = []
        self.grpc_services: List[Dict] = []
        self.iis_shortnames: List[str] = []
        self.wordlist: Set[str] = set()
        
        # Screenshot directory
        self.screenshot_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            'reporter', 'screenshots'
        )
        os.makedirs(self.screenshot_dir, exist_ok=True)
        
    def _save_finding(self, category: str, finding: str, severity: str = 'Info', details: str = ''):
        """Save a finding to the database."""
        if self.db.connect():
            try:
                cursor = self.db.conn.cursor()
                # Use title/description columns to match existing schema
                # Prefix title with category for identification
                title = f"[{category}] {finding}"
                cursor.execute("""
                    INSERT INTO findings (target_id, title, severity, description, url)
                    VALUES (?, ?, ?, ?, ?)
                """, (self.target_id, title, severity, details, self.base_url))
                self.db.conn.commit()
            except Exception as e:
                print(f"{Colors.WARNING}    [!] Failed to save finding: {e}{Colors.RESET}")
            finally:
                self.db.close()
    
    def _rate_limit_wait(self):
        """Rate limiting disabled for speed."""
        pass  # Disabled for performance

    # =========================================================================
    # 1. WEB PROBING
    # =========================================================================
    
    def run_web_probing(self):
        """
        Detect live web servers on standard and uncommon ports.
        Uses httpx if available, falls back to Python requests.
        """
        print(f"{Colors.INFO}    [+] Web Probing - Detecting live servers...{Colors.RESET}")
        
        # Try httpx first
        if check_tool_available('httpx'):
            self._run_httpx_probing()
        else:
            self._run_python_probing()
        
        if self.live_servers:
            print(f"{Colors.SUCCESS}        ✓ Found {len(self.live_servers)} live web server(s){Colors.RESET}")
            for server in self.live_servers:
                print(f"          - {server['url']} [{server['status']}] {server.get('title', '')}")
        else:
            print(f"{Colors.WARNING}        [!] No live web servers detected{Colors.RESET}")
    
    def _run_httpx_probing(self):
        """Use httpx for web probing."""
        ports_str = ','.join(map(str, COMMON_WEB_PORTS))
        cmd = ['httpx', '-u', self.target, '-ports', ports_str, '-json', '-silent', '-nc', '-td']
        
        success, stdout, stderr = run_command(cmd, timeout=120)
        if success and stdout:
            for line in stdout.strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        self.live_servers.append({
                            'url': data.get('url', ''),
                            'status': data.get('status_code', 0),
                            'title': data.get('title', ''),
                            'tech': data.get('tech', []),
                            'webserver': data.get('webserver', ''),
                        })
                    except json.JSONDecodeError:
                        pass
    
    def _run_python_probing(self):
        """Python fallback for web probing."""
        def probe_port(port: int) -> Optional[Dict]:
            for scheme in ['https', 'http']:
                url = f"{scheme}://{self.target}:{port}" if port not in [80, 443] else f"{scheme}://{self.target}"
                if (scheme == 'http' and port == 443) or (scheme == 'https' and port == 80):
                    continue
                try:
                    resp = requests.get(
                        url, 
                        headers=get_random_headers(self.target),
                        timeout=2,  # Ultra-fast timeout
                        verify=False,
                        allow_redirects=False  # Faster without redirects
                    )
                    title = ''
                    if HAS_BS4 and resp.headers.get('content-type', '').startswith('text/html'):
                        soup = BeautifulSoup(resp.text, 'html.parser')
                        title_tag = soup.find('title')
                        if title_tag:
                            title = title_tag.text.strip()[:100]
                    
                    return {
                        'url': url,
                        'status': resp.status_code,
                        'title': title,
                        'webserver': resp.headers.get('Server', ''),
                    }
                except:
                    pass
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(probe_port, port): port for port in COMMON_WEB_PORTS}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self.live_servers.append(result)

    # =========================================================================
    # 2. SCREENSHOTS
    # =========================================================================
    
    def run_screenshots(self):
        """
        Capture screenshots of web pages.
        Uses nuclei with screenshot templates if available.
        """
        print(f"{Colors.INFO}    [+] Capturing Screenshots...{Colors.RESET}")
        
        if not self.live_servers:
            print(f"{Colors.WARNING}        [!] No live servers to screenshot{Colors.RESET}")
            return
        
        captured = 0
        for server in self.live_servers[:5]:  # Limit to first 5 servers
            url = server['url']
            filename = hashlib.md5(url.encode()).hexdigest()[:16] + '.png'
            filepath = os.path.join(self.screenshot_dir, filename)
            
            # Try nuclei headless
            if check_tool_available('nuclei'):
                cmd = ['nuclei', '-u', url, '-headless', '-screenshot', '-srd', self.screenshot_dir]
                success, _, _ = run_command(cmd, timeout=30)
                if success and os.path.exists(filepath):
                    captured += 1
                    continue
            
            # Python fallback would require playwright/selenium - skip for now
            print(f"        [-] Skipping screenshots (nuclei tool not found)")
            break
        
        if captured:
            print(f"{Colors.SUCCESS}        ✓ Captured {captured} screenshot(s){Colors.RESET}")

    # =========================================================================
    # 3. VIRTUAL HOST FUZZING
    # =========================================================================
    
    def run_vhost_fuzzing(self):
        """
        Identify virtual hosts by fuzzing HTTP headers.
        """
        print(f"{Colors.INFO}    [+] Virtual Host Fuzzing...{Colors.RESET}")
        
        # Get baseline response
        base_url = self.base_url if self.live_servers else f"https://{self.target}"
        try:
            baseline = requests.get(
                base_url,
                headers=get_random_headers(self.target),
                timeout=self.http_timeout,
                verify=False
            )
            baseline_len = len(baseline.content)
            baseline_status = baseline.status_code
        except:
            print(f"{Colors.WARNING}        [!] Could not establish baseline response{Colors.RESET}")
            return
        
        # Extract base domain
        parts = self.target.split('.')
        if len(parts) >= 2:
            base_domain = '.'.join(parts[-2:])
        else:
            base_domain = self.target
        
        def check_vhost(prefix: str) -> Optional[str]:
            vhost = f"{prefix}.{base_domain}"
            try:
                headers = get_random_headers(vhost)
                resp = requests.get(
                    base_url,
                    headers=headers,
                    timeout=2,  # Fast timeout
                    verify=False
                )
                # Different response indicates valid vhost
                if resp.status_code != baseline_status or abs(len(resp.content) - baseline_len) > 100:
                    return vhost
            except:
                pass
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
            futures = {executor.submit(check_vhost, prefix): prefix for prefix in VHOST_PREFIXES}
            for future in concurrent.futures.as_completed(futures, timeout=30):
                result = future.result()
                if result:
                    self.vhosts.add(result)
        
        if self.vhosts:
            print(f"{Colors.SUCCESS}        ✓ Found {len(self.vhosts)} virtual host(s):{Colors.RESET}")
            for vhost in list(self.vhosts)[:10]:
                print(f"          - {vhost}")
                self._save_finding('Web Analysis', f'Virtual Host: {vhost}', 'Info')

    # =========================================================================
    # 4. CMS DETECTION
    # =========================================================================
    
    def run_cms_detection(self):
        """
        Identify content management systems.
        Uses CMSeeK if available, falls back to signature-based detection.
        """
        print(f"{Colors.INFO}    [+] CMS Detection...{Colors.RESET}")
        
        # Try CMSeeK first
        if check_tool_available('cmseek'):
            cmd = ['cmseek', '-u', self.target, '--batch', '-r']
            success, stdout, _ = run_command(cmd, timeout=60)
            if success and 'Detected CMS' in stdout:
                # Parse CMSeeK output
                match = re.search(r'Detected CMS: (\w+)', stdout)
                if match:
                    self.cms_detected = match.group(1)
        
        # Python fallback - signature-based detection
        if not self.cms_detected:
            base_url = self.live_servers[0]['url'] if self.live_servers else f"https://{self.target}"
            
            for cms_name, signatures in CMS_SIGNATURES.items():
                detected = False
                for path, expected_status in signatures:
                    try:
                        resp = requests.get(
                            urljoin(base_url, path),
                            headers=get_random_headers(self.target),
                            timeout=2,  # Fast
                            verify=False,
                            allow_redirects=False
                        )
                        if isinstance(expected_status, list):
                            if resp.status_code in expected_status:
                                detected = True
                                break
                        elif resp.status_code == expected_status:
                            detected = True
                            break
                    except:
                        pass
                
                if detected:
                    self.cms_detected = cms_name
                    break
        
        if self.cms_detected:
            print(f"{Colors.SUCCESS}        ✓ Detected CMS: {self.cms_detected}{Colors.RESET}")
            self._save_finding('Web Analysis', f'CMS Detected: {self.cms_detected}', 'Info', 
                             f'Content Management System: {self.cms_detected}')
        else:
            print(f"{Colors.WARNING}        [!] No CMS detected{Colors.RESET}")

    # =========================================================================
    # 5. URL EXTRACTION
    # =========================================================================
    
    def run_url_extraction(self):
        """
        Collect URLs passively and actively using multiple tools.
        Tools: urlfinder, katana, github-endpoints, JSA
        """
        print(f"{Colors.INFO}    [+] URL Extraction...{Colors.RESET}")
        
        # Try katana for active crawling
        if check_tool_available('katana'):
            cmd = ['katana', '-u', self.target, '-d', '1', '-silent', '-jc', '-nc', '-timeout', '5']  # Shallow + fast
            success, stdout, _ = run_command(cmd, timeout=120)
            if success:
                for line in stdout.strip().split('\n'):
                    if line and line.startswith('http'):
                        self.discovered_urls.add(line.strip())
        
        # Python fallback - basic crawling
        else:
            self._crawl_urls_python()
        
        # Extract JS files for later analysis
        for url in self.discovered_urls:
            if url.endswith('.js'):
                self.js_files.add(url)
        
        if self.discovered_urls:
            print(f"{Colors.SUCCESS}        ✓ Extracted {len(self.discovered_urls)} URL(s){Colors.RESET}")
            print(f"          - JavaScript files: {len(self.js_files)}")
    
    def _crawl_urls_python(self, max_pages: int = 10):
        """Fast Python URL crawler - limited depth."""
        if not HAS_BS4:
            return
        
        visited = set()
        to_visit = [self.base_url]
        
        while to_visit and len(visited) < max_pages:
            url = to_visit.pop(0)
            if url in visited:
                continue
            
            visited.add(url)
            
            try:
                resp = requests.get(
                    url,
                    headers=get_random_headers(self.target),
                    timeout=self.http_timeout,
                    verify=False
                )
                if 'text/html' not in resp.headers.get('content-type', ''):
                    continue
                
                soup = BeautifulSoup(resp.text, 'html.parser')
                
                # Extract links
                for tag in soup.find_all(['a', 'script', 'link', 'img', 'form']):
                    href = tag.get('href') or tag.get('src') or tag.get('action')
                    if href:
                        full_url = urljoin(url, href)
                        parsed = urlparse(full_url)
                        if self.target in parsed.netloc:
                            self.discovered_urls.add(full_url)
                            if full_url not in visited and full_url.startswith('http'):
                                to_visit.append(full_url)
            except:
                pass

    # =========================================================================
    # 6. URL PATTERN ANALYSIS
    # =========================================================================
    
    def run_url_pattern_analysis(self):
        """
        Classify URLs using patterns for potential vulnerabilities.
        Looks for: SQLi, XSS, LFI, RCE, SSRF patterns
        """
        print(f"{Colors.INFO}    [+] URL Pattern Analysis...{Colors.RESET}")
        
        patterns = {
            'SQLi': [r'[?&](id|user|name|query|search|cat|item)=', r'\.php\?.*=\d+'],
            'XSS': [r'[?&](q|s|search|query|keyword|msg|message|text|comment)='],
            'LFI': [r'[?&](file|page|path|template|include|dir|document|folder)='],
            'RCE': [r'[?&](cmd|exec|command|run|ping|shell)='],
            'SSRF': [r'[?&](url|uri|path|dest|redirect|site|html|link)='],
            'IDOR': [r'[?&](id|user_id|uid|account|profile|order)=\d+'],
            'Debug': [r'(debug|test|dev|admin|config|backup|old)'],
        }
        
        findings = {k: [] for k in patterns}
        
        for url in self.discovered_urls:
            for vuln_type, regexes in patterns.items():
                for regex in regexes:
                    if re.search(regex, url, re.IGNORECASE):
                        findings[vuln_type].append(url)
                        break
        
        has_findings = False
        for vuln_type, urls in findings.items():
            if urls:
                has_findings = True
                print(f"{Colors.SUCCESS}        ✓ {vuln_type} patterns: {len(urls)} URL(s){Colors.RESET}")
                for url in urls[:3]:
                    print(f"          - {url[:80]}...")
                    self._save_finding('Web Analysis', f'{vuln_type} Pattern: {url[:200]}', 'Medium',
                                     f'URL matches {vuln_type} vulnerable pattern')
        
        if not has_findings:
            print(f"{Colors.WARNING}        [!] No vulnerable patterns detected{Colors.RESET}")

    # =========================================================================
    # 7. FAVICON ANALYSIS
    # =========================================================================
    
    def run_favicon_analysis(self):
        """
        Discover real IPs behind favicons using favicon hash analysis.
        """
        print(f"{Colors.INFO}    [+] Favicon Analysis...{Colors.RESET}")
        
        favicon_urls = [
            f"{self.base_url}/favicon.ico",
            f"{self.base_url}/favicon.png",
        ]
        
        for favicon_url in favicon_urls:
            try:
                resp = requests.get(
                    favicon_url,
                    headers=get_random_headers(self.target),
                    timeout=self.http_timeout,
                    verify=False
                )
                if resp.status_code == 200 and len(resp.content) > 0:
                    # Calculate favicon hash (MurmurHash3)
                    import base64
                    favicon_b64 = base64.b64encode(resp.content).decode()
                    # Simple hash for searching
                    favicon_hash = hashlib.md5(resp.content).hexdigest()
                    
                    print(f"{Colors.SUCCESS}        ✓ Favicon found: {favicon_url}{Colors.RESET}")
                    print(f"          - MD5 Hash: {favicon_hash}")
                    print(f"          - Size: {len(resp.content)} bytes")
                    
                    self._save_finding('Web Analysis', f'Favicon Hash: {favicon_hash}', 'Info',
                                     f'Search Shodan: http.favicon.hash:{favicon_hash}')
                    return
            except:
                pass
        
        print(f"{Colors.WARNING}        [!] No favicon found{Colors.RESET}")

    # =========================================================================
    # 8. JAVASCRIPT ANALYSIS
    # =========================================================================
    
    def run_javascript_analysis(self):
        """
        Extract secrets and endpoints from JavaScript files.
        """
        print(f"{Colors.INFO}    [+] JavaScript Analysis...{Colors.RESET}")
        
        secret_patterns = {
            'AWS Key': r'AKIA[0-9A-Z]{16}',
            'AWS Secret': r'[0-9a-zA-Z/+]{40}',
            'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
            'GitHub Token': r'ghp_[0-9a-zA-Z]{36}',
            'Slack Token': r'xox[baprs]-[0-9a-zA-Z]{10,48}',
            'Private Key': r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----',
            'Generic API Key': r'["\']?api[_-]?key["\']?\s*[:=]\s*["\'][0-9a-zA-Z]{16,}["\']',
            'JWT Token': r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+',
            'Email': r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
            'Internal URL': r'https?://(?:10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)[^\s"\'<>]+',
            'Hardcoded Password': r'["\']?password["\']?\s*[:=]\s*["\'][^"\']+["\']',
        }
        
        endpoint_patterns = [
            r'["\']/(api|v[0-9]+)/[^"\']+["\']',
            r'["\']https?://[^"\']+["\']',
            r'\.get\(["\'][^"\']+["\']\)',
            r'\.post\(["\'][^"\']+["\']\)',
            r'fetch\(["\'][^"\']+["\']\)',
        ]
        
        for js_url in list(self.js_files)[:5]:  # Limit to 5 JS files for speed
            try:
                resp = requests.get(
                    js_url,
                    headers=get_random_headers(self.target),
                    timeout=3,
                    verify=False
                )
                if resp.status_code != 200:
                    continue
                
                content = resp.text
                
                # Search for secrets
                for secret_type, pattern in secret_patterns.items():
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches[:5]:  # Limit matches per type
                        if len(match) > 8:  # Avoid false positives
                            self.js_secrets.append({
                                'type': secret_type,
                                'value': match[:50] + '...' if len(match) > 50 else match,
                                'file': js_url
                            })
                
                # Search for endpoints
                for pattern in endpoint_patterns:
                    matches = re.findall(pattern, content)
                    for match in matches:
                        self.discovered_urls.add(match.strip('"\''))
                        
            except:
                pass
        
        if self.js_secrets:
            print(f"{Colors.SUCCESS}        ✓ Found {len(self.js_secrets)} potential secret(s){Colors.RESET}")
            for secret in self.js_secrets[:5]:
                print(f"          - [{secret['type']}] {secret['value']}")
                self._save_finding('Web Analysis', f"JS Secret: {secret['type']}", 'High',
                                 f"Found in {secret['file']}: {secret['value']}")
        else:
            print(f"{Colors.WARNING}        [!] No secrets found in JavaScript files{Colors.RESET}")

    # =========================================================================
    # 9. SOURCE MAP EXTRACTION
    # =========================================================================
    
    def run_sourcemap_extraction(self):
        """
        Retrieve sensitive data from JavaScript source maps.
        """
        print(f"{Colors.INFO}    [+] Source Map Extraction...{Colors.RESET}")
        
        sourcemaps_found = []
        
        for js_url in list(self.js_files)[:5]:  # Limit for speed
            sourcemap_url = js_url + '.map'
            try:
                resp = requests.get(
                    sourcemap_url,
                    headers=get_random_headers(self.target),
                    timeout=2,
                    verify=False
                )
                if resp.status_code == 200 and 'version' in resp.text[:100]:
                    sourcemaps_found.append(sourcemap_url)
            except:
                pass
        
        if sourcemaps_found:
            print(f"{Colors.SUCCESS}        ✓ Found {len(sourcemaps_found)} source map(s){Colors.RESET}")
            for sm in sourcemaps_found[:5]:
                print(f"          - {sm}")
                self._save_finding('Web Analysis', 'Source Map Exposed', 'Medium',
                                 f'Source map accessible: {sm}')
        else:
            print(f"{Colors.WARNING}        [!] No source maps found{Colors.RESET}")

    # =========================================================================
    # 10. GRAPHQL DETECTION
    # =========================================================================
    
    def run_graphql_detection(self):
        """
        Discover GraphQL endpoints and optionally perform introspection.
        """
        print(f"{Colors.INFO}    [+] GraphQL Detection...{Colors.RESET}")
        
        base_url = self.live_servers[0]['url'] if self.live_servers else self.base_url
        
        introspection_query = {"query": "{__schema{types{name}}}"}
        
        for endpoint in GRAPHQL_ENDPOINTS:
            url = urljoin(base_url, endpoint)
            try:
                self._rate_limit_wait()
                # Try GET first
                resp = requests.get(
                    url,
                    headers=get_random_headers(self.target),
                    timeout=self.http_timeout,
                    verify=False
                )
                
                if resp.status_code in [200, 400] and ('graphql' in resp.text.lower() or '__schema' in resp.text):
                    self.graphql_endpoints.append(url)
                    continue
                
                # Try POST with introspection
                resp = requests.post(
                    url,
                    json=introspection_query,
                    headers={**get_random_headers(self.target), 'Content-Type': 'application/json'},
                    timeout=self.http_timeout,
                    verify=False
                )
                
                if resp.status_code == 200 and '__schema' in resp.text:
                    self.graphql_endpoints.append(url)
                    
            except:
                pass
        
        if self.graphql_endpoints:
            print(f"{Colors.SUCCESS}        ✓ Found {len(self.graphql_endpoints)} GraphQL endpoint(s){Colors.RESET}")
            for ep in self.graphql_endpoints:
                print(f"          - {ep}")
                self._save_finding('Web Analysis', 'GraphQL Endpoint', 'Info', f'Endpoint: {ep}')
        else:
            print(f"{Colors.WARNING}        [!] No GraphQL endpoints detected{Colors.RESET}")

    # =========================================================================
    # 11. PARAMETER DISCOVERY
    # =========================================================================
    
    def run_parameter_discovery(self):
        """
        Bruteforce hidden parameters on endpoints using arjun.
        """
        print(f"{Colors.INFO}    [+] Parameter Discovery...{Colors.RESET}")
        
        # Try arjun
        if check_tool_available('arjun'):
            target_url = self.live_servers[0]['url'] if self.live_servers else self.base_url
            cmd = ['arjun', '-u', target_url, '-oJ', '-', '--stable', '-t', '5']
            success, stdout, _ = run_command(cmd, timeout=120)
            if success and stdout:
                try:
                    data = json.loads(stdout)
                    for url, params in data.items():
                        for param in params:
                            self.discovered_params.add(param)
                except:
                    pass
        
        # Python fallback - common parameter wordlist
        else:
            common_params = [
                'id', 'page', 'search', 'q', 'name', 'user', 'file', 'url', 'debug'
            ]  # Reduced for speed
            
            base_url = self.live_servers[0]['url'] if self.live_servers else self.base_url
            
            def test_param(param: str) -> Optional[str]:
                try:
                    test_url = f"{base_url}?{param}=test123"
                    resp = requests.get(
                        test_url,
                        headers=get_random_headers(self.target),
                        timeout=2,
                        verify=False
                    )
                    if resp.status_code == 200 and 'test123' in resp.text:
                        return param
                except:
                    pass
                return None
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = {executor.submit(test_param, p): p for p in common_params}
                for future in concurrent.futures.as_completed(futures, timeout=15):
                    result = future.result()
                    if result:
                        self.discovered_params.add(result)
        
        if self.discovered_params:
            print(f"{Colors.SUCCESS}        ✓ Discovered {len(self.discovered_params)} parameter(s){Colors.RESET}")
            for param in list(self.discovered_params)[:10]:
                print(f"          - {param}")
        else:
            print(f"{Colors.WARNING}        [!] No hidden parameters discovered{Colors.RESET}")

    # =========================================================================
    # 12. WEBSOCKET AUDITING
    # =========================================================================
    
    def run_websocket_audit(self):
        """
        Validate WebSocket upgrade handshakes and origin handling.
        """
        print(f"{Colors.INFO}    [+] WebSocket Auditing...{Colors.RESET}")
        
        ws_endpoints = [
            f"wss://{self.target}/ws",
            f"wss://{self.target}/socket.io/",
        ]  # Reduced for speed
        
        def check_ws(ws_url: str) -> Optional[Dict]:
            http_url = ws_url.replace('wss://', 'https://')
            try:
                headers = {
                    'Upgrade': 'websocket',
                    'Connection': 'Upgrade',
                    'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                    'Sec-WebSocket-Version': '13',
                    'Origin': 'https://evil.com',
                }
                resp = requests.get(
                    http_url,
                    headers={**get_random_headers(self.target), **headers},
                    timeout=2,
                    verify=False,
                    allow_redirects=False
                )
                if resp.status_code == 101:
                    return {'url': ws_url, 'origin_bypass': True, 'status': 'Cross-origin allowed'}
                elif resp.status_code in [200, 400]:
                    return {'url': ws_url, 'origin_bypass': False, 'status': 'Endpoint detected'}
            except:
                pass
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(check_ws, ws) for ws in ws_endpoints]
            for future in concurrent.futures.as_completed(futures, timeout=10):
                result = future.result()
                if result:
                    self.websocket_findings.append(result)
        
        if self.websocket_findings:
            print(f"{Colors.SUCCESS}        ✓ Found {len(self.websocket_findings)} WebSocket endpoint(s){Colors.RESET}")
            for ws in self.websocket_findings:
                severity = 'High' if ws.get('origin_bypass') else 'Info'
                print(f"          - {ws['url']} ({ws['status']})")
                self._save_finding('Web Analysis', f"WebSocket: {ws['url']}", severity, ws['status'])
        else:
            print(f"{Colors.WARNING}        [!] No WebSocket endpoints detected{Colors.RESET}")

    # =========================================================================
    # 13. gRPC REFLECTION
    # =========================================================================
    
    def run_grpc_reflection(self):
        """
        Probe common gRPC ports for exposed service reflection.
        """
        print(f"{Colors.INFO}    [+] gRPC Reflection Probing...{Colors.RESET}")
        
        # Try grpcurl
        if check_tool_available('grpcurl'):
            for port in GRPC_PORTS:
                addr = f"{self.target}:{port}"
                cmd = ['grpcurl', '-plaintext', addr, 'list']
                success, stdout, stderr = run_command(cmd, timeout=10)
                
                if success and stdout and 'grpc.reflection' not in stderr.lower():
                    services = [s.strip() for s in stdout.strip().split('\n') if s.strip()]
                    if services:
                        self.grpc_services.append({
                            'address': addr,
                            'services': services
                        })
        
        # Python fallback - basic port check
        else:
            for port in GRPC_PORTS:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    result = sock.connect_ex((self.target, port))
                    sock.close()
                    if result == 0:
                        self.grpc_services.append({
                            'address': f"{self.target}:{port}",
                            'services': ['Port open - grpcurl required for service enumeration']
                        })
                except:
                    pass
        
        if self.grpc_services:
            print(f"{Colors.SUCCESS}        ✓ Found {len(self.grpc_services)} gRPC endpoint(s){Colors.RESET}")
            for grpc in self.grpc_services:
                print(f"          - {grpc['address']}: {len(grpc['services'])} service(s)")
                self._save_finding('Web Analysis', f"gRPC Endpoint: {grpc['address']}", 'Info',
                                 f"Services: {', '.join(grpc['services'][:5])}")
        else:
            print(f"{Colors.WARNING}        [!] No gRPC services detected{Colors.RESET}")

    # =========================================================================
    # 14. FUZZING
    # =========================================================================
    
    def run_fuzzing(self):
        """
        Perform directory and parameter fuzzing using ffuf.
        """
        print(f"{Colors.INFO}    [+] Directory Fuzzing...{Colors.RESET}")
        
        # Common directories to fuzz
        common_dirs = [
            'admin', 'administrator', 'login', 'api', 'backup', 'config',
            'dashboard', 'debug', 'dev', 'test', 'staging', 'upload',
            'uploads', 'files', 'images', 'static', 'assets', 'css', 'js',
            '.git', '.svn', '.env', 'robots.txt', 'sitemap.xml', 'phpinfo.php',
            'wp-admin', 'wp-login.php', 'admin.php', 'server-status', 'info.php'
        ]
        
        base_url = self.live_servers[0]['url'] if self.live_servers else self.base_url
        found_dirs = []
        
        # Try ffuf
        if check_tool_available('ffuf'):
            # Create temp wordlist
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                f.write('\n'.join(common_dirs))
                wordlist_path = f.name
            
            cmd = ['ffuf', '-u', f'{base_url}/FUZZ', '-w', wordlist_path, '-mc', '200,204,301,302,307,401,403', '-o', '-', '-of', 'json', '-s']
            success, stdout, _ = run_command(cmd, timeout=60)
            
            if success and stdout:
                try:
                    data = json.loads(stdout)
                    for result in data.get('results', []):
                        found_dirs.append({
                            'path': result.get('input', {}).get('FUZZ', ''),
                            'status': result.get('status', 0),
                            'length': result.get('length', 0)
                        })
                except:
                    pass
            
            os.unlink(wordlist_path)
        
        # Python fallback
        else:
            def check_dir(dir_name: str) -> Optional[Dict]:
                try:
                    url = urljoin(base_url + '/', dir_name)
                    resp = requests.get(
                        url,
                        headers=get_random_headers(self.target),
                        timeout=2,
                        verify=False,
                        allow_redirects=False
                    )
                    if resp.status_code in [200, 301, 302, 307, 401, 403]:
                        return {'path': dir_name, 'status': resp.status_code, 'length': len(resp.content)}
                except:
                    pass
                return None
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
                futures = [executor.submit(check_dir, d) for d in common_dirs]
                for future in concurrent.futures.as_completed(futures, timeout=30):
                    result = future.result()
                    if result:
                        found_dirs.append(result)
        
        if found_dirs:
            print(f"{Colors.SUCCESS}        ✓ Found {len(found_dirs)} accessible path(s){Colors.RESET}")
            for d in found_dirs[:10]:
                status_color = Colors.GREEN if d['status'] == 200 else Colors.YELLOW
                print(f"          - /{d['path']} [{status_color}{d['status']}{Colors.RESET}]")
                severity = 'High' if d['path'] in ['.git', '.env', 'backup', 'config'] else 'Info'
                self._save_finding('Web Analysis', f"Directory: /{d['path']}", severity,
                                 f"Status: {d['status']}, Length: {d['length']}")
        else:
            print(f"{Colors.WARNING}        [!] No interesting directories found{Colors.RESET}")

    # =========================================================================
    # 15. FILE EXTENSION SORTING
    # =========================================================================
    
    def sort_by_file_extension(self):
        """
        Organize discovered URLs by file extensions.
        """
        print(f"{Colors.INFO}    [+] Sorting URLs by File Extension...{Colors.RESET}")
        
        extensions = {}
        
        for url in self.discovered_urls:
            parsed = urlparse(url)
            path = parsed.path
            ext = os.path.splitext(path)[1].lower() or 'no-extension'
            
            if ext not in extensions:
                extensions[ext] = []
            extensions[ext].append(url)
        
        if extensions:
            print(f"{Colors.SUCCESS}        ✓ Sorted into {len(extensions)} extension type(s){Colors.RESET}")
            for ext, urls in sorted(extensions.items(), key=lambda x: len(x[1]), reverse=True)[:10]:
                print(f"          - {ext}: {len(urls)} file(s)")
        else:
            print(f"{Colors.WARNING}        [!] No URLs to sort{Colors.RESET}")

    # =========================================================================
    # 16. WORDLIST GENERATION
    # =========================================================================
    
    def generate_wordlist(self):
        """
        Create custom wordlists from discovered content for fuzzing.
        """
        print(f"{Colors.INFO}    [+] Generating Custom Wordlist...{Colors.RESET}")
        
        # Extract words from URLs
        for url in self.discovered_urls:
            parsed = urlparse(url)
            # Extract path segments
            for segment in parsed.path.split('/'):
                if segment and len(segment) > 2:
                    self.wordlist.add(segment)
            # Extract query parameters
            for key in parse_qs(parsed.query).keys():
                self.wordlist.add(key)
        
        # Extract words from JS secrets context
        for secret in self.js_secrets:
            words = re.findall(r'[a-zA-Z]{3,20}', secret.get('value', ''))
            self.wordlist.update(words)
        
        # Add common suffixes
        base_words = list(self.wordlist)
        for word in base_words[:50]:
            self.wordlist.add(word + '-old')
            self.wordlist.add(word + '-backup')
            self.wordlist.add(word + '-dev')
            self.wordlist.add(word + '-test')
        
        if self.wordlist:
            print(f"{Colors.SUCCESS}        ✓ Generated wordlist with {len(self.wordlist)} entries{Colors.RESET}")
            # Save wordlist
            wordlist_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                'reporter', f'{self.target}_wordlist.txt'
            )
            try:
                with open(wordlist_path, 'w') as f:
                    f.write('\n'.join(sorted(self.wordlist)))
                print(f"          - Saved to: {wordlist_path}")
            except:
                pass
        else:
            print(f"{Colors.WARNING}        [!] No words to generate{Colors.RESET}")

    # =========================================================================
    # 17. PASSWORD DICTIONARY
    # =========================================================================
    
    def generate_password_dict(self):
        """
        Generate password dictionaries based on target information.
        """
        print(f"{Colors.INFO}    [+] Generating Password Dictionary...{Colors.RESET}")
        
        passwords = set()
        
        # Base words from target
        domain_parts = self.target.replace('.', ' ').replace('-', ' ').split()
        base_words = [p for p in domain_parts if len(p) > 2]
        
        # Add company name variants
        if self.cms_detected:
            base_words.append(self.cms_detected.lower())
        
        # Common password patterns
        years = ['2024', '2025', '2026', '2023']
        suffixes = ['!', '@', '#', '123', '1234', '12345', '!@#', '']
        
        for word in base_words:
            word_cap = word.capitalize()
            for year in years:
                for suffix in suffixes:
                    passwords.add(f"{word}{year}{suffix}")
                    passwords.add(f"{word_cap}{year}{suffix}")
                    passwords.add(f"{word.upper()}{year}{suffix}")
        
        # Add common passwords with target context
        common = ['admin', 'password', 'letmein', 'welcome', 'qwerty']
        for c in common:
            for year in years:
                passwords.add(f"{c}{year}")
                passwords.add(f"{c.capitalize()}{year}")
        
        if passwords:
            print(f"{Colors.SUCCESS}        ✓ Generated {len(passwords)} password candidates{Colors.RESET}")
            # Save password dict
            dict_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                'reporter', f'{self.target}_passwords.txt'
            )
            try:
                with open(dict_path, 'w') as f:
                    f.write('\n'.join(sorted(passwords)))
                print(f"          - Saved to: {dict_path}")
            except:
                pass

    # =========================================================================
    # 18. IIS SHORTNAME SCANNING
    # =========================================================================
    
    def run_iis_shortname_scan(self):
        """
        Detect IIS shortname vulnerabilities (8.3 filename disclosure).
        """
        print(f"{Colors.INFO}    [+] IIS Shortname Scanning...{Colors.RESET}")
        
        base_url = self.live_servers[0]['url'] if self.live_servers else self.base_url
        
        # Check if target is likely IIS
        is_iis = False
        try:
            resp = requests.get(
                base_url,
                headers=get_random_headers(self.target),
                timeout=self.http_timeout,
                verify=False
            )
            server = resp.headers.get('Server', '').lower()
            is_iis = 'iis' in server or 'microsoft' in server
        except:
            pass
        
        if not is_iis:
            print(f"{Colors.WARNING}        [!] Target does not appear to be IIS - skipping{Colors.RESET}")
            return
        
        # Try shortscan
        if check_tool_available('shortscan'):
            cmd = ['shortscan', base_url]
            success, stdout, _ = run_command(cmd, timeout=60)
            if success and stdout:
                for line in stdout.split('\n'):
                    if '~' in line:
                        self.iis_shortnames.append(line.strip())
        
        # Python fallback - basic check
        else:
            test_url = f"{base_url}/*~1*/.aspx"
            try:
                resp = requests.get(
                    test_url,
                    headers=get_random_headers(self.target),
                    timeout=self.http_timeout,
                    verify=False
                )
                if resp.status_code == 404:
                    # Not vulnerable
                    pass
                elif resp.status_code != 400:
                    self.iis_shortnames.append("Potentially vulnerable - manual verification needed")
            except:
                pass
        
        if self.iis_shortnames:
            print(f"{Colors.SUCCESS}        ✓ IIS Shortname vulnerability detected{Colors.RESET}")
            for name in self.iis_shortnames[:10]:
                print(f"          - {name}")
                self._save_finding('Web Analysis', 'IIS Shortname Vulnerability', 'Medium',
                                 f'Shortname: {name}')
        else:
            print(f"{Colors.WARNING}        [!] No IIS shortname vulnerability detected{Colors.RESET}")

    # =========================================================================
    # MAIN EXECUTION
    # =========================================================================
    
    def execute(self):
        """
        Main execution flow for Web Analysis module.
        Runs all web analysis features in sequence.
        """
        print(f"\n{Colors.HEADER}WEB ANALYSIS MODULE{Colors.RESET}")
        print("=" * 50)
        print(f"Target: {self.target}")
        print("=" * 50 + "\n")
        
        # Phase 1: Discovery
        self.run_web_probing()
        self.run_screenshots()
        self.run_vhost_fuzzing()
        self.run_cms_detection()
        
        # Phase 2: URL Intelligence
        print(f"\n{Colors.INFO}--- URL Intelligence ---{Colors.RESET}")
        self.run_url_extraction()
        self.run_url_pattern_analysis()
        self.sort_by_file_extension()
        
        # Phase 3: JavaScript Analysis
        print(f"\n{Colors.INFO}--- JavaScript Analysis ---{Colors.RESET}")
        self.run_javascript_analysis()
        self.run_sourcemap_extraction()
        
        # Phase 4: API & Endpoint Discovery
        print(f"\n{Colors.INFO}--- API & Endpoint Discovery ---{Colors.RESET}")
        self.run_graphql_detection()
        self.run_parameter_discovery()
        self.run_favicon_analysis()
        
        # Phase 5: Protocol Auditing
        print(f"\n{Colors.INFO}--- Protocol Auditing ---{Colors.RESET}")
        self.run_websocket_audit()
        self.run_grpc_reflection()
        
        # Phase 6: Fuzzing & Wordlists
        print(f"\n{Colors.INFO}--- Fuzzing & Wordlists ---{Colors.RESET}")
        self.run_fuzzing()
        self.generate_wordlist()
        self.generate_password_dict()
        
        # Phase 7: IIS Security
        print(f"\n{Colors.INFO}--- IIS Security ---{Colors.RESET}")
        self.run_iis_shortname_scan()
        
        # Summary
        print(f"\n{Colors.SUCCESS}✓ Web Analysis Complete{Colors.RESET}")
        print("=" * 50)
        print(f"  - Live Servers: {len(self.live_servers)}")
        print(f"  - URLs Discovered: {len(self.discovered_urls)}")
        print(f"  - JS Secrets: {len(self.js_secrets)}")
        print(f"  - Virtual Hosts: {len(self.vhosts)}")
        print(f"  - GraphQL Endpoints: {len(self.graphql_endpoints)}")
        print(f"  - Parameters: {len(self.discovered_params)}")
        print(f"  - CMS: {self.cms_detected or 'Not detected'}")
        print("=" * 50)


if __name__ == "__main__":
    # Test mode
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
        
        class MockDB:
            def connect(self): return False
            def close(self): pass
            conn = None
        
        wa = WebAnalysis(target, 0, MockDB())
        wa.execute()
    else:
        print("Usage: python web_analysis.py <target>")
