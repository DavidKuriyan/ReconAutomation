"""
Technology Detector Module
Logic for matching technology signatures against target response data.
Enhanced with: version extraction, favicon hashing, cloud detection, findings creation.
"""

import requests
import re
import codecs
import concurrent.futures
from urllib.parse import urljoin, urlparse
from config import config, Colors
from modules.tech_signatures import TECHNOLOGIES, FAVICON_HASHES, TECH_CATEGORY_MAP, TECH_CATEGORIES

# Pure Python MurmurHash3 32-bit implementation to avoid external dependency
def murmurhash3_32(key, seed=0):
    def fmix(h):
        h ^= h >> 16
        h = (h * 0x85ebca6b) & 0xFFFFFFFF
        h ^= h >> 13
        h = (h * 0xc2b2ae35) & 0xFFFFFFFF
        h ^= h >> 16
        return h

    length = len(key)
    nblocks = length // 4
    h1 = seed
    c1 = 0xcc9e2d51
    c2 = 0x1b873593

    # Body
    for i in range(0, nblocks * 4, 4):
        k1 = key[i+3] << 24 | key[i+2] << 16 | key[i+1] << 8 | key[i]
        
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = (k1 << 15) | (k1 >> 17)
        k1 = (k1 * c2) & 0xFFFFFFFF

        h1 ^= k1
        h1 = (h1 << 13) | (h1 >> 19)
        h1 = (h1 * 5 + 0xe6546b64) & 0xFFFFFFFF

    # Tail
    tail_index = nblocks * 4
    k1 = 0
    tail_size = length & 3

    if tail_size >= 3:
        k1 ^= key[tail_index + 2] << 16
    if tail_size >= 2:
        k1 ^= key[tail_index + 1] << 8
    if tail_size >= 1:
        k1 ^= key[tail_index]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = (k1 << 15) | (k1 >> 17)
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    # Finalization
    h1 ^= length
    h1 = fmix(h1)
    
    # Handle signed 32-bit int for compatibility with standard mmh3
    if h1 & 0x80000000:
        return -((h1 ^ 0xFFFFFFFF) + 1)
    return h1


class TechDetector:
    """
    Identifies website technologies using local analysis of:
    - HTTP Headers
    - HTML Source (Meta tags, scripts, structure)
    - Cookies
    - Favicon hashes (MurmurHash3)
    - JavaScript files
    - CSS files
    - Server banners
    
    Enhanced: version extraction, cloud/CDN detection, multi-response analysis.
    """
    
    __slots__ = ('target', 'target_id', 'db', 'technologies_found', 'versions_found', 
                 'favicon_hashes', '_script_srcs', 'responses')
    
    def __init__(self, target, target_id, db_manager):
        self.target = target  # e.g., "example.com"
        self.target_id = target_id
        self.db = db_manager
        self.technologies_found = set()  # (name, source)
        self.versions_found = {}  # name -> version
        self.responses = []  # Multiple HTTP responses (http, https, www, etc.)
        
    def _extract_versions(self, response, tech_name):
        """Extract version from headers if version_headers defined."""
        if tech_name not in TECHNOLOGIES:
            return ""
        rules = TECHNOLOGIES[tech_name]
        if "version_headers" not in rules:
            return ""
        
        headers = response.headers
        for header_name, version_pattern in rules["version_headers"].items():
            if header_name in headers:
                match = re.search(version_pattern, headers[header_name], re.IGNORECASE)
                if match:
                    # Take the first non-None group
                    for group in match.groups():
                        if group:
                            return group
                    return match.group(1) if match.lastindex else match.group(0)
        return ""
    
    def get_favicon_hash(self, base_url):
        """Calculate MMH3 hash of the favicon from a base URL."""
        favicon_urls = [
            urljoin(base_url, "/favicon.ico"),
            urljoin(base_url, "/favicon.png"),
            urljoin(base_url, "/assets/favicon.ico"),
            urljoin(base_url, "/images/favicon.ico"),
        ]
        
        for url in favicon_urls:
            try:
                response = requests.get(
                    url, timeout=5, verify=False,
                    headers={'User-Agent': 'Mozilla/5.0'}
                )
                if response.status_code == 200 and len(response.content) > 50:
                    favicon = codecs.encode(response.content, "base64")
                    return murmurhash3_32(favicon)
            except:
                pass
        return None
    
    def analyze(self, response):
        """
        Analyze a single page response for technologies.
        
        Args:
            response: requests.Response object
        """
        if not response:
            return
            
        self.responses.append(response)
        headers = response.headers
        text = response.text
        
        # 1. Header Analysis (with version extraction)
        self._check_headers(headers, response)
        
        # 2. Cookie Analysis
        self._check_cookies(response.cookies)
        
        # 3. HTML/Body Analysis (Meta tags, scripts, content)
        self._check_html(text)
        
        # 4. Cloud/Infrastructure-specific header checks
        self._check_cloud_headers(headers)
        
    def _check_headers(self, headers, response):
        """Check HTTP headers against signatures with version extraction."""
        for tech_name, rules in TECHNOLOGIES.items():
            if "headers" in rules:
                for header_name, pattern in rules["headers"].items():
                    # Handle special case where we just check existence
                    if header_name in headers:
                        if pattern.search(headers[header_name]):
                            self.technologies_found.add((tech_name, "HTTP Header"))
                            # Extract version
                            version = self._extract_versions(response, tech_name)
                            if version:
                                self.versions_found[tech_name] = version
    
    def _check_cookies(self, cookies):
        """Check Cookies against signatures."""
        for tech_name, rules in TECHNOLOGIES.items():
            if "cookies" in rules:
                for cookie_name, pattern in rules["cookies"].items():
                    # Check by cookie name
                    if cookie_name in cookies:
                        self.technologies_found.add((tech_name, "Cookie"))
    
    def _check_html(self, text):
        """Check HTML content against signatures."""
        if not text:
            return
            
        for tech_name, rules in TECHNOLOGIES.items():
            # Meta tags
            if "meta" in rules:
                for meta_name, pattern in rules["meta"].items():
                    meta_regex = re.compile(
                        rf'<meta[^>]+name=["\']{meta_name}["\'][^>]+content=["\']([^"\']+)["\']',
                        re.IGNORECASE
                    )
                    match = meta_regex.search(text)
                    if match:
                        content = match.group(1)
                        if pattern.search(content):
                            self.technologies_found.add((tech_name, "Meta Tag"))

            # General HTML patterns
            if "html" in rules:
                for pattern in rules["html"]:
                    if pattern.search(text):
                        self.technologies_found.add((tech_name, "HTML Source"))

        # Script src patterns (extracted once for all technologies)
        self._script_srcs = re.findall(
            r'<script[^>]+src=["\']([^"\']+)["\']', text, re.IGNORECASE
        )
        
        for tech_name, rules in TECHNOLOGIES.items():
            if "script" in rules:
                for pattern in rules["script"]:
                    for src in self._script_srcs:
                        if pattern.search(src):
                            self.technologies_found.add((tech_name, "JavaScript"))
                            break
    
    def _check_cloud_headers(self, headers):
        """Check for cloud/CDN/infrastructure specific headers."""
        # Amazon/CloudFront detection
        if 'X-Amz-Cf-Id' in headers:
            self.technologies_found.add(("Amazon CloudFront", "HTTP Header (CF ID)"))
            self.technologies_found.add(("Amazon AWS", "HTTP Header"))
        
        # General AWS detection
        if 'X-Amz-Request-Id' in headers or 'x-amzn-RequestId' in headers:
            self.technologies_found.add(("Amazon AWS", "HTTP Header"))
        
        # Varnish
        if 'X-Varnish' in headers:
            varnish_id = headers.get('X-Varnish', '')
            if varnish_id.replace(' ', '').isdigit():
                self.technologies_found.add(("Varnish", "HTTP Header (X-Varnish)"))
        
        # Akamai
        if 'X-Akamai-Transformed' in headers:
            self.technologies_found.add(("Akamai", "HTTP Header"))
    
    def analyze_favicon(self, base_url):
        """Analyze favicon for technology identification."""
        fav_hash = self.get_favicon_hash(base_url)
        if fav_hash and fav_hash in FAVICON_HASHES:
            tech_name = FAVICON_HASHES[fav_hash]
            self.technologies_found.add((tech_name, "Favicon Hash"))
            print(f"    ✓ Favicon hash matched: {tech_name}")
    
    def analyze_responses(self, responses):
        """Analyze multiple responses (HTTP + HTTPS + www + root)."""
        for resp in responses:
            if resp:
                self.analyze(resp)
    
    def save_results(self):
        """Save discovered technologies to DB and create findings with severity."""
        count = self.save_technologies()
        finding_count = self.save_technology_findings()
        return count, finding_count
    
    def save_technologies(self):
        """Save discovered technologies to the database."""
        if not self.technologies_found:
            return 0
        
        if not self.db.connect():
            return 0
            
        saved_count = 0
        try:
            cursor = self.db.conn.cursor()
            for name, source in self.technologies_found:
                try:
                    version = self.versions_found.get(name, "")
                    category = TECH_CATEGORY_MAP.get(name, "Other")
                    
                    cursor.execute(
                        "SELECT id FROM technologies WHERE target_id=? AND name=?",
                        (self.target_id, name)
                    )
                    if not cursor.fetchone():
                        cursor.execute(
                            "INSERT INTO technologies (target_id, name, category, version) VALUES (?, ?, ?, ?)",
                            (self.target_id, name, category, version)
                        )
                        saved_count += 1
                except Exception:
                    pass
            self.db.conn.commit()
        except Exception:
            pass
        finally:
            self.db.close()
        
        return saved_count
    
    def save_technology_findings(self):
        """
        Create findings in the database for each detected technology.
        Severity is 'Info' by default, but security-related technologies get 'Low'.
        """
        if not self.technologies_found:
            return 0
        
        if not self.db.connect():
            return 0
        
        saved_count = 0
        seen = set()
        try:
            cursor = self.db.conn.cursor()
            for name, source in self.technologies_found:
                # Avoid duplicate findings
                if name in seen:
                    continue
                seen.add(name)
                
                try:
                    version = self.versions_found.get(name, "")
                    category = TECH_CATEGORY_MAP.get(name, "Other")
                    category_desc = TECH_CATEGORIES.get(category, category)
                    
                    # Determine severity
                    if category == "WAF":
                        severity = "Low"
                        description = f"Web Application Firewall detected: {name}. Site is protected by {name}."
                    elif category == "CDN":
                        severity = "Low"
                        description = f"CDN / Reverse Proxy detected: {name}. Site uses {name} for content delivery."
                    elif name in ("Let's Encrypt", "Cloudflare SSL"):
                        severity = "Info"
                        description = f"SSL/TLS certificate from {name}."
                    elif category == "Security":
                        severity = "Info"
                        description = f"Security technology detected: {name}."
                    else:
                        severity = "Info"
                        description = f"Technology identified: {name} ({category_desc}) - detected via {source}."
                    
                    if version:
                        description += f" Version: {version}"
                        title = f"Tech Stack: {name} v{version}"
                    else:
                        title = f"Tech Stack: {name}"
                    
                    cursor.execute(
                        "SELECT id FROM findings WHERE target_id=? AND title=?",
                        (self.target_id, title)
                    )
                    if not cursor.fetchone():
                        cursor.execute(
                            "INSERT INTO findings (target_id, title, severity, description, url) VALUES (?, ?, ?, ?, ?)",
                            (self.target_id, title, severity, description, f"https://{self.target}")
                        )
                        saved_count += 1
                except Exception:
                    pass
            
            self.db.conn.commit()
        except Exception:
            pass
        finally:
            self.db.close()
        
        return saved_count
    
    def run_techchecker_api(self):
        """Query TechnologyChecker.io API for comprehensive tech stack detection.
        
        Uses Bearer token auth to query https://api.technologychecker.io
        Falls back to live detection if domain not found in pre-crawled DB.
        """
        if not config.TECHCHECKER_API_KEY:
            print(f"{Colors.WARNING}    [!] TechChecker API key not configured, skipping{Colors.RESET}")
            return
        
        print(f"{Colors.INFO}[+] Technology Checker API - Querying tech stack...{Colors.RESET}")
        
        def query_domain(domain):
            """Query the pre-crawled domain database (1 credit)."""
            url = f"https://api.technologychecker.io/v1/domain/{domain}"
            headers = {
                'Authorization': f'Bearer {config.TECHCHECKER_API_KEY}',
                'Accept': 'application/json'
            }
            try:
                resp = requests.get(url, headers=headers, timeout=15)
                if resp.status_code == 200:
                    return resp.json()
                elif resp.status_code == 404:
                    return None  # Not found in DB, try live scan
                else:
                    print(f"    [!] TechChecker API error: HTTP {resp.status_code}")
                    return None
            except requests.exceptions.Timeout:
                print(f"    [!] TechChecker API timeout")
                return None
            except Exception as e:
                print(f"    [!] TechChecker API error: {e}")
                return None
        
        def query_live(domain):
            """Perform live detection (5 credits)."""
            url = "https://api.technologychecker.io/v1/technology-lookup-live"
            headers = {
                'Authorization': f'Bearer {config.TECHCHECKER_API_KEY}',
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
            payload = {'url': domain}
            try:
                resp = requests.post(url, headers=headers, json=payload, timeout=30)
                if resp.status_code == 200:
                    return resp.json()
                else:
                    print(f"    [!] TechChecker live scan error: HTTP {resp.status_code}")
                    return None
            except requests.exceptions.Timeout:
                print(f"    [!] TechChecker live scan timeout")
                return None
            except Exception as e:
                print(f"    [!] TechChecker live scan error: {e}")
                return None
        
        # Step 1: Try pre-crawled database
        tech_data = query_domain(self.target)
        
        # Step 2: Fallback to live detection
        if tech_data is None:
            print(f"    - Domain not in pre-crawled DB, trying live scan...")
            tech_data = query_live(self.target)
        
        if not tech_data:
            print(f"{Colors.WARNING}    [!] No technology data from TechChecker{Colors.RESET}")
            return
        
        # Step 3: Parse the response
        technologies = []
        
        if 'technologies' in tech_data:
            technologies = tech_data.get('technologies', [])
        elif 'technology' in tech_data:
            tech = tech_data.get('technology', {})
            if isinstance(tech, dict):
                technologies.append(tech)
            elif isinstance(tech, list):
                technologies = tech
        elif isinstance(tech_data, list):
            technologies = tech_data
        
        if not technologies:
            print(f"    - No technologies identified")
            return
        
        print(f"{Colors.SUCCESS}    ✓ TechChecker identified {len(technologies)} technologies{Colors.RESET}")
        
        # Save to DB
        if self.db.connect():
            cursor = self.db.conn.cursor()
            saved_count = 0
            for tech in technologies:
                if isinstance(tech, dict):
                    name = tech.get('name', tech.get('technology', 'Unknown'))
                    category = tech.get('category', tech.get('type', ''))
                    version = tech.get('version', '')
                    confidence = tech.get('confidence', 100)
                    
                    if isinstance(confidence, (int, float)) and confidence < 30:
                        continue
                    
                    cursor.execute(
                        "SELECT id FROM technologies WHERE target_id=? AND name=?",
                        (self.target_id, name)
                    )
                    if not cursor.fetchone():
                        cursor.execute(
                            "INSERT INTO technologies (target_id, name, category, version) VALUES (?, ?, ?, ?)",
                            (self.target_id, name, category, version)
                        )
                        saved_count += 1
                        print(f"      - {name} ({category}) v{version}" if version else f"      - {name} ({category})")
            
            self.db.conn.commit()
            self.db.close()
            print(f"    - Saved {saved_count} new technologies to database")
        
        return technologies
