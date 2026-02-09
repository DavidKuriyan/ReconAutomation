"""
Technology Detector Module
Logic for matching technology signatures against target response data.
"""

import requests
import re
import codecs
import  concurrent.futures
from urllib.parse import urljoin, urlparse
from config import config, Colors
from modules.tech_signatures import TECHNOLOGIES

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
    """
    
    __slots__ = ('target', 'target_id', 'db', 'technologies_found', 'favicon_hashes', '_script_srcs')
    
    def __init__(self, target, target_id, db_manager):
        self.target = target  # e.g., "example.com"
        self.target_id = target_id
        self.db = db_manager
        self.technologies_found = set()
        self.favicon_hashes = {} # Common hashes
        
    def get_favicon_hash(self, url):
        """Calculate MMH3 hash of the favicon."""
        try:
            response = requests.get(url, timeout=5, verify=False)
            if response.status_code == 200:
                # Standard shodan/mmh3 approach: base64 encode then hash
                favicon = codecs.encode(response.content, "base64")
                return murmurhash3_32(favicon)
        except:
            return None
            
    def analyze(self, response):
        """
        Analyze a single page response for technologies.
        
        Args:
            response: requests.Response object
        """
        if not response:
            return
            
        headers = response.headers
        text = response.text
        cookies = response.cookies
        
        # 1. Header Analysis
        self._check_headers(headers)
        
        # 2. Cookie Analysis
        self._check_cookies(cookies)
        
        # 3. HTML/Body Analysis (Meta tags, scripts, content)
        self._check_html(text)
        
    def _check_headers(self, headers):
        """Check HTTP headers against signatures."""
        for tech_name, rules in TECHNOLOGIES.items():
            if "headers" in rules:
                for header_name, pattern in rules["headers"].items():
                    # Handle special case where we just check existence
                    if header_name in headers:
                        if pattern.search(headers[header_name]):
                            self.technologies_found.add((tech_name, "Header"))
                            
    def _check_cookies(self, cookies):
        """Check Cookies against signatures."""
        for tech_name, rules in TECHNOLOGIES.items():
            if "cookies" in rules:
                for cookie_name, pattern in rules["cookies"].items():
                    if cookie_name in cookies:
                        if pattern.search(cookies[cookie_name]):
                            self.technologies_found.add((tech_name, "Cookie"))
                            
    def _check_html(self, text):
        """Check HTML content against signatures."""
        # Pre-scan for meta generator to save time
        
        for tech_name, rules in TECHNOLOGIES.items():
            # Meta tags
            if "meta" in rules:
                for meta_name, pattern in rules["meta"].items():
                    # Simple regex for meta tags (faster than parsing HTML soup for every rule)
                    # matches <meta name="generator" content="WordPress...
                    meta_regex = re.compile(rf'<meta[^>]+name=["\']{meta_name}["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE)
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
                        
            # Script src patterns
            if "script" in rules:
                # Extract all src attributes first to avoid re-scanning full text
                # This is a basic extraction, could be optimized
                if not hasattr(self, '_script_srcs'):
                    self._script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', text, re.IGNORECASE)
                
                for pattern in rules["script"]:
                    for src in self._script_srcs:
                        if pattern.search(src):
                            self.technologies_found.add((tech_name, "JavaScript"))
                            break

    def save_results(self):
        """Save discovered technologies to the database."""
        if not self.technologies_found:
            return 0
            
        print(f"    - Found {len(self.technologies_found)} technologies")
        
        saved_count = 0
        if self.db.connect():
            cursor = self.db.conn.cursor()
            for name, source in self.technologies_found:
                try:
                    # Check if already exists to avoid duplicates (though set handles local dedup)
                    cursor.execute("SELECT id FROM technologies WHERE target_id=? AND name=?", (self.target_id, name))
                    if not cursor.fetchone():
                        cursor.execute("INSERT INTO technologies (target_id, name, category, version) VALUES (?, ?, ?, ?)", 
                                      (self.target_id, name, source, ""))
                        saved_count += 1
                except Exception as e:
                    pass
            self.db.conn.commit()
            self.db.close()
            
        return saved_count
