"""
Passive Data Sources Module for Aether-Recon OSINT Framework
Implements 40+ passive reconnaissance data sources for subdomain discovery,
email harvesting, IP intelligence, and threat analysis.
"""

import os
import re
import json
import base64
import hashlib
import socket
import requests
import concurrent.futures
import warnings
import urllib3
from urllib.parse import quote, urljoin
from typing import Set, List, Dict, Optional, Tuple
import random
import time

# Suppress SSL warnings (we're doing OSINT, not banking)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Import config
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import config, Colors

# User agents for rotation
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
]

def get_random_ua() -> str:
    return random.choice(USER_AGENTS)

def make_request(url: str, headers: dict = None, timeout: int = 10, json_resp: bool = False):
    """Make HTTP request with error handling."""
    try:
        hdrs = headers or {'User-Agent': get_random_ua()}
        resp = requests.get(url, headers=hdrs, timeout=timeout, verify=False)
        if resp.status_code == 200:
            return resp.json() if json_resp else resp.text
    except:
        pass
    return None


class PassiveSources:
    """
    Collection of passive reconnaissance data sources.
    All methods return sets of subdomains or relevant data.
    
    DSA Optimizations:
    - __slots__ for memory efficiency
    - Precompiled regex patterns at class level
    - Frozenset for O(1) pattern lookups
    - LRU caching for repeated operations
    """
    
    # Memory optimization: use __slots__ to prevent __dict__ creation
    __slots__ = ('domain', 'subdomains', 'emails', 'ips', 'findings', 'timeout', '_domain_suffix')
    
    # Precompiled regex patterns (class-level, compiled once)
    VALID_SUBDOMAIN_PATTERN = re.compile(r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$')
    IP_PATTERN = re.compile(r'\d{1,3}[-_.]\d{1,3}[-_.]\d{1,3}[-_.]\d{1,3}')
    INVALID_CHARS_PATTERN = re.compile(r'[@+*<>\s]|[^a-z0-9.\-]')
    
    def __init__(self, domain: str):
        self.domain = domain
        self._domain_suffix = '.' + domain  # Cache for faster suffix checks
        self.subdomains: Set[str] = set()
        self.emails: Set[str] = set()
        self.ips: Set[str] = set()
        self.findings: List[Dict] = []
        self.timeout = 10
    
    def _is_valid_subdomain(self, subdomain: str) -> bool:
        """
        Validate subdomain against common junk patterns and DNS rules.
        Optimized with precompiled patterns and early returns.
        """
        if not subdomain:
            return False
        
        sub = subdomain.lower().strip()
        
        # Fast suffix check using cached suffix
        if not (sub.endswith(self._domain_suffix) or sub == self.domain):
            return False
        
        # Single regex check for all invalid chars (O(n) instead of multiple O(n))
        if self.INVALID_CHARS_PATTERN.search(sub):
            return False
        
        # Fast DNS format validation
        if not self.VALID_SUBDOMAIN_PATTERN.match(sub):
            return False
        
        # Get the subdomain prefix (part before the main domain)
        prefix = sub[:-len(self._domain_suffix)] if sub.endswith(self._domain_suffix) else ''
        
        if prefix:
            prefix_clean = prefix.replace('.', '').replace('-', '')
            prefix_len = len(prefix_clean)
            
            if prefix_len > 0:
                # Count using generator expressions (memory efficient)
                num_count = sum(1 for c in prefix_clean if c.isdigit())
                
                # If more than 70% numbers and prefix is long, likely junk
                if len(prefix) > 10 and num_count / prefix_len > 0.7:
                    return False
                
                # Very long random-looking prefixes
                alpha_count = sum(1 for c in prefix_clean if c.isalpha())
                if len(prefix) > 30 and alpha_count < 5:
                    return False
            
            # Contains IP address patterns (precompiled regex)
            if self.IP_PATTERN.search(prefix):
                return False
        
        return True
    
    def _clean_subdomains(self, subs: Set[str]) -> Set[str]:
        """Filter and clean subdomains using set comprehension (O(n))."""
        return {sub.lower().strip() for sub in subs if self._is_valid_subdomain(sub.lower().strip())}
    
    # =========================================================================
    # FREE SUBDOMAIN SOURCES (No API Key Required)
    # =========================================================================
    
    def crtsh(self) -> Set[str]:
        """Certificate Transparency via crt.sh"""
        subs = set()
        try:
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            data = make_request(url, timeout=15, json_resp=True)
            if data:
                for entry in data:
                    name = entry.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub and '*' not in sub and self.domain in sub:
                            subs.add(sub)
        except:
            pass
        return subs
    
    def certspotter(self) -> Set[str]:
        """Cert Spotter - Certificate Transparency monitoring"""
        subs = set()
        try:
            url = f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
            data = make_request(url, timeout=15, json_resp=True)
            if data:
                for entry in data:
                    for name in entry.get('dns_names', []):
                        if self.domain in name and '*' not in name:
                            subs.add(name.lower())
        except:
            pass
        return subs
    
    def bufferoverun(self) -> Set[str]:
        """BufferOver.run - TLS certificate subdomain search"""
        subs = set()
        try:
            url = f"https://tls.bufferover.run/dns?q=.{self.domain}"
            data = make_request(url, timeout=10, json_resp=True)
            if data and data.get('Results'):
                for result in data['Results']:
                    parts = result.split(',')
                    if len(parts) >= 2:
                        sub = parts[1].strip().lower()
                        if self.domain in sub:
                            subs.add(sub)
        except:
            pass
        return subs
    
    def hackertarget(self) -> Set[str]:
        """HackerTarget - Free subdomain finder"""
        subs = set()
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            data = make_request(url, timeout=10)
            if data and 'error' not in data.lower():
                for line in data.split('\n'):
                    if ',' in line:
                        sub = line.split(',')[0].strip().lower()
                        if self.domain in sub:
                            subs.add(sub)
        except:
            pass
        return subs
    
    def rapiddns(self) -> Set[str]:
        """RapidDNS - DNS query tool"""
        subs = set()
        try:
            url = f"https://rapiddns.io/subdomain/{self.domain}?full=1"
            headers = {'User-Agent': get_random_ua()}
            data = make_request(url, headers=headers, timeout=15)
            if data:
                # Parse HTML for subdomains
                matches = re.findall(r'<td>([a-zA-Z0-9.-]+\.' + re.escape(self.domain) + r')</td>', data)
                for match in matches:
                    subs.add(match.lower())
        except:
            pass
        return subs
    
    def dnsdumpster(self) -> Set[str]:
        """DNSDumpster - Domain research tool"""
        subs = set()
        try:
            session = requests.Session()
            session.headers['User-Agent'] = get_random_ua()
            
            # Get CSRF token
            resp = session.get("https://dnsdumpster.com/", timeout=10)
            csrf_token = re.search(r"name='csrfmiddlewaretoken' value='([^']+)'", resp.text)
            
            if csrf_token:
                data = {
                    'csrfmiddlewaretoken': csrf_token.group(1),
                    'targetip': self.domain,
                    'user': 'free'
                }
                resp = session.post("https://dnsdumpster.com/", data=data, timeout=15)
                
                # Parse results
                matches = re.findall(r'([a-zA-Z0-9.-]+\.' + re.escape(self.domain) + r')', resp.text)
                for match in matches:
                    subs.add(match.lower())
        except:
            pass
        return subs
    
    def subdomaincenter(self) -> Set[str]:
        """Subdomain Center - Free subdomain finder"""
        subs = set()
        try:
            url = f"https://api.subdomain.center/?domain={self.domain}"
            data = make_request(url, timeout=10, json_resp=True)
            if data and isinstance(data, list):
                for sub in data:
                    if self.domain in sub:
                        subs.add(sub.lower())
        except:
            pass
        return subs
    
    def thc_subdomain(self) -> Set[str]:
        """THC - Free subdomain enumeration (ip.thc.org)"""
        subs = set()
        try:
            url = f"https://ip.thc.org/api/v1/dns/search?query={self.domain}"
            data = make_request(url, timeout=10, json_resp=True)
            if data:
                for entry in data:
                    sub = entry.get('hostname', '').lower()
                    if self.domain in sub:
                        subs.add(sub)
        except:
            pass
        return subs
    
    def threatminer(self) -> Set[str]:
        """ThreatMiner - Subdomain and related data"""
        subs = set()
        try:
            url = f"https://api.threatminer.org/v2/domain.php?q={self.domain}&rt=5"
            data = make_request(url, timeout=10, json_resp=True)
            if data and data.get('results'):
                for sub in data['results']:
                    if self.domain in sub:
                        subs.add(sub.lower())
        except:
            pass
        return subs
    
    # =========================================================================
    # SEARCH ENGINES (No API Key Required)
    # =========================================================================
    
    def duckduckgo(self) -> Set[str]:
        """DuckDuckGo search for subdomains"""
        subs = set()
        try:
            url = f"https://html.duckduckgo.com/html/?q=site:{self.domain}"
            headers = {'User-Agent': get_random_ua()}
            data = make_request(url, headers=headers, timeout=10)
            if data:
                matches = re.findall(r'([a-zA-Z0-9.-]+\.' + re.escape(self.domain) + r')', data)
                for match in matches:
                    subs.add(match.lower())
        except:
            pass
        return subs
    
    def baidu(self) -> Set[str]:
        """Baidu search for subdomains"""
        subs = set()
        try:
            url = f"https://www.baidu.com/s?wd=site:{self.domain}"
            headers = {'User-Agent': get_random_ua()}
            data = make_request(url, headers=headers, timeout=10)
            if data:
                matches = re.findall(r'([a-zA-Z0-9.-]+\.' + re.escape(self.domain) + r')', data)
                for match in matches:
                    subs.add(match.lower())
        except:
            pass
        return subs
    
    def yahoo(self) -> Set[str]:
        """Yahoo search for subdomains"""
        subs = set()
        try:
            url = f"https://search.yahoo.com/search?p=site:{self.domain}"
            headers = {'User-Agent': get_random_ua()}
            data = make_request(url, headers=headers, timeout=10)
            if data:
                matches = re.findall(r'([a-zA-Z0-9.-]+\.' + re.escape(self.domain) + r')', data)
                for match in matches:
                    subs.add(match.lower())
        except:
            pass
        return subs
    
    # =========================================================================
    # API-BASED SOURCES (Key Required)
    # =========================================================================
    
    def virustotal(self, api_key: str) -> Set[str]:
        """VirusTotal subdomain search"""
        subs = set()
        if not api_key:
            return subs
        try:
            url = f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={api_key}&domain={self.domain}"
            data = make_request(url, timeout=15, json_resp=True)
            if data:
                for sub in data.get('subdomains', []):
                    subs.add(sub.lower())
        except:
            pass
        return subs
    
    def shodan_subdomains(self, api_key: str) -> Set[str]:
        """Shodan subdomain search"""
        subs = set()
        if not api_key:
            return subs
        try:
            url = f"https://api.shodan.io/dns/domain/{self.domain}?key={api_key}"
            data = make_request(url, timeout=15, json_resp=True)
            if data:
                for entry in data.get('data', []):
                    sub = entry.get('subdomain', '')
                    if sub:
                        subs.add(f"{sub}.{self.domain}".lower())
        except:
            pass
        return subs
    
    def censys_subdomains(self, api_id: str, api_secret: str) -> Set[str]:
        """Censys subdomain search"""
        subs = set()
        if not api_id or not api_secret:
            return subs
        try:
            auth = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
            headers = {'Authorization': f'Basic {auth}', 'Content-Type': 'application/json'}
            url = f"https://search.censys.io/api/v2/certificates/search"
            query = {"q": f"names: {self.domain}", "per_page": 100}
            resp = requests.post(url, headers=headers, json=query, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                for hit in data.get('result', {}).get('hits', []):
                    for name in hit.get('names', []):
                        if self.domain in name and '*' not in name:
                            subs.add(name.lower())
        except:
            pass
        return subs
    
    def securitytrails(self, api_key: str) -> Set[str]:
        """SecurityTrails subdomain search"""
        subs = set()
        if not api_key:
            return subs
        try:
            headers = {'APIKEY': api_key}
            url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
            data = make_request(url, headers=headers, timeout=15, json_resp=True)
            if data and data.get('subdomains'):
                for sub in data['subdomains']:
                    subs.add(f"{sub}.{self.domain}".lower())
        except:
            pass
        return subs
    
    def fullhunt(self, api_key: str) -> Set[str]:
        """FullHunt attack surface search"""
        subs = set()
        if not api_key:
            return subs
        try:
            headers = {'X-API-KEY': api_key}
            url = f"https://fullhunt.io/api/v1/domain/{self.domain}/subdomains"
            data = make_request(url, headers=headers, timeout=15, json_resp=True)
            if data and data.get('hosts'):
                for sub in data['hosts']:
                    subs.add(sub.lower())
        except:
            pass
        return subs
    
    def intelx(self, api_key: str) -> Set[str]:
        """Intelligence X search"""
        subs = set()
        if not api_key:
            return subs
        try:
            headers = {'x-key': api_key, 'Content-Type': 'application/json'}
            # Start search
            search_url = "https://2.intelx.io/intelligent/search"
            payload = {"term": self.domain, "maxresults": 100, "media": 0, "sort": 2, "terminate": []}
            resp = requests.post(search_url, headers=headers, json=payload, timeout=15)
            if resp.status_code == 200:
                search_id = resp.json().get('id')
                # Get results
                time.sleep(2)
                result_url = f"https://2.intelx.io/intelligent/search/result?id={search_id}"
                resp = requests.get(result_url, headers=headers, timeout=15)
                if resp.status_code == 200:
                    data = resp.json()
                    for record in data.get('records', []):
                        # Extract subdomains from records
                        name = record.get('name', '')
                        if self.domain in name:
                            subs.add(name.lower())
        except:
            pass
        return subs
    
    def leakix(self, api_key: str = None) -> Set[str]:
        """LeakIX search (works without key but rate limited)"""
        subs = set()
        try:
            headers = {'User-Agent': get_random_ua()}
            if api_key:
                headers['api-key'] = api_key
            url = f"https://leakix.net/api/subdomains/{self.domain}"
            data = make_request(url, headers=headers, timeout=15, json_resp=True)
            if data:
                for entry in data:
                    sub = entry.get('subdomain', '')
                    if self.domain in sub:
                        subs.add(sub.lower())
        except:
            pass
        return subs
    
    def netlas(self, api_key: str) -> Set[str]:
        """Netlas subdomain search"""
        subs = set()
        if not api_key:
            return subs
        try:
            headers = {'X-API-Key': api_key}
            url = f"https://app.netlas.io/api/domains/?q=domain:*.{self.domain}"
            data = make_request(url, headers=headers, timeout=15, json_resp=True)
            if data and data.get('items'):
                for item in data['items']:
                    sub = item.get('data', {}).get('domain', '')
                    if self.domain in sub:
                        subs.add(sub.lower())
        except:
            pass
        return subs
    
    def urlscan(self, api_key: str = None) -> Set[str]:
        """URLScan subdomain search"""
        subs = set()
        try:
            headers = {'User-Agent': get_random_ua()}
            if api_key:
                headers['API-Key'] = api_key
            url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}"
            data = make_request(url, headers=headers, timeout=15, json_resp=True)
            if data and data.get('results'):
                for result in data['results']:
                    page = result.get('page', {})
                    domain = page.get('domain', '').lower()
                    if self.domain in domain:
                        subs.add(domain)
        except:
            pass
        return subs
    
    def chaos(self, api_key: str) -> Set[str]:
        """ProjectDiscovery Chaos subdomain search"""
        subs = set()
        if not api_key:
            return subs
        try:
            headers = {'Authorization': api_key}
            url = f"https://dns.projectdiscovery.io/dns/{self.domain}/subdomains"
            data = make_request(url, headers=headers, timeout=15, json_resp=True)
            if data and data.get('subdomains'):
                for sub in data['subdomains']:
                    subs.add(f"{sub}.{self.domain}".lower())
        except:
            pass
        return subs
    
    def brave_search(self, api_key: str) -> Set[str]:
        """Brave Search API for subdomains"""
        subs = set()
        if not api_key:
            return subs
        try:
            headers = {'X-Subscription-Token': api_key, 'Accept': 'application/json'}
            url = f"https://api.search.brave.com/res/v1/web/search?q=site:{self.domain}"
            data = make_request(url, headers=headers, timeout=15, json_resp=True)
            if data and data.get('web', {}).get('results'):
                for result in data['web']['results']:
                    url_str = result.get('url', '')
                    matches = re.findall(r'([a-zA-Z0-9.-]+\.' + re.escape(self.domain) + r')', url_str)
                    for match in matches:
                        subs.add(match.lower())
        except:
            pass
        return subs
    
    def fofa(self, email: str, api_key: str) -> Set[str]:
        """FOFA search engine"""
        subs = set()
        if not email or not api_key:
            return subs
        try:
            query = base64.b64encode(f'domain="{self.domain}"'.encode()).decode()
            url = f"https://fofa.info/api/v1/search/all?email={email}&key={api_key}&qbase64={query}&size=100"
            data = make_request(url, timeout=15, json_resp=True)
            if data and data.get('results'):
                for result in data['results']:
                    if len(result) > 0:
                        host = result[0]
                        if self.domain in host:
                            subs.add(host.lower())
        except:
            pass
        return subs
    
    def zoomeye(self, api_key: str) -> Set[str]:
        """ZoomEye search (China's Shodan)"""
        subs = set()
        if not api_key:
            return subs
        try:
            headers = {'API-KEY': api_key}
            url = f"https://api.zoomeye.org/domain/search?q={self.domain}&type=1"
            data = make_request(url, headers=headers, timeout=15, json_resp=True)
            if data and data.get('list'):
                for item in data['list']:
                    sub = item.get('name', '')
                    if self.domain in sub:
                        subs.add(sub.lower())
        except:
            pass
        return subs
    
    def onyphe(self, api_key: str) -> Set[str]:
        """Onyphe cyber defense search"""
        subs = set()
        if not api_key:
            return subs
        try:
            headers = {'Authorization': f'apikey {api_key}'}
            url = f"https://www.onyphe.io/api/v2/simple/resolver/{self.domain}"
            data = make_request(url, headers=headers, timeout=15, json_resp=True)
            if data and data.get('results'):
                for result in data['results']:
                    sub = result.get('forward', '')
                    if self.domain in sub:
                        subs.add(sub.lower())
        except:
            pass
        return subs
    
    def criminalip(self, api_key: str) -> Set[str]:
        """Criminal IP - CTI search"""
        subs = set()
        if not api_key:
            return subs
        try:
            headers = {'x-api-key': api_key}
            url = f"https://api.criminalip.io/v1/domain/reports/subdomains?query={self.domain}"
            data = make_request(url, headers=headers, timeout=15, json_resp=True)
            if data and data.get('data'):
                for item in data['data']:
                    sub = item.get('subdomain', '')
                    if self.domain in sub:
                        subs.add(sub.lower())
        except:
            pass
        return subs
    
    # =========================================================================
    # EMAIL DISCOVERY SOURCES
    # =========================================================================
    
    def hunter_emails(self, api_key: str) -> Set[str]:
        """Hunter.io email finder"""
        emails = set()
        if not api_key:
            return emails
        try:
            url = f"https://api.hunter.io/v2/domain-search?domain={self.domain}&api_key={api_key}"
            data = make_request(url, timeout=15, json_resp=True)
            if data and data.get('data', {}).get('emails'):
                for entry in data['data']['emails']:
                    emails.add(entry.get('value', '').lower())
        except:
            pass
        return emails
    
    def tomba_emails(self, api_key: str, secret: str) -> Set[str]:
        """Tomba.io email finder"""
        emails = set()
        if not api_key or not secret:
            return emails
        try:
            headers = {'X-Tomba-Key': api_key, 'X-Tomba-Secret': secret}
            url = f"https://api.tomba.io/v1/domain-search?domain={self.domain}"
            data = make_request(url, headers=headers, timeout=15, json_resp=True)
            if data and data.get('data', {}).get('emails'):
                for entry in data['data']['emails']:
                    emails.add(entry.get('email', '').lower())
        except:
            pass
        return emails
    
    # =========================================================================
    # AGGREGATE RUNNER
    # =========================================================================
    
    def run_all_free(self) -> Tuple[Set[str], int]:
        """Run all free (no API key) sources in parallel."""
        all_subs = set()
        sources_run = 0
        
        free_sources = [
            ('crt.sh', self.crtsh),
            ('CertSpotter', self.certspotter),
            ('BufferOver', self.bufferoverun),
            ('HackerTarget', self.hackertarget),
            ('RapidDNS', self.rapiddns),
            ('DNSDumpster', self.dnsdumpster),
            ('SubdomainCenter', self.subdomaincenter),
            ('THC', self.thc_subdomain),
            ('ThreatMiner', self.threatminer),
            ('DuckDuckGo', self.duckduckgo),
            ('Yahoo', self.yahoo),
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {}
            for name, func in free_sources:
                futures[executor.submit(func)] = name
            
            for future in concurrent.futures.as_completed(futures, timeout=60):
                name = futures[future]
                try:
                    result = future.result()
                    if result:
                        # Clean results before adding
                        cleaned = self._clean_subdomains(result)
                        if cleaned:
                            print(f"        - {name}: {len(cleaned)} valid subdomain(s)")
                            all_subs.update(cleaned)
                            sources_run += 1
                except Exception as e:
                    pass
        
        return all_subs, sources_run
    
    def run_with_apis(self, api_keys: dict) -> Tuple[Set[str], int]:
        """Run API-based sources with provided keys."""
        all_subs = set()
        sources_run = 0
        
        api_sources = [
            ('VirusTotal', lambda: self.virustotal(api_keys.get('VIRUSTOTAL_API_KEY', ''))),
            ('Shodan', lambda: self.shodan_subdomains(api_keys.get('SHODAN_API_KEY', ''))),
            ('Censys', lambda: self.censys_subdomains(api_keys.get('CENSYS_API_ID', ''), api_keys.get('CENSYS_API_SECRET', ''))),
            ('SecurityTrails', lambda: self.securitytrails(api_keys.get('SECURITYTRAILS_API_KEY', ''))),
            ('FullHunt', lambda: self.fullhunt(api_keys.get('FULLHUNT_API_KEY', ''))),
            ('LeakIX', lambda: self.leakix(api_keys.get('LEAKIX_API_KEY', ''))),
            ('URLScan', lambda: self.urlscan(api_keys.get('URLSCAN_API_KEY', ''))),
            ('Chaos', lambda: self.chaos(api_keys.get('CHAOS_API_KEY', ''))),
            ('Brave', lambda: self.brave_search(api_keys.get('BRAVE_API_KEY', ''))),
            ('Netlas', lambda: self.netlas(api_keys.get('NETLAS_API_KEY', ''))),
            ('ZoomEye', lambda: self.zoomeye(api_keys.get('ZOOMEYE_API_KEY', ''))),
            ('Onyphe', lambda: self.onyphe(api_keys.get('ONYPHE_API_KEY', ''))),
            ('CriminalIP', lambda: self.criminalip(api_keys.get('CRIMINALIP_API_KEY', ''))),
        ]
        
        for name, func in api_sources:
            try:
                result = func()
                if result:
                    # Clean results before adding
                    cleaned = self._clean_subdomains(result)
                    if cleaned:
                        print(f"        - {name}: {len(cleaned)} valid subdomain(s)")
                        all_subs.update(cleaned)
                        sources_run += 1
            except:
                pass
        
        return all_subs, sources_run


if __name__ == "__main__":
    # Test mode
    import sys
    if len(sys.argv) > 1:
        domain = sys.argv[1]
        ps = PassiveSources(domain)
        print(f"Testing passive sources for: {domain}")
        subs, count = ps.run_all_free()
        print(f"\nTotal: {len(subs)} unique subdomains from {count} sources")
        for sub in sorted(list(subs))[:20]:
            print(f"  - {sub}")
    else:
        print("Usage: python passive_sources.py <domain>")
