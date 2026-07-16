"""
Web Reconnaissance Module
Adds new web reconnaissance techniques (free platforms only) without altering existing modules.

Techniques (all free / no paid APIs required):
  1. CORS Misconfiguration Testing
  2. Open Redirect Detection
  3. CRLF Injection Testing
  4. Subdomain Takeover Detection (free check)
  5. Host Header Injection Testing
  6. Rate Limit Detection
  7. Technology CVE Lookup (free CVE database)
  8. Sensitive Comment Extraction
  9. Mixed Content Detection
  10. Cache & Caching Header Inspection
  11. Third-party Resource Analysis
  12. Form Discovery & Analysis
  13. Password Policy Analysis
  14. Embedded Object Detection (iframes, objects)
  15. Content Security Policy Deep Analysis
  16. API Endpoint Security Testing
  17. HTTP Request Smuggling Detection (basic)
  18. Information Disclosure Testing
  19. Backup/Sensitive File Discovery
  20. Hidden Endpoint Discovery
  21. SMTP Open Relay Testing
  22. Active Subdomain Brute Force
  23. Network Route Visualization

Free API platforms used (with free tiers):
  - urlscan.io (free, no key needed for basic queries)
  - HackerTarget (free, no key needed)
  - NVD/CVE (free, no key needed)
"""

import socket
import ssl
import os
import subprocess
import concurrent.futures
import requests
import re
import json
import time
from urllib.parse import urljoin, urlparse
from typing import Optional, List, Set
from config import config, Colors
from utils import get_random_user_agent as _get_ua

# Disable SSL warnings
try:
    requests.packages.urllib3.disable_warnings()
except:
    pass


class WebRecon:
    """
    Complementary Web Reconnaissance module.
    ALL techniques are new additions - does NOT modify existing web_analysis.py methods.
    Uses ONLY free platforms. Paid API keys are NOT required for any technique.
    
    Free API platforms used:
      - HackerTarget (free, no key needed)
      - NVD/CVE (free, no key needed)
    """

    __slots__ = ('target', 'target_id', 'db', 'base_url', 'http_timeout',
                 'session', 'domains_found', 'secrets_found')

    def __init__(self, target: str, target_id: int, db_manager):
        self.target = target
        self.target_id = target_id
        self.db = db_manager
        self.base_url = f"https://{target}"
        self.http_timeout = 8
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': _get_ua()})
        self.session.verify = False
        self.domains_found: Set[str] = set()
        self.secrets_found: list = []

    def _db_execute(self, query: str, params=()) -> Optional[any]:
        if not self.db.connect():
            return None
        try:
            cursor = self.db.conn.cursor()
            cursor.execute(query, params)
            self.db.conn.commit()
            return cursor
        except Exception:
            return None
        finally:
            self.db.close()

    def _save_finding(self, title: str, severity: str = 'Info', description: str = ''):
        self._db_execute(
            "INSERT OR IGNORE INTO findings (target_id, title, severity, description, url) VALUES (?, ?, ?, ?, ?)",
            (self.target_id, title, severity, description, self.base_url)
        )

    # =========================================================================
    # 1. CORS MISCONFIGURATION TESTING
    # =========================================================================

    def run_cors_testing(self):
        """Test for CORS misconfigurations that allow arbitrary origins."""
        print("    - CORS Misconfiguration Testing...")
        test_origins = [
            'https://evil.com',
            'null',
            'https://evil.' + self.target,
            'https://' + self.target + '.evil.com',
            'https://' + self.target + '.evil',
        ]

        issues = []
        for origin in test_origins:
            try:
                resp = self.session.get(
                    self.base_url,
                    headers={
                        'Origin': origin,
                        'User-Agent': _get_ua()
                    },
                    timeout=5
                )
                acao = resp.headers.get('Access-Control-Allow-Origin', '')
                acac = resp.headers.get('Access-Control-Allow-Credentials', '')

                if acao == '*' or acao == origin:
                    issue = f"Origin {origin[:40]} reflected in ACAO"
                    issues.append(issue)

                    if acac == 'true':
                        self._save_finding(
                            "CORS: Credentialed Misconfiguration",
                            "Critical",
                            f"ACAO reflects '{origin}' with Allow-Credentials=true"
                        )
                        print(f"      ⚠ CRITICAL: {issue} (with credentials)")
                    else:
                        self._save_finding(
                            "CORS: Arbitrary Origin Reflection",
                            "Medium",
                            f"ACAO reflects '{origin}'"
                        )
                        print(f"      ⚠ {issue}")
            except:
                pass

        if not issues:
            print(f"      ✓ No CORS misconfigurations detected")

    # =========================================================================
    # 2. OPEN REDIRECT DETECTION
    # =========================================================================

    def run_open_redirect_test(self):
        """Detect open redirect vulnerabilities in URL parameters."""
        print("    - Open Redirect Detection...")

        redirect_params = [
            'url', 'redirect', 'redirect_uri', 'redirect_url', 'return',
            'return_to', 'return_url', 'goto', 'next', 'target', 'view',
            'to', 'out', 'view', 'dir', 'dest', 'destination', 'location',
            'link', 'href', 'ref', 'referer', 'continue', 'follow',
            'page', 'forward', 'proxy', 'load', 'path', 'site',
        ]

        test_url = 'https://evil.com/'
        found = []

        for param in redirect_params:
            try:
                url = f"{self.base_url}?{param}={test_url}"
                resp = self.session.get(url, timeout=3, allow_redirects=False)
                location = resp.headers.get('Location', '')

                if 'evil.com' in location or 'evil' in location:
                    found.append(f"?{param}={test_url} -> {location}")
                    self._save_finding(
                        f"Open Redirect: {param} parameter",
                        "Medium",
                        f"Parameter '{param}' reflects external URL in redirect: {location}"
                    )
                    print(f"      ⚠ ?{param}={test_url[:30]} -> {location[:60]}")
            except:
                pass

        if not found:
            print(f"      ✓ No open redirects detected")

    # =========================================================================
    # 3. CRLF INJECTION TESTING
    # =========================================================================

    def run_crlf_test(self):
        """Test for CRLF injection (HTTP response splitting)."""
        print("    - CRLF Injection Testing...")

        payloads = [
            ('Header-Injection', '%0d%0aX-Injected:%20yes'),
            ('Header-Injection2', '%0d%0aX-Injected:%20yes%0d%0a'),
        ]

        found = False
        for header_name, payload in payloads:
            try:
                url = f"{self.base_url}/{self.target}/%3F{payload}"
                resp = self.session.get(
                    url,
                    timeout=3,
                    headers={'User-Agent': _get_ua()}
                )
                if 'X-Injected' in resp.headers.get('X-Injected', ''):
                    found = True
                    self._save_finding(
                        "CRLF Injection Detected",
                        "Critical",
                        f"CRLF injection possible via URL parameter: {payload[:40]}"
                    )
                    print(f"      ⚠ CRLF Injection: X-Injected header reflected!")
                    break
            except:
                pass

        if not found:
            print(f"      ✓ No CRLF injection detected")

    # =========================================================================
    # 4. SUBDOMAIN TAKEOVER DETECTION
    # =========================================================================

    def run_subdomain_takeover_check(self):
        """Check for potential subdomain takeover vulnerabilities (free check)."""
        print("    - Subdomain Takeover Detection...")

        # Check common vulnerable services by looking at CNAME records
        takeover_signatures = {
            'aws': ['s3.amazonaws.com', 'cloudfront.net', 'elasticbeanstalk.com'],
            'azure': ['azurewebsites.net', 'trafficmanager.net', 'cloudapp.net'],
            'gcp': ['appspot.com', 'storage.googleapis.com', 'firebaseio.com'],
            'github': ['github.io'],
            'heroku': ['herokuapp.com', 'herokudns.com'],
            'shopify': ['myshopify.com'],
            'wordpress': ['wordpress.com'],
            'surge': ['surge.sh'],
            'netlify': ['netlify.com', 'netlify.app'],
            'readme': ['readme.io'],
            'bitbucket': ['bitbucket.io'],
        }

        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3

            # Check main domain CNAME first
            try:
                answers = resolver.resolve(self.target, 'CNAME')
                for rdata in answers:
                    cname = str(rdata).lower()
                    for service, domains in takeover_signatures.items():
                        for domain in domains:
                            if domain in cname:
                                print(f"      ⚠ Potential takeover: {cname} ({service})")
                                self._save_finding(
                                    f"Subdomain Takeover Risk: {service}",
                                    "High",
                                    f"Domain {self.target} CNAMEs to {cname}. "
                                    f"If {service} resource is deleted, domain can be claimed."
                                )
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass

        except ImportError:
            print(f"      - dnspython not available, skipping CNAME check")

        print(f"      ✓ Subdomain takeover check complete")

    # =========================================================================
    # 5. HOST HEADER INJECTION
    # =========================================================================

    def run_host_header_injection(self):
        """Test for Host header injection and cache poisoning."""
        print("    - Host Header Injection Testing...")

        test_hosts = [
            'evil.com',
            f'evil.{self.target}',
            'localhost',
            '127.0.0.1',
            '0.0.0.0',
        ]

        issues = []
        try:
            baseline = self.session.get(self.base_url, timeout=3)

            for test_host in test_hosts:
                try:
                    resp = self.session.get(
                        self.base_url,
                        headers={'Host': test_host, 'User-Agent': _get_ua()},
                        timeout=3
                    )

                    # Check if response content changed (reflects different host)
                    if len(resp.content) != len(baseline.content):
                        if test_host in resp.text or test_host.split('.')[0] in resp.text:
                            issues.append(test_host)
                            self._save_finding(
                                f"Host Header Injection",
                                "Medium",
                                f"Server reflects Host header value in response. "
                                f"Tested: {test_host}"
                            )
                            print(f"      ⚠ Host header injection: {test_host}")
                            break
                except:
                    pass
        except:
            pass

        if not issues:
            print(f"      ✓ No host header injection detected")

    # =========================================================================
    # 6. RATE LIMIT DETECTION
    # =========================================================================

    def run_rate_limit_test(self):
        """Test if the target has rate limiting in place."""
        print("    - Rate Limit Detection...")

        responses = []
        start = time.time()

        for i in range(15):  # Send 15 rapid requests
            try:
                resp = self.session.get(
                    self.base_url,
                    timeout=2,
                    headers={'User-Agent': _get_ua()}
                )
                responses.append(resp.status_code)
                time.sleep(0.05)
            except:
                responses.append(0)

        elapsed = time.time() - start
        unique_codes = set(responses)
        rate_limited = any(code in [429, 503] for code in unique_codes)

        if rate_limited:
            print(f"      ✓ Rate limiting detected (429/503 after {len(responses)} requests)")
        else:
            print(f"      - No rate limiting detected ({len(responses)} requests in {elapsed:.1f}s)")
            self._save_finding(
                "No Rate Limiting Detected",
                "Low",
                f"Server allowed {len(responses)} requests in {elapsed:.1f}s without rate limiting"
            )

    # =========================================================================
    # 7. TECHNOLOGY CVE LOOKUP (Free NVD database)
    # =========================================================================

    def run_tech_cve_lookup(self):
        """Look up known CVEs for detected technologies using free NVD API."""
        print("    - Technology CVE Lookup...")

        # Query the database for detected technologies
        if not self.db.connect():
            return

        try:
            cursor = self.db.conn.cursor()
            cursor.execute(
                "SELECT DISTINCT name, version FROM technologies WHERE target_id=? AND version != ''",
                (self.target_id,)
            )
            techs = cursor.fetchall()
        except:
            techs = []
        finally:
            self.db.close()

        if not techs:
            print(f"      - No technologies with versions found in database")
            return

        for tech_name, tech_version in techs[:5]:  # Limit to 5 for speed
            try:
                # Use NVD API (free, no key needed, rate-limited)
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/"
                params = {
                    'keywordSearch': f'{tech_name} {tech_version}',
                    'resultsPerPage': 3
                }
                resp = requests.get(url, params=params, timeout=8)

                if resp.status_code == 200:
                    data = resp.json()
                    vulns = data.get('vulnerabilities', [])
                    if vulns:
                        print(f"      ⚠ {tech_name} {tech_version}: {len(vulns)} CVE(s) found")
                        for vuln in vulns[:2]:
                            cve_id = vuln.get('cve', {}).get('id', '')
                            desc = vuln.get('cve', {}).get('descriptions', [{}])[0].get('value', '')[:100]
                            print(f"        > {cve_id}: {desc}...")
                            self._save_finding(
                                f"CVE: {cve_id} ({tech_name})",
                                "Medium",
                                f"{tech_name} {tech_version}: {desc}"
                            )
                    else:
                        print(f"      - {tech_name} {tech_version}: No recent CVEs")
                time.sleep(1)  # Rate limit for NVD API
            except:
                continue

    # =========================================================================
    # 8. SENSITIVE COMMENT EXTRACTION
    # =========================================================================

    def run_comment_extraction(self):
        """Extract sensitive HTML/JavaScript comments from pages."""
        print("    - Sensitive Comment Extraction...")

        sensitive_patterns = [
            (r'<!--.*?(?:TODO|FIXME|HACK|XXX|WARN|BUG|TODO|REMOVE|DELETE|TODO|FIX|HACK).*?-->',
             'Sensitive HTML Comment'),
            (r'//\s*(?:TODO|FIXME|HACK|XXX|WARN|BUG|TODO).*$', 'Sensitive JS Comment'),
            (r'<!--.*?(?:password|secret|key|token|api_key|api.secret|credentials?).*?-->',
             'Credential in Comment'),
            (r'<!--.*?(?:administrator|admin|login|debug|test|dev).*?-->',
             'Admin Comment'),
            (r'<!--.*?(?:deprecated|old|removed|obsolete|no longer).*?-->',
             'Deprecated Code Comment'),
            (r'<!--.*?(?:username|email|phone|ssn|address).*?-->',
             'PII in Comment'),
            (r'/\*.*?(?:password|secret|key|token).*?\*/', 'Credential in Block Comment'),
        ]

        found = []
        urls_to_check = [self.base_url]

        # Add a few common paths
        for path in ['/js/main.js', '/js/app.js', '/assets/js/main.js',
                      '/static/js/main.js', '/wp-content/themes/']:
            urls_to_check.append(urljoin(self.base_url, path))

        for url in urls_to_check[:5]:
            try:
                resp = self.session.get(url, timeout=3)
                text = resp.text

                for pattern, label in sensitive_patterns:
                    matches = re.findall(pattern, text, re.IGNORECASE | re.MULTILINE)
                    for match in matches[:3]:
                        clean = match.strip()[:80]
                        found.append(f"{label}: {clean}")
                        self._save_finding(
                            f"Sensitive Comment: {label}",
                            "Medium",
                            f"Found in {url}: {clean}"
                        )
            except:
                pass

        if found:
            for f in found[:5]:
                print(f"      ⚠ {f}")
        else:
            print(f"      ✓ No sensitive comments found")

    # =========================================================================
    # 9. MIXED CONTENT DETECTION
    # =========================================================================

    def run_mixed_content_check(self):
        """Detect mixed content (HTTP resources on HTTPS pages)."""
        print("    - Mixed Content Detection...")

        try:
            response = self.session.get(self.base_url, timeout=5)
            html_text = response.text

            # Find HTTP resources
            http_sources = []
            http_sources.extend(re.findall(r'src="http://[^"]+', html_text))
            http_sources.extend(re.findall(r'href="http://[^"]+', html_text))
            http_sources.extend(re.findall(r"src='http://[^']+", html_text))
            http_sources.extend(re.findall(r"href='http://[^']+", html_text))

            # Filter to actual resources (not navigation links)
            resource_extensions = ('.js', '.css', '.png', '.jpg', '.gif', '.svg', '.ico',
                                    '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.webm')
            mixed = [s for s in http_sources if any(s.split('?')[0].lower().endswith(ext) for ext in resource_extensions)]

            if mixed:
                print(f"      ⚠ Mixed content: {len(mixed)} HTTP resource(s)")
                for item in mixed[:5]:
                    print(f"        > {item[:80]}")
                self._save_finding(
                    "Mixed Content Detected",
                    "Medium",
                    f"Page loads {len(mixed)} HTTP resource(s) over HTTPS"
                )
            else:
                print(f"      ✓ No mixed content detected")
        except:
            print(f"      - Mixed content check failed")

    # =========================================================================
    # 10. CACHE & CACHING HEADER INSPECTION
    # =========================================================================

    def run_cache_inspection(self):
        """Analyze caching headers and cache behavior."""
        print("    - Cache & Cache Header Inspection...")

        try:
            resp = self.session.get(self.base_url, timeout=3)

            cache_headers = {
                'Cache-Control': resp.headers.get('Cache-Control', ''),
                'Pragma': resp.headers.get('Pragma', ''),
                'Expires': resp.headers.get('Expires', ''),
                'Age': resp.headers.get('Age', ''),
                'ETag': resp.headers.get('ETag', '')[:30],
                'Last-Modified': resp.headers.get('Last-Modified', '')[:30],
                'X-Cache': resp.headers.get('X-Cache', ''),
                'CF-Cache-Status': resp.headers.get('CF-Cache-Status', ''),
            }

            # Display cache status
            cache_status = resp.headers.get('X-Cache', resp.headers.get('CF-Cache-Status', ''))
            if cache_status:
                print(f"      ✓ Cache status: {cache_status}")

            # Check for sensitive caching
            cc = cache_headers.get('Cache-Control', '').lower()
            if 'no-store' in cc or 'no-cache' in cc:
                print(f"      ✓ Cache-Control: no-store (sensitive data protected)")
            elif 'public' in cc:
                print(f"      ⚠ Cache-Control: public (may cache sensitive data)")

            # Check for ETag cache leaks
            etag = cache_headers.get('ETag', '')
            if etag:
                print(f"      - ETag: {etag}")

        except:
            print(f"      - Cache inspection failed")

    # =========================================================================
    # 11. THIRD-PARTY RESOURCE ANALYSIS
    # =========================================================================

    def run_third_party_analysis(self):
        """Analyze third-party resources loaded by the page."""
        print("    - Third-party Resource Analysis...")

        try:
            resp = self.session.get(self.base_url, timeout=5)
            text = resp.text

            # Find all external domains in src/href
            external_domains = set()
            all_srcs = re.findall(r'(?:src|href)="(https?://[^"]+)"', text)

            for src in all_srcs:
                try:
                    domain = urlparse(src).netloc
                    if domain and domain != self.target:
                        external_domains.add(domain)
                except:
                    pass

            if external_domains:
                print(f"      ✓ {len(external_domains)} third-party domain(s):")
                for domain in sorted(external_domains)[:10]:
                    # Categorize
                    category = "Unknown"
                    if 'google' in domain: category = "Analytics/Ads"
                    elif 'facebook' in domain: category = "Social"
                    elif 'cloudflare' in domain: category = "CDN"
                    elif 'jquery' in domain or 'cdnjs' in domain: category = "Library CDN"
                    elif 'jsdelivr' in domain: category = "Library CDN"
                    elif 'bootstrap' in domain: category = "Framework CDN"
                    elif 'hotjar' in domain: category = "Analytics"
                    elif 'newrelic' in domain: category = "Monitoring"
                    elif 'stripe' in domain or 'paypal' in domain: category = "Payment"
                    elif 'sentry' in domain: category = "Error Tracking"
                    print(f"        > {domain} ({category})")

                if len(external_domains) > 10:
                    print(f"        ... and {len(external_domains) - 10} more")
            else:
                print(f"      - No third-party resources detected")
        except:
            print(f"      - Third-party analysis failed")

    # =========================================================================
    # 12. FORM DISCOVERY & ANALYSIS
    # =========================================================================

    def run_form_discovery(self):
        """Discover forms and analyze input fields for security relevance."""
        print("    - Form Discovery & Analysis...")

        try:
            resp = self.session.get(self.base_url, timeout=5)
            text = resp.text

            # Find forms
            forms = re.findall(r'<form[^>]*action="([^"]*)"[^>]*method="([^"]*)"[^>]*>', text, re.IGNORECASE)
            inputs = re.findall(r'<input[^>]*name="([^"]*)"[^>]*type="([^"]*)"[^>]*>', text, re.IGNORECASE)

            if inputs:
                print(f"      ✓ Found {len(inputs)} input field(s)")
                if forms:
                    print(f"        in {len(forms)} form(s)")

                # Check for file uploads
                file_uploads = [n for n, t in inputs if t == 'file']
                if file_uploads:
                    print(f"      ⚠ File upload field(s): {', '.join(file_uploads[:3])}")
                    self._save_finding(
                        "File Upload Detected",
                        "Medium",
                        f"File upload fields: {', '.join(file_uploads[:3])}"
                    )

                # Check for search fields
                search_fields = [n for n, t in inputs if 'search' in t.lower() or 'q' == n.lower()]
                if search_fields:
                    print(f"      - Search fields: {', '.join(search_fields[:3])}")

            if not forms and not inputs:
                print(f"      - No forms detected on homepage")
        except:
            print(f"      - Form analysis failed")

    # =========================================================================
    # 13. PASSWORD POLICY ANALYSIS
    # =========================================================================

    def run_password_policy_analysis(self):
        """Analyze password policies from registration/login pages."""
        print("    - Password Policy Analysis...")

        auth_paths = ['/login', '/register', '/signup', '/signin', '/create-account']
        findings = []

        for path in auth_paths:
            try:
                url = urljoin(self.base_url, path)
                resp = self.session.get(url, timeout=3)

                if resp.status_code < 400:
                    text = resp.text.lower()

                    # Look for password requirements
                    min_len = re.search(r'(\d+)\s*(?:character|char|length)', text)
                    require_upper = 'uppercase' in text or 'capital' in text
                    require_lower = 'lowercase' in text
                    require_digit = 'digit' in text or 'number' in text
                    require_special = 'special' in text or 'symbol' in text

                    reqs = []
                    if min_len: reqs.append(f"min {min_len.group(1)} chars")
                    if require_upper: reqs.append("uppercase")
                    if require_lower: reqs.append("lowercase")
                    if require_digit: reqs.append("digit")
                    if require_special: reqs.append("special char")

                    if reqs:
                        print(f"      {path}: {', '.join(reqs)}")
                        findings.append((path, reqs))
            except:
                continue

        if not findings:
            print(f"      - No registration/login pages accessible for policy check")

    # =========================================================================
    # 14. EMBEDDED OBJECT DETECTION
    # =========================================================================

    def run_embedded_objects_check(self):
        """Detect embedded objects: iframes, objects, embeds."""
        print("    - Embedded Object Detection...")

        try:
            resp = self.session.get(self.base_url, timeout=5)
            text = resp.text

            iframes = re.findall(r'<iframe[^>]*src="([^"]*)"', text, re.IGNORECASE)
            objects = re.findall(r'<object[^>]*data="([^"]*)"', text, re.IGNORECASE)
            embeds = re.findall(r'<embed[^>]*src="([^"]*)"', text, re.IGNORECASE)

            if iframes:
                print(f"      ⚠ {len(iframes)} iframe(s):")
                for iframe in iframes[:3]:
                    print(f"        > {iframe[:80]}")
                    self._save_finding(
                        "iframe Inclusion",
                        "Info",
                        f"Page includes iframe: {iframe[:100]}"
                    )

            if objects:
                print(f"      ⚠ {len(objects)} object(s):")
                for obj in objects[:3]:
                    print(f"        > {obj[:80]}")

            if embeds:
                print(f"      ⚠ {len(embeds)} embed(s):")
                for emb in embeds[:3]:
                    print(f"        > {emb[:80]}")

            if not iframes and not objects and not embeds:
                print(f"      ✓ No embedded objects detected")
        except:
            print(f"      - Embedded object check failed")

    # =========================================================================
    # 15. CONTENT SECURITY POLICY DEEP ANALYSIS
    # =========================================================================

    def run_csp_analysis(self):
        """Deep Content Security Policy analysis."""
        print("    - Content Security Policy Analysis...")

        try:
            resp = self.session.get(self.base_url, timeout=5)
            csp = resp.headers.get('Content-Security-Policy', '')

            if not csp:
                print(f"      ⚠ No CSP header found!")
                self._save_finding(
                    "Missing Content Security Policy",
                    "Medium",
                    "No CSP header found. Risk of XSS and data injection."
                )
                return

            directives = {}
            for directive in csp.split(';'):
                directive = directive.strip()
                if ' ' in directive:
                    key, value = directive.split(' ', 1)
                    directives[key.lower()] = value

            print(f"      ✓ CSP present with {len(directives)} directive(s)")

            # Check for dangerous directives
            issues = []
            script_src = directives.get('script-src', '')
            if "'unsafe-inline'" in script_src:
                issues.append("'unsafe-inline' in script-src (XSS risk)")
            if "'unsafe-eval'" in script_src:
                issues.append("'unsafe-eval' in script-src (code injection risk)")
            if script_src == '*':
                issues.append("script-src: * (all scripts allowed)")

            # Check for weak directives
            if 'default-src' not in directives and 'script-src' not in directives:
                issues.append("No default-src or script-src (no script restrictions)")

            if issues:
                print(f"      ⚠ CSP issues:")
                for issue in issues:
                    print(f"        > {issue}")
                    self._save_finding(
                        f"CSP: {issue}",
                        "Medium",
                        f"Content Security Policy issue: {issue}"
                    )
            else:
                print(f"      ✓ No major CSP issues found")

        except:
            print(f"      - CSP analysis failed")

    # =========================================================================
    # 16. API ENDPOINT SECURITY TESTING
    # =========================================================================

    def run_api_security_test(self):
        """Test API endpoints for common security issues."""
        print("    - API Endpoint Security Testing...")

        api_endpoints = [
            '/api/', '/api/v1/', '/api/v2/', '/api/v3/',
            '/graphql', '/rest/', '/api/swagger', '/api/docs',
            '/api/health', '/api/status', '/api/user', '/api/users',
            '/api/admin', '/api/config', '/swagger.json', '/openapi.json',
            '/api-docs/', '/v1/', '/v2/',
        ]

        found = []
        for endpoint in api_endpoints:
            try:
                url = urljoin(self.base_url, endpoint)
                resp = self.session.get(url, timeout=3)

                if resp.status_code < 400:
                    found.append((url, resp.status_code))
                    print(f"      ✓ {url} [{resp.status_code}]")

                    # Check for sensitive exposure
                    text = resp.text.lower()
                    if any(word in text for word in ['config', 'secret', 'key', 'token', 'password', 'admin']):
                        print(f"        ⚠ Potential sensitive data exposed!")
                        self._save_finding(
                            f"API Endpoint: {endpoint}",
                            "Medium",
                            f"API endpoint accessible at {url} with possible sensitive data"
                        )
            except:
                continue

        if not found:
            print(f"      - No open API endpoints detected")

    # =========================================================================
    # 17. HTTP REQUEST SMUGGLING DETECTION (basic)
    # =========================================================================

    def run_request_smuggling_check(self):
        """Basic HTTP request smuggling detection using raw sockets.
        Tests CL.TE (Content-Length / Transfer-Encoding) discrepancy.
        """
        print("    - HTTP Request Smuggling Check...")

        try:
            host = self.target
            port = 443 if 'https' in self.base_url else 80

            # Build raw CL.TE smuggling payload
            smuggled_req = "GET /404nonexistent HTTP/1.1\r\nHost: {}\r\n\r\n".format(host)
            cl_te_body = "0\r\n" + smuggled_req + "\r\n"
            content_length = str(len(cl_te_body))

            raw_request = (
                f"POST / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Length: {content_length}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"Connection: close\r\n"
                f"\r\n"
                f"{cl_te_body}"
            )

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)

            if port == 443:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            sock.connect((host, port))
            sock.send(raw_request.encode())

            response = b""
            try:
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data
            except socket.timeout:
                pass
            sock.close()

            text = response.decode(errors='ignore')

            if '404nonexistent' in text or '404 Not Found' in text:
                print(f"      ⚠ Possible CL.TE smuggling detected!")
                self._save_finding(
                    "HTTP Request Smuggling (CL.TE)",
                    "Critical",
                    "Possible CL.TE request smuggling detected via raw socket probe"
                )
            else:
                print(f"      ✓ No obvious request smuggling detected")
        except Exception as e:
            print(f"      - Request smuggling check: {e}")

    # =========================================================================
    # 18. INFORMATION DISCLOSURE TESTING
    # =========================================================================

    def run_info_disclosure_test(self):
        """Test for information disclosure via headers, error pages, etc."""
        print("    - Information Disclosure Testing...")

        disclosures = []
        try:
            resp = self.session.get(self.base_url, timeout=3)

            # Check for verbose server headers
            server = resp.headers.get('Server', '')
            x_powered = resp.headers.get('X-Powered-By', '')

            if server:
                print(f"      - Server: {server}")
                if 'detailed' in server.lower() or server.count('/') > 0:
                    disclosures.append(f"Verbose server header: {server}")

            if x_powered:
                print(f"      - X-Powered-By: {x_powered}")
                disclosures.append(f"Technology leak: {x_powered}")

            # Check for debug headers
            debug_headers = ['X-Debug', 'X-Debug-Info', 'X-Debug-Token',
                              'X-Debug-Token-Link', 'X-Sentry-ID', 'Debug']
            for dh in debug_headers:
                if dh in resp.headers:
                    disclosures.append(f"Debug header: {dh}: {resp.headers[dh][:50]}")
                    print(f"      ⚠ Debug header: {dh}")

            # Check for stack traces
            if any(sig in resp.text for sig in ['Stack trace:', 'Traceback (most recent',
                                                  'at java.lang', 'in <module>']):
                disclosures.append("Stack trace detected in response")
                print(f"      ⚠ Stack trace exposed!")

            # Check for directory listing
            if 'Index of /' in resp.text and 'Parent Directory' in resp.text:
                disclosures.append("Directory listing enabled")
                print(f"      ⚠ Directory listing enabled!")

            if disclosures:
                for d in disclosures[:5]:
                    self._save_finding(
                        f"Information Disclosure: {d[:60]}",
                        "Low",
                        d
                    )
        except:
            pass

        if not disclosures:
            print(f"      ✓ No major information disclosure detected")

    # =========================================================================
    # 19. BACKUP/SENSITIVE FILE DISCOVERY
    # =========================================================================

    def run_sensitive_file_discovery(self):
        """Discover backup files, sensitive archives, and exposed configs."""
        print("    - Sensitive File Discovery...")

        sensitive_files = [
            '/backup.zip', '/backup.tar.gz', '/backup.sql', '/db.sql',
            '/database.sql', '/dump.sql', '/export.sql', '/sql.tar.gz',
            '/wp-config.php.bak', '/wp-config.php~', '/wp-config.php.old',
            '/config.php.bak', '/config.php~', '/config.inc.php',
            '/config.json', '/config.yml', '/config.yaml',
            '/.aws/credentials', '/.git/config', '/.git/HEAD',
            '/.svn/entries', '/.svn/wc.db',
            '/.env.bak', '/.env.local', '/.env.dev', '/.env.prod',
            '/composer.json', '/package.json', '/yarn.lock',
            '/Dockerfile', '/docker-compose.yml',
            '/Procfile', '/app.json', '/scaleway.json',
            '/credentials.json', '/service-account.json',
            '/id_rsa', '/id_rsa.pub', '/authorized_keys',
            '/phpinfo.php', '/info.php', '/test.php',
            '/.htaccess', '/.htpasswd',
            '/web.config', '/Web.config',
            '/sitemap.xml', '/robots.txt', '/security.txt',
            '/swagger.json', '/openapi.json', '/api-docs.json',
        ]

        found = []
        for path in sensitive_files:
            try:
                url = urljoin(self.base_url + '/', path.lstrip('/'))
                resp = self.session.get(url, timeout=2, allow_redirects=False)

                if resp.status_code == 200 and len(resp.content) > 0:
                    found.append((path, resp.status_code, len(resp.content)))
                    severity = 'High' if any(k in path for k in ['key', 'credential', '.env', 'aws', 'secret',
                                                                    'id_rsa', 'htpasswd', 'service-account']) else 'Medium'
                    print(f"      ⚠ {path} [{resp.status_code}] ({len(resp.content)} bytes)")
                    self._save_finding(
                        f"Sensitive File: {path}",
                        severity,
                        f"Accessible: {url} ({len(resp.content)} bytes)"
                    )
            except:
                continue

        if not found:
            print(f"      ✓ No sensitive files discovered")

    # =========================================================================
    # 20. HIDDEN ENDPOINT DISCOVERY
    # =========================================================================

    def run_hidden_endpoint_discovery(self):
        """Discover hidden admin/API endpoints via common naming patterns."""
        print("    - Hidden Endpoint Discovery...")

        # Common admin/hidden endpoints
        endpoints = [
            '/admin', '/administrator', '/manage', '/management',
            '/panel', '/cpanel', '/dashboard', '/dash',
            '/console', '/shell', '/terminal', '/bash',
            '/phpmyadmin', '/pma', '/adminer', '/mysql',
            '/logs', '/log', '/debug', '/debugbar', '_debugbar',
            '/monitoring', '/monitor', '/metrics', '/prometheus',
            '/health', '/healthcheck', '/status', '/ready',
            '/swagger', '/api/doc', '/api/documentation',
            '/actuator', '/actuator/health', '/actuator/info',
            '/.well-known/', '/.well-known/security.txt',
            '/server-status', '/server-info',
            '/cgi-bin/', '/cgi-bin/status',
            '/web-console', '/jmx-console',
            '/version', '/version.txt', '/version.php',
            '/deploy', '/deployment', '/release',
        ]

        found = []
        for endpoint in endpoints:
            try:
                url = urljoin(self.base_url.rstrip('/') + '/', endpoint.lstrip('/'))
                resp = self.session.get(url, timeout=2, allow_redirects=False)

                if resp.status_code in [200, 201, 401, 403, 302, 301]:
                    found.append((endpoint, resp.status_code))
                    severity = 'Medium' if resp.status_code == 200 else 'Info'
                    if endpoint in ['/actuator', '/console', '/shell', '/phpmyadmin', '/metrics']:
                        severity = 'High'
                    print(f"      ✓ {endpoint} [{resp.status_code}]")
            except:
                continue

        if not found:
            print(f"      ✓ No hidden endpoints discovered")

    # =========================================================================
    # 21. SMTP RELAY TEST
    # =========================================================================

    def run_smtp_relay_test(self):
        """Test for open SMTP relay by attempting to send email through the target server.
        Uses raw socket to check if the server allows relaying mail to external domains.
        FREE technique — no API required.
        """
        print("    - SMTP Open Relay Test...")

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, 25))
            banner = sock.recv(1024).decode(errors='ignore')

            if '220' not in banner:
                print(f"      - No SMTP banner received")
                return

            print(f"      ✓ SMTP server detected")

            # EHLO — validate response before proceeding
            sock.send(f"EHLO relay-test-{self.target}\r\n".encode())
            ehlo_resp = sock.recv(2048).decode(errors='ignore')

            if '250' not in ehlo_resp:
                print(f"      - EHLO rejected, server may not support relaying")
                return

            # MAIL FROM
            sock.send(b"MAIL FROM:<test@relay-check.org>\r\n")
            mail_resp = sock.recv(512).decode(errors='ignore')

            if '250' not in mail_resp:
                print(f"      - MAIL FROM rejected (not an open relay)")
                return

            # RCPT TO: external domain — the actual relay test
            sock.send(b"RCPT TO:<nonexistent-test@example.com>\r\n")
            rcpt_resp = sock.recv(512).decode(errors='ignore')

            if '250' in rcpt_resp or '251' in rcpt_resp:
                print(f"      [OPEN RELAY] Server accepts mail for external domains!")
                self._save_finding(
                    "SMTP Open Relay Detected",
                    "Critical",
                    f"SMTP server at {self.target}:25 open relay — accepts external domain mail."
                )
            elif '550' in rcpt_resp or '553' in rcpt_resp or '554' in rcpt_resp:
                print(f"      ✓ RCPT TO rejected — relay blocked (no open relay)")
            else:
                resp_code = rcpt_resp[:3] if len(rcpt_resp) >= 3 else '?'
                print(f"      - RCPT TO response: {resp_code} (relay probably blocked)")

        except socket.timeout:
            print(f"      - SMTP port 25 timeout (filtered/blocked)")
        except ConnectionRefusedError:
            print(f"      - Port 25 closed")
        except Exception as e:
            print(f"      - SMTP relay test: {e}")
        finally:
            if sock:
                try:
                    sock.send(b"QUIT\r\n")
                except:
                    pass
                sock.close()

    # =========================================================================
    # 22. ACTIVE SUBDOMAIN BRUTE FORCE
    # =========================================================================

    def run_subdomain_brute_force(self):
        """Active subdomain brute force using common wordlist and DNS resolution.
        FREE technique — no API key required. Uses system DNS.
        """
        print("    - Subdomain Brute Force...")

        # Common subdomain wordlist (sorted by frequency)
        wordlist = [
            'www', 'mail', 'ftp', 'admin', 'api', 'blog', 'shop', 'cdn', 'dev',
            'test', 'webmail', 'm', 'support', 'forum', 'help', 'news', 'portal',
            'wiki', 'apps', 'app', 'server', 'ns1', 'ns2', 'smtp', 'pop3',
            'vpn', 'secure', 'status', 'git', 'bitbucket', 'jenkins', 'jira',
            'confluence', 'docs', 'wiki', 'kb', 'manager', 'partner', 'intranet',
            'dashboard', 'cms', 'wp-admin', 'wordpress', 'moodle', 'lms',
            'stage', 'staging', 'demo', 'beta', 'preprod', 'prod', 'production',
            'old', 'new', 'backup', 'monitor', 'analytics', 'tracking',
            'static', 'assets', 'images', 'css', 'js', 'img', 'files',
            'uploads', 'download', 'downloads', 'media', 'video', 'tv',
            'stream', 'chat', 'live', 'tv', 'radio', 'web', 'remote',
            'radius', 'ldap', 'mysql', 'db', 'database', 'sql',
            'owa', 'exchange', 'autodiscover', 'lync', 'skype',
            'cpanel', 'whm', 'webdisk', 'dns', 'direct',
        ]

        found = []

        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            resolver.nameservers = ['8.8.8.8', '8.8.4.4']

            print(f"      Brute-forcing {len(wordlist)} common subdomains...")

            for sub in wordlist:
                domain = f"{sub}.{self.target}"
                try:
                    answers = resolver.resolve(domain, 'A')
                    if answers:
                        ip = answers[0].to_text()
                        found.append((sub, ip))
                        print(f"      ✓ {sub}.{self.target} -> {ip}")
                    time.sleep(0.05)  # Rate limit
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    pass
                except dns.exception.Timeout:
                    pass
                except Exception:
                    pass

        except ImportError:
            print(f"      Using socket fallback for DNS...")
            for sub in wordlist:
                domain = f"{sub}.{self.target}"
                try:
                    ip = socket.gethostbyname(domain)
                    if ip:
                        found.append((sub, ip))
                        print(f"      ✓ {sub}.{self.target} -> {ip}")
                    time.sleep(0.05)
                except socket.gaierror:
                    pass
                except:
                    pass

        if found:
            print(f"      ✓ Found {len(found)} subdomain(s) via brute force")
            for sub, ip in found[:10]:
                self._save_finding(
                    f"Subdomain: {sub}.{self.target}",
                    "Info",
                    f"Brute-forced subdomain resolves to {ip}"
                )
        else:
            print(f"      - No subdomains found via brute force")

    # =========================================================================
    # 23. ROUTE VISUALIZATION
    # =========================================================================

    def run_route_visualization(self):
        """Visualize network route with hop-by-hop geo/IP analysis.
        Uses OS traceroute and free geo-lookup for each hop.
        FREE technique — no API key required.
        """
        print("    - Route Visualization...")

        if os.name == 'nt':
            cmd = ['tracert', '-h', '15', '-w', '2000', self.target]
        else:
            cmd = ['traceroute', '-m', '15', '-w', '2', '-q', '1', self.target]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
            if not result.stdout:
                print(f"      - Traceroute produced no output")
                return

            # Parse hops: extract hop number, IP, and hostname
            # Windows tracert format:
            #   1     1 ms     3 ms     3 ms  192.168.1.1
            #   2     *        *        *     Request timed out.
            #   3    10 ms     8 ms     9 ms  hostname.example.com [1.2.3.4]
            hops = []
            timed_out = 0
            for line in result.stdout.split('\n'):
                line = line.strip()
                if not line or not line[0].isdigit():
                    continue
                # Extract hop number (always at line start)
                hop_match = re.match(r'(\d+)', line)
                if not hop_match:
                    continue
                hop_num = int(hop_match.group(1))
                # Priority 1: IP in brackets [1.2.3.4] (avoids hostname false matches)
                ip_in_brackets = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', line)
                if ip_in_brackets:
                    hops.append((hop_num, ip_in_brackets.group(1)))
                else:
                    # Priority 2: standalone IP (no brackets)
                    ip_standalone = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if ip_standalone:
                        hops.append((hop_num, ip_standalone.group(1)))
                    else:
                        # No IP at all — timed out hop, skip silently
                        timed_out += 1

            if not hops:
                if timed_out > 0:
                    print(f"      - All {timed_out} hop(s) timed out (no response)")
                else:
                    print(f"      - Could not parse traceroute output")
                return
            if timed_out > 0:
                print(f"      (skipped {timed_out} timed-out hop(s))")

            print(f"      Route to {self.target} ({len(hops)} hops):")
            max_hop = max(h[0] for h in hops)

            # Resolve geo concurrently with shorter timeout
            def geo_lookup(ip: str) -> str:
                try:
                    r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=0.8)
                    if r.status_code == 200:
                        d = r.json()
                        city, country, org = d.get('city',''), d.get('country',''), d.get('org','')[:20]
                        parts = [p for p in [city, country] if p]
                        loc = ', '.join(parts)
                        return f"{loc} [{org}]" if org else loc
                except:
                    pass
                return ""

            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                geo_futures = {
                    executor.submit(geo_lookup, ip): (hop, ip)
                    for hop, ip in hops if hop > 1 and not ip.startswith(('10.', '172.16.', '192.168.'))
                }
                geo_results = {}
                for future in concurrent.futures.as_completed(geo_futures, timeout=10):
                    hop, ip = geo_futures[future]
                    try:
                        loc = future.result()
                        if loc:
                            geo_results[hop] = loc
                    except:
                        pass

            # Display route
            for hop_num, ip_addr in hops:
                bar_len = max(1, int((hop_num / max_hop) * 30))
                bar = '=' * bar_len + '>' if hop_num < max_hop else '=' * min(bar_len, 30) + '>'
                location = geo_results.get(hop_num, '')
                if location:
                    print(f"      {bar} Hop {hop_num}: {ip_addr} ({location})")
                elif ip_addr.startswith(('10.', '172.16.', '192.168.')):
                    print(f"      {bar} Hop {hop_num}: {ip_addr} (local network)")
                else:
                    print(f"      {bar} Hop {hop_num}: {ip_addr}")

        except subprocess.TimeoutExpired:
            print(f"      - Traceroute timed out")
        except FileNotFoundError:
            print(f"      - Traceroute command not found")
        except Exception as e:
            print(f"      - Route visualization: {e}")

    # =========================================================================
    # MAIN EXECUTION
    # =========================================================================

    def execute_all(self):
        """Run all web reconnaissance techniques."""
        print(f"\n{Colors.HEADER}WEB RECONNAISSANCE — New Free Techniques{Colors.RESET}")
        print(f"{Colors.INFO}[*] Target: {self.target}{Colors.RESET}")

        # Security Testing
        print(f"\n{Colors.BOLD}[1] WEB SECURITY TESTING{Colors.RESET}")
        print("-" * 40)
        self.run_cors_testing()
        self.run_open_redirect_test()
        self.run_crlf_test()
        self.run_host_header_injection()
        self.run_request_smuggling_check()

        # Vulnerability Assessment
        print(f"\n{Colors.BOLD}[2] VULNERABILITY ASSESSMENT{Colors.RESET}")
        print("-" * 40)
        self.run_rate_limit_test()
        self.run_smtp_relay_test()
        self.run_subdomain_brute_force()
        self.run_subdomain_takeover_check()
        self.run_tech_cve_lookup()
        self.run_sensitive_file_discovery()
        self.run_hidden_endpoint_discovery()

        # Content & Client Analysis
        print(f"\n{Colors.BOLD}[3] CONTENT & CLIENT ANALYSIS{Colors.RESET}")
        print("-" * 40)
        self.run_comment_extraction()
        self.run_mixed_content_check()
        self.run_third_party_analysis()
        self.run_embedded_objects_check()
        self.run_api_security_test()

        # Configuration, Network & Infrastructure
        print(f"\n{Colors.BOLD}[4] CONFIGURATION & NETWORK ANALYSIS{Colors.RESET}")
        print("-" * 40)
        self.run_cache_inspection()
        self.run_csp_analysis()
        self.run_info_disclosure_test()
        self.run_form_discovery()
        self.run_password_policy_analysis()
        self.run_route_visualization()

        print(f"{Colors.SUCCESS}    ✓ Web Reconnaissance completed{Colors.RESET}")
