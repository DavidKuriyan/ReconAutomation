import os
import sys
import time
import sqlite3
import subprocess
import requests
import dns.resolver
import socket
import ssl
import OpenSSL
import concurrent.futures
import re
import random
import os
import sys
import time
import sqlite3
import subprocess
import requests
import dns.resolver
import socket
import ssl
import OpenSSL
import concurrent.futures
import re
import random
from urllib.parse import urlparse

# Steath & WAF Evasion Constants
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1'
]

def get_random_headers(host):
    return {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Host': host
    }

# Steath & WAF Evasion Constants
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1'
]

def get_random_headers(host):
    return {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Host': host
    }

# Enhanced OSINT Modules
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

# Initialize Colorama
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    pass # Fallback to raw ANSI or stripped if needed

# Configuration
DB_PATH = "../reporter/argus.db"

def simple_whois(domain):
    try:
        # 1. Connect to Verisign (good default for com/net)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect(("whois.verisign-grs.com", 43))
        s.send(f"{domain}\r\n".encode())
        
        response = b""
        while True:
            data = s.recv(4096)
            if not data: break
            response += data
        s.close()
        
        text = response.decode(errors='ignore')
        return text
    except Exception as e:
        return f"WHOIS Lookup Failed: {e}"

def parse_whois_dates(text):
    # Very naive parser for demo purposes
    created = ""
    expires = ""
    registrar = ""
    
    for line in text.splitlines():
        line = line.strip()
        if "Creation Date:" in line:
            created = line.split(":", 1)[1].strip()
        elif "Registry Expiry Date:" in line:
            expires = line.split(":", 1)[1].strip()
        elif "Registrar:" in line:
            registrar = line.split(":", 1)[1].strip()
            
    return created, expires, registrar

class ReconEngine:
    def __init__(self, target, consent_given=False, scan_mode='full', custom_modules=None):
        # Normalize target (remove http://, https://, and trailing slash)
        self.target = target.replace("https://", "").replace("http://", "").strip("/")
        self.target_id = None
        self.conn = None
        self.consent_given = consent_given
        self.discovered_emails = []
        self.target_ip = None
        self.scan_mode = scan_mode  # 'full', 'active', 'passive', 'custom'
        self.custom_modules = custom_modules or []

    def connect_db(self):
        try:
            self.conn = sqlite3.connect(DB_PATH, timeout=30.0)
            self.conn.execute("PRAGMA journal_mode=WAL;")
            return True
        except Exception as e:
            print(f"[!] DB Connection Error: {e}")
            return False

    def close_db(self):
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass
            self.conn = None

    def get_or_create_target(self):
        if not self.connect_db(): return
        cursor = self.conn.cursor()
        cursor.execute("INSERT OR IGNORE INTO targets (domain) VALUES (?)", (self.target,))
        self.conn.commit()
        cursor.execute("SELECT id FROM targets WHERE domain = ?", (self.target,))
        result = cursor.fetchone()
        if result:
            self.target_id = result[0]
        self.close_db()
        print(f"[*] Target ID: {self.target_id}")

    def publish_event(self, channel, message):
        try:
            local_conn = sqlite3.connect(DB_PATH, timeout=30.0)
            cursor = local_conn.cursor()
            cursor.execute("INSERT INTO event_queue (channel, message) VALUES (?, ?)", (channel, message))
            local_conn.commit()
            local_conn.close()
        except Exception as e:
            print(f"[!] Event Error: {e}")

    # --- PASSIVE RECON ---

    def run_whois(self):
        print("[+] Running WHOIS lookup (Native)...")
        try:
            raw_text = simple_whois(self.target)
            c_date, e_date, registrar = parse_whois_dates(raw_text)
            
            if not self.connect_db(): return
            cursor = self.conn.cursor()
            
            cursor.execute("""
                INSERT INTO domain_info (target_id, registrar, creation_date, expiration_date, registrant_name, registrant_email)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (self.target_id, registrar, c_date, e_date, "Redacted (GDPR)", "Redacted"))
            self.conn.commit()
            self.close_db()
        except Exception as e:
            print(f"[!] WHOIS Error: {e}")

    def run_dns_enum(self):
        print(f"{Colors.INFO}[+] Running DNS Enumeration...{Colors.RESET}")
        record_types = ['A', 'NS', 'MX', 'TXT', 'SOA']
        
        def check_record(r_type):
            results = []
            try:
                answers = dns.resolver.resolve(self.target, r_type)
                for rdata in answers:
                    val = rdata.to_text()
                    TTL = answers.ttl
                    results.append((r_type, val, TTL))
            except Exception:
                pass
            return results

        all_records = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_type = {executor.submit(check_record, r): r for r in record_types}
            for future in concurrent.futures.as_completed(future_to_type):
                all_records.extend(future.result())

        if not self.connect_db(): return
        cursor = self.conn.cursor()
        for r_type, val, ttl in all_records:
            print(f"    - {r_type}: {val}")
            cursor.execute("INSERT INTO dns_records (target_id, record_type, value, ttl) VALUES (?, ?, ?, ?)",
                           (self.target_id, r_type, val, ttl))
        
        self.conn.commit()
        self.close_db()

    def run_ssl_analysis(self):
        module_name = "SSL Analysis"
        print(f"{Colors.INFO}[+] Running {module_name}...{Colors.RESET}")
        try:
            port = 443
            context = ssl.create_default_context()
            with socket.create_connection((self.target, port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bin)
                    
                    issuer = dict(x509.get_issuer().get_components())
                    subject = dict(x509.get_subject().get_components())
                    valid_from = x509.get_notBefore().decode()
                    valid_to = x509.get_notAfter().decode()
                    expired = x509.has_expired()
                    
                    # Convert bytes to string for storage
                    issuer_str = str(issuer)
                    subject_str = str(subject)

                    if not self.connect_db(): return
                    cursor = self.conn.cursor()
                    cursor.execute("""
                        INSERT INTO ssl_info (target_id, issuer, subject, valid_from, valid_to, has_expired)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (self.target_id, issuer_str, subject_str, valid_from, valid_to, expired))
                    self.conn.commit()
                    self.close_db()
        except Exception as e:
            print(f"[!] SSL Error: {e}")

    def run_subdomain_discovery(self):
        print("[+] Running Subdomain Discovery...")
        subdomains = set()
        
        # 1. Try Subfinder
        try:
            subprocess.run(["subfinder", "-version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            print("    - Mode: Subfinder")
            cmd = ["subfinder", "-d", self.target, "-silent"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if line.strip(): subdomains.add(line.strip())
        except (FileNotFoundError, subprocess.CalledProcessError):
            print("    - Mode: crt.sh (Passive Fallback)")
            # 2. Fallback to crt.sh
            try:
                url = f"https://crt.sh/?q=%25.{self.target}&output=json"
                res = requests.get(url, timeout=10)
                if res.status_code == 200:
                    data = res.json()
                    for entry in data:
                        name_value = entry['name_value']
                        for sub in name_value.split('\n'):
                            if "*" not in sub:
                                subdomains.add(sub.strip())
            except Exception as e:
                print(f"    [!] crt.sh failed: {e}")

        print(f"    - Found {len(subdomains)} subdomains")

        # Reuse subdomains logic
        if subdomains:
            # Resolve IPs for subdomains (Robust Logic)
            print("    - Resolving IPs for subdomains...")
            subdomain_ips = {}
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            
            for sub in subdomains:
                ip = "N/A"
                # 1. Try default resolver
                try:
                    answers = resolver.resolve(sub, 'A')
                    ip = answers[0].to_text()
                except:
                    # 2. Try Public DNS (Google)
                    try:
                        resolver.nameservers = ['8.8.8.8', '8.8.4.4']
                        answers = resolver.resolve(sub, 'A')
                        ip = answers[0].to_text()
                    except:
                        # 3. Fallback to system socket
                        try:
                            ip = socket.gethostbyname(sub)
                        except:
                            ip = "N/A"
                
                subdomain_ips[sub] = ip

            if self.connect_db():
                cursor = self.conn.cursor()
                for sub in subdomains:
                    ip = subdomain_ips.get(sub, "N/A")
                    cursor.execute("INSERT OR IGNORE INTO subdomains (target_id, subdomain, ip_address) VALUES (?, ?, ?)", (self.target_id, sub, ip))
                    # Update IP if it exists but was null (optional, but good for reruns)
                    cursor.execute("UPDATE subdomains SET ip_address = ? WHERE target_id = ? AND subdomain = ?", (ip, self.target_id, sub))
                self.conn.commit()
                self.close_db()
            
            # Publish batch events (limit to 20 to avoid spam)
            if self.connect_db():
                cursor = self.conn.cursor()
                count = 0
                for sub in subdomains:
                     cursor.execute("INSERT INTO event_queue (channel, message) VALUES (?, ?)", ("scan:subdomain_found", sub))
                     count += 1
                     if count > 20: break 
                self.conn.commit()
                self.close_db()

    def run_email_harvest(self):
        print("[+] Running Email Harvesting (TheHarvester-Lite)...")
        emails = set()
        
        # 1. Scrape Homepage
        try:
            requests.packages.urllib3.disable_warnings()
            res = requests.get(
                f"https://{self.target}", 
                timeout=10, 
                verify=False,
                headers=get_random_headers(self.target)
            )
            text = res.text
            # Basic Email Regex
            found = set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text))
            for email in found:
                if not email.endswith(('.png', '.jpg', '.jpeg', '.gif', '.js', '.css')):
                    emails.add(email)
        except Exception:
            pass
            
        if emails:
            print(f"    - Found {len(emails)} emails")
            if self.connect_db():
                cursor = self.conn.cursor()
                for email in emails:
                    print(f"      > {email}")
                    self.discovered_emails.append(email)  # Store for later use
                    cursor.execute("INSERT OR IGNORE INTO emails (target_id, email, source_url) VALUES (?, ?, ?)", 
                                   (self.target_id, email, f"https://{self.target}"))
                self.conn.commit()
                self.close_db()
        else:
            print("    - No emails found on public pages.")

    def run_smtp_analysis(self):
        print("[+] Running Email Server Analysis...")
        try:
            mx_records = dns.resolver.resolve(self.target, 'MX')
            for mx in mx_records:
                params = mx.to_text().split()
                server = params[1]
                
                # Banner grab port 25
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(3)
                    s.connect((server, 25))
                    banner = s.recv(1024).decode(errors='ignore').strip()
                    s.close()
                    print(f"    - MX: {server} -> {banner}")
                    
                    if self.connect_db():
                        cursor = self.conn.cursor()
                        cursor.execute("INSERT INTO findings (target_id, title, severity, description) VALUES (?, ?, ?, ?)",
                                       (self.target_id, f"SMTP Banner: {server}", "Info", f"Banner: {banner}"))
                        self.conn.commit()
                        self.close_db()
                except Exception:
                    pass
        except Exception:
            pass

    # --- ACTIVE RECON ---

    def run_ping(self):
        print("[+] Running Ping check...")
        param = '-n' if os.name == 'nt' else '-c'
        command = ['ping', param, '1', self.target]
        result = subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        status = "UP" if result == 0 else "DOWN"
        print(f"    - Status: {status}")

    def run_nmap(self):
        print("[+] Running Port Scan & Banner Grabbing...")
        nmap_available = False
        try:
            subprocess.run(["nmap", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            nmap_available = True
        except (FileNotFoundError, subprocess.CalledProcessError):
            nmap_available = False

        if nmap_available:
            try:
                print("    - Mode: Nmap (Active)")
                cmd = ["nmap", "-F", "-sV", self.target]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if self.connect_db():
                    cursor = self.conn.cursor()
                    for line in result.stdout.split('\n'):
                        if "/tcp" in line and "open" in line:
                            parts = line.split()
                            port = int(parts[0].split('/')[0])
                            service = parts[2] if len(parts) > 2 else "unknown"
                            version = " ".join(parts[3:]) if len(parts) > 3 else ""
                            cursor.execute("INSERT INTO ports (target_id, port, service, version, state) VALUES (?, ?, ?, ?, 'open')", 
                                           (self.target_id, port, service, version))
                    self.conn.commit()
                    self.close_db()
            except Exception as e:
                print(f"[!] Nmap Error: {e}")
        else:
            print("    - Mode: Native Socket Scan (Fallback with Banner Grabbing)")
            common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8000, 8080, 8443]
            open_ports = []
            
            def scan_port(port):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1.0) # Faster timeout
                    result = sock.connect_ex((self.target, port))
                    
                    banner = ""
                    if result == 0:
                        # Improved Banner Grab (Stealthier, WAF-aware)
                        try:
                            # Send legit HTTP request to avoid 400 Bad Request
                            # Using GET instead of HEAD as some servers block HEAD
                            if port in [80, 8080, 8000]:
                                req = f"GET / HTTP/1.1\r\nHost: {self.target}\r\nUser-Agent: {random.choice(USER_AGENTS)}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
                                sock.send(req.encode())
                            elif port in [443, 8443]:
                                # SSL Wrapping for HTTPS ports
                                context = ssl.create_default_context()
                                context.check_hostname = False
                                context.verify_mode = ssl.CERT_NONE
                                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                                     req = f"GET / HTTP/1.1\r\nHost: {self.target}\r\nUser-Agent: {random.choice(USER_AGENTS)}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
                                     ssock.send(req.encode())
                                     banner_data = ssock.recv(1024).decode('utf-8', errors='ignore').strip()
                                     banner = banner_data.split('\n')[0][:50] if banner_data else ""
                                     
                                     try:
                                         service = "https"
                                     except: service = "unknown"
                                     return (port, service, banner)
                            else:
                                # Generic banner grab for non-web
                                sock.send(b'Hello\r\n')
                                banner_data = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                                banner = banner_data.split('\n')[0][:50] if banner_data else ""

                            if not banner:
                                # Try standard HTTP receive
                                banner_data = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                                banner = banner_data.split('\n')[0][:50] if banner_data else ""

                        except:
                            pass
                        
                        try:
                            service = socket.getservbyport(port)
                        except:
                            service = "unknown"
                        sock.close()
                        return (port, service, banner)
                    sock.close()
                except:
                    pass
                return None

            max_threads = 50
            ports_to_scan = common_ports # Using common_ports for fallback
            print(f"{Colors.INFO}[+] Running Port Scan (Top {len(ports_to_scan)} ports)...{Colors.RESET}")
            print(f"    - Scanning {self.target} with {max_threads} threads...")
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = [executor.submit(scan_port, p) for p in common_ports]
                for future in concurrent.futures.as_completed(futures):
                    res = future.result()
                    if res:
                        open_ports.append(res)
                        banner_display = f" | Banner: {res[2]}" if res[2] else ""
                        print(f"{Colors.SUCCESS}    ✓ Found open port: {res[0]} ({res[1]}){Colors.RESET}")
                        if res[2]:
                            print(f"{Colors.INFO}      Banner: {res[2]}{Colors.RESET}")

            if not open_ports:
                print(f"{Colors.WARNING}    [-] No open ports found{Colors.RESET}")
            if open_ports and self.connect_db():
                cursor = self.conn.cursor()
                for p, s, b in open_ports:
                     cursor.execute("INSERT INTO ports (target_id, port, service, version, state) VALUES (?, ?, ?, ?, 'open')", 
                                    (self.target_id, p, s, b))
                self.conn.commit()
                self.close_db()

    def run_dirb_lite(self):
        print("[+] Running Directory Busting (Enhanced)...")
        wordlist = [
            'admin', 'login', 'dashboard', 'api', 'uploads', 'images', 'css', 'js', 'config', 'backup', 'db', 
            'wordpress', 'robots.txt', '.git', '.env', 'public', 'assets', 'static', 'media', 'files',
            'admin.php', 'login.php', 'config.php', 'wp-admin', 'wp-content', 'shell.php', 'backup.zip'
        ]
        protocol = "https://"
        found_dirs = []
        headers = get_random_headers(self.target)

        def check_url(path):
            url = f"{protocol}{self.target}/{path}"
            try:
                requests.packages.urllib3.disable_warnings()
                # Randomize user agent per request for better evasion
                req_headers = headers.copy()
                req_headers['User-Agent'] = random.choice(USER_AGENTS)
                
                res = requests.get(url, headers=req_headers, timeout=5, allow_redirects=False, verify=False)
                
                # Filter out Cloudflare generic blocks (often 403/503 but sometimes 200 captcha)
                if "Attention Required! | Cloudflare" in res.text:
                    return None
                    
                if res.status_code in [200, 301, 302, 401, 403, 500]:
                    print(f"    - Found: /{path} [{res.status_code}]")
                    return (f"/{path}", res.status_code)
            except Exception:
                pass
            return None

        # Increased threads for speed
        with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
            future_to_url = {executor.submit(check_url, path): path for path in wordlist}
            for future in concurrent.futures.as_completed(future_to_url):
                res = future.result()
                if res:
                    found_dirs.append(res)
        
        if found_dirs and self.connect_db():
            cursor = self.conn.cursor()
            for path, code in found_dirs:
                cursor.execute("INSERT INTO directories (target_id, path, status_code) VALUES (?, ?, ?)",
                               (self.target_id, path, code))
            self.conn.commit()
            self.close_db()

    def run_extended_web_recon(self):
        print("[+] Running Security Header & Robots Analysis...")
        try:
            requests.packages.urllib3.disable_warnings()
            res = requests.get(f"https://{self.target}", timeout=5, verify=False)
            
            headers = res.headers
            missing_headers = []
            
            if 'Strict-Transport-Security' not in headers: missing_headers.append('HSTS')
            if 'Content-Security-Policy' not in headers: missing_headers.append('CSP')
            if 'X-Frame-Options' not in headers: missing_headers.append('X-Frame-Options')
            
            if self.connect_db():
                cursor = self.conn.cursor()
                for mh in missing_headers:
                    cursor.execute("""
                        INSERT INTO findings (target_id, title, severity, description, url)
                        VALUES (?, ?, 'Low', ?, ?)
                    """, (self.target_id, f"Missing Header: {mh}", f"The site is missing the {mh} security header.", f"https://{self.target}"))
                self.conn.commit()
                self.close_db()
                if missing_headers:
                    print(f"    - Missing Headers: {', '.join(missing_headers)}")

            res_rob = requests.get(f"https://{self.target}/robots.txt", timeout=5, verify=False)
            if res_rob.status_code == 200:
                print("    - Robots.txt found")
                for line in res_rob.text.splitlines():
                    if "Disallow:" in line:
                        path = line.split(":", 1)[1].strip()
                        if self.connect_db():
                            cursor = self.conn.cursor()
                            cursor.execute("INSERT INTO directories (target_id, path, status_code) VALUES (?, ?, ?)",
                                          (self.target_id, f"{path} [ROBOTS]", 200))
                            self.conn.commit()
                            self.close_db()
        except Exception as e:
            print(f"    [!] Extended Recon failed: {e}")

    def run_tech_detect(self):
        print("[+] Detecting Technologies...")
        try:
            requests.packages.urllib3.disable_warnings()
            res = requests.get(
                f"https://{self.target}", 
                timeout=5, 
                verify=False,
                headers=get_random_headers(self.target)
            )
            headers = res.headers
            text = res.text.lower()
            
            detected = []
            
            if 'Server' in headers: detected.append((headers['Server'], 'Server'))
            if 'X-Powered-By' in headers: detected.append((headers['X-Powered-By'], 'Framework'))
            
            signatures = {
                'WordPress': 'wp-content',
                'Bootstrap': 'bootstrap.min.css',
                'JQuery': 'jquery.min.js',
                'React': 'react',
                'Cloudflare': 'cloudflare'
            }
            
            for name, sig in signatures.items():
                if sig in text:
                    detected.append((name, 'Frontend'))
            
            if detected:
                print(f"    - Found {len(detected)} technologies")
                if self.connect_db():
                    cursor = self.conn.cursor()
                    for name, cat in detected:
                        cursor.execute("INSERT INTO technologies (target_id, name, category) VALUES (?, ?, ?)", (self.target_id, name, cat))
                    self.conn.commit()
                    self.close_db()
        except Exception:
            pass

    def log_audit(self, action, module_name="", notes=""):
        """Log audit trail for ethical tracking"""
        if not config.AUDIT_LOGGING:
            return
        
        try:
            conn = sqlite3.connect(config.DB_PATH, timeout=30.0)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO audit_log (target_id, action, module_name, consent_given, notes)
                VALUES (?, ?, ?, ?, ?)
            """, (self.target_id, action, module_name, self.consent_given, notes))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[!] Audit logging error: {e}")
    
    def check_consent(self):
        """Display legal disclaimer and request consent"""
        if self.consent_given:
            print("[*] Consent flag provided, skipping consent check")
            return True
        
        if not config.REQUIRE_CONSENT:
            return True
        
        print("\n" + "="*70)
        print("LEGAL DISCLAIMER - ETHICAL OSINT FRAMEWORK")
        print("="*70)
        print("\nThis tool performs Open Source Intelligence gathering.")
        print("")
        print(f"\n{Colors.WARNING}⚠️  WARNING: Unauthorized scanning may be ILLEGAL in your jurisdiction.{Colors.RESET}")
        print("")
        print("You MUST have explicit authorization to scan this target.")
        print("By proceeding, you confirm that:")
        print("  1. You have permission to scan the target domain")
        print("  2. You will use findings ethically and legally")
        print("  3. You have read ETHICAL_GUIDELINES.md")
        print("")
        print(f"For full legal disclaimer, see: {Colors.BOLD}ETHICAL_GUIDELINES.md{Colors.RESET}")
        print("="*70)
        
        response = input(f"\n{Colors.INPUT}Do you have authorization to scan this target? (yes/no): {Colors.RESET}")
        
        if response.lower() in ['yes', 'y']:
            print(f"{Colors.SUCCESS}[✓] Consent granted. Proceeding with scan...{Colors.RESET}\n")
            return Colors.SUCCESS
        else:
            print(f"{Colors.ERROR}[!] Consent not granted. Exiting...{Colors.RESET}")
            return Colors.ERROR
    
    def should_run(self, module_type):
        """Check if module should run based on scan mode"""
        if self.scan_mode == 'full': return True
        if self.scan_mode == 'active':
            return module_type in ['active', 'search']
        if self.scan_mode == 'passive':
            return module_type == 'passive'
        if self.scan_mode == 'custom':
            return module_type in self.custom_modules
        return False

        return False

    def calculate_risk_score(self):
        """Calculate comprehensive risk score based on all findings"""
        print(f"{Colors.INFO}[*] Calculating comprehensive risk score...{Colors.RESET}")
        try:
            if not self.connect_db(): return
            cursor = self.conn.cursor()
            
            score = 0
            
            # 1. Findings (High/Critical weights)
            cursor.execute("SELECT severity FROM findings WHERE target_id=?", (self.target_id,))
            findings = cursor.fetchall()
            for (severity,) in findings:
                if severity == 'Critical': score += 20
                elif severity == 'High': score += 10
                elif severity == 'Medium': score += 5
                elif severity == 'Low': score += 1
            
            # 2. Open Ports (Critical ports)
            cursor.execute("SELECT port, service FROM ports WHERE target_id=?", (self.target_id,))
            ports = cursor.fetchall()
            critical_ports = [21, 22, 23, 25, 445, 3389]
            for port, service in ports:
                if port in critical_ports: score += 10
                else: score += 1
            
            # 3. Existing Threat Intel Score (Max)
            cursor.execute("SELECT risk_score FROM targets WHERE id=?", (self.target_id,))
            current_score = cursor.fetchone()[0] or 0
            
            final_score = min(max(score, current_score), 100)
            
            # Update DB
            cursor.execute("UPDATE targets SET risk_score = ? WHERE id = ?", (final_score, self.target_id))
            self.conn.commit()
            print(f"{Colors.SUCCESS}    ✓ Final Risk Score: {final_score}/100{Colors.RESET}")
            
            self.close_db()
        except Exception as e:
            print(f"{Colors.ERROR}    [!] Risk calculation failed: {e}{Colors.RESET}")

    def prompt_reporting(self):
        """Ask user to generate report"""
        print("\n" + "="*70)
        print("📝 REPORT GENERATION")
        print("="*70)
        print("1. HTML Report (Responsive, interactive)")
        print("2. PDF Report (Professional, printable)")
        print("3. Both")
        print("4. Skip")
        
        choice = input("\nEnter choice (1-4): ")
        
        reporter = ReportGenerator(self.target, self.target_id)
        
        if choice in ['1', '3']:
            print("[*] Generating HTML Report...")
            path = reporter.generate_html()
            print(f"    ✓ Saved to: {path}")
            
        if choice in ['2', '3']:
            print("[*] Generating PDF Report...")
            path = reporter.generate_pdf()
            if path:
                print(f"    ✓ Saved to: {path}")
            else:
                print("    [!] PDF generation failed (check logs)")

    def execute(self):
        print("\n" + "="*70)
        print("🛰️  AETHER-RECON v2.0 - Enhanced OSINT Framework")
        print("="*70)
        print(f"[*] Target: {self.target}")
        print(f"[*] Mode: {self.scan_mode.upper()}")
        
        # Display configuration status
        config.print_status()
        
        # Consent check
        if not self.check_consent():
            sys.exit(1)
        
        # Initialize target
        self.get_or_create_target()
        
        # Log scan start
        self.log_audit("scan_started", notes=f"Target: {self.target} | Mode: {self.scan_mode}")
        
        # --- PASSIVE PHASE ---
        if self.should_run('passive') or (self.scan_mode == 'custom' and 'passive' in self.custom_modules):
            print(Colors.HEADER)
            print("PHASE 1: PASSIVE RECONNAISSANCE")
            print("="*50 + Colors.RESET)
            
            # Enhanced WHOIS
            self.run_whois()
            self.log_audit("module_executed", "whois")
            
            # DNS Enumeration
            self.run_dns_enum()
            self.log_audit("module_executed", "dns_enum")
            
            # Geolocation Intelligence (NEW)
            if config.ENABLE_GEOLOCATION:
                geo = GeoIntelligence(self.target, self.target_id)
                geo.execute()
                self.target_ip = geo.get_target_ip()
                self.log_audit("module_executed", "geolocation")
            
            # SSL Analysis
            self.run_ssl_analysis()
            self.log_audit("module_executed", "ssl_analysis")
            
            # Subdomain Discovery
            self.run_subdomain_discovery()
            self.log_audit("module_executed", "subdomain_discovery")
            
            # Historical Intelligence (NEW)
            if config.ENABLE_HISTORICAL:
                historical = HistoricalIntelligence(self.target, self.target_id)
                historical.execute()
                self.log_audit("module_executed", "historical_intel")
            
            # Email Harvesting
            self.run_email_harvest()
            self.log_audit("module_executed", "email_harvest")
            
            # SMTP Analysis
            self.run_smtp_analysis()
            self.log_audit("module_executed", "smtp_analysis")
            
            # Social Media Intelligence (NEW)
            if config.ENABLE_SOCMINT and self.discovered_emails:
                socmint = SocialIntelligence(self.target, self.target_id, self.discovered_emails)
                socmint.execute()
                self.log_audit("module_executed", "socmint")
            
            # Breach Intelligence (NEW)
            if config.ENABLE_BREACH_INTEL and self.discovered_emails:
                breach = BreachIntelligence(self.target, self.target_id, self.discovered_emails)
                breach.execute()
                self.log_audit("module_executed", "breach_intel")
            
            # Threat Intelligence (NEW)
            if config.ENABLE_THREAT_INTEL:
                # Ensure IP is resolved for Shodan
                if not self.target_ip:
                     try:
                        self.target_ip = socket.gethostbyname(self.target)
                        print(f"    - Resolved IP for Threat Intel: {self.target_ip}")
                     except:
                        pass
                
                threat = ThreatIntelligence(self.target, self.target_id, self.target_ip)
                threat.execute()
                self.log_audit("module_executed", "threat_intel")
        
        # --- ACTIVE PHASE ---
        if self.should_run('active') or (self.scan_mode == 'custom' and 'active' in self.custom_modules):
            print(Colors.HEADER)
            print("PHASE 2: ACTIVE RECONNAISSANCE")
            print("="*50 + Colors.RESET)
            
            # Ping Check
            self.run_ping()
            
            # Port Scanning
            self.run_nmap()
            self.log_audit("module_executed", "port_scan")
            
            # Technology Detection
            self.run_tech_detect()
            self.log_audit("module_executed", "tech_detect")
            
            # Directory Enumeration
            self.run_dirb_lite()
            self.log_audit("module_executed", "directory_enum")
            
            # Security Headers
            self.run_extended_web_recon()
            self.log_audit("module_executed", "web_recon")
            
            # Metadata Extraction (NEW)
            if config.ENABLE_METADATA:
                metadata = MetadataExtractor(self.target, self.target_id)
                metadata.execute()
                self.log_audit("module_executed", "metadata_extraction")
        
        # --- SEARCH PHASE ---
        if self.should_run('search') or (self.scan_mode == 'custom' and 'search' in self.custom_modules):
            print(Colors.HEADER)
            print("PHASE 3: SEARCH INTELLIGENCE")
            print("="*50 + Colors.RESET)
            
            # Search Intelligence (NEW)
            if config.ENABLE_SEARCH_INTEL:
                search = SearchIntelligence(self.target, self.target_id)
                search.execute()
                self.log_audit("module_executed", "search_intel")
        
        # Log completion
        self.log_audit("scan_completed", notes=f"Target: {self.target}")
        
        # Notify
        self.publish_event("scan:complete", self.target)
        
        print(Colors.HEADER)
        print("✓ SCAN COMPLETED SUCCESSFULLY")
        print("="*50 + Colors.RESET)
        print(f"{Colors.INFO}Results saved to database: {config.DB_PATH}")
        print(f"{Colors.INFO}View dashboard at: http://localhost:5000")
        print("="*70)
        
        # Calculate Risk Score before reporting
        self.calculate_risk_score()
        
        # Prompt for reporting
        self.prompt_reporting()

def check_dependencies():
    """Verify that essential requirements are installed"""
    try:
        import requests
        import dns.resolver
        import OpenSSL
        import xhtml2pdf
        return True
    except ImportError as e:
        print(f"[!] Missing dependency: {e.name}")
        print("Please run: pip install -r ../reporter/requirements.txt")
        return False

def show_banner():
    banner = f"""{Colors.GREEN}
    ░█████╗░██████╗░░██████╗░██╗░░░██╗░██████╗
    ██╔══██╗██╔══██╗██╔════╝░██║░░░██║██╔════╝
    ███████║██████╔╝██║░░██╗░██║░░░██║╚█████╗░
    ██╔══██║██╔══██╗██║░░╚██╗██║░░░██║░╚═══██╗
    ██║░░██║██║░░██║╚██████╔╝╚██████╔╝██████╔╝
    ╚═╝░░╚═╝╚═╝░░╚═╝░╚═════╝░░╚═════╝░╚═════╝░
    
    Argus OSINT Framework | v2.0 | Ethical Intelligence{Colors.RESET}
    """
    print(banner)

def interactive_menu(target=None):
    if not target:
        target = input("Enter target domain (e.g., example.com): ").strip()
        if not target:
            print("[!] Target is required.")
            sys.exit(1)
            
    print("\n" + "="*50)
    print(f"🎯 TARGET: {target}")
    print("="*50)
    print("Select Scan Mode:")
    print("1. Active Scan (Intrusive: Ports, Directories, etc.)")
    print("2. Passive Scan (Stealth: WHOIS, DNS, OSINT)")
    print("3. Full Scan (Both Active & Passive + Search)")
    print("4. Custom Scan (Select specific modules)")
    
    choice = input("\nEnter choice (1-4): ")
    
    mode = 'full'
    custom_modules = []
    
    if choice == '1':
        mode = 'active'
    elif choice == '2':
        mode = 'passive'
    elif choice == '3':
        mode = 'full'
    elif choice == '4':
        mode = 'custom'
        print("\nSelect Modules:")
        if input("Run Passive Modules? (y/n): ").lower() == 'y': custom_modules.append('passive')
        if input("Run Active Modules? (y/n): ").lower() == 'y': custom_modules.append('active')
        if input("Run Search Intelligence? (y/n): ").lower() == 'y': custom_modules.append('search')
    
    return target, mode, custom_modules

if __name__ == "__main__":
    show_banner()
    
    if not check_dependencies():
        sys.exit(1)

    target = None
    consent_given = False
    
    # Check command line args
    if len(sys.argv) > 1:
        if sys.argv[1] not in ['--consent-given', '-h', '--help']:
            target = sys.argv[1]
        
        if '--consent-given' in sys.argv:
            consent_given = True
            
        # If target provided and no mode specified, default to full or ask?
        # If specific args were supported we'd check them here. 
        
    # Launch interactive menu if running directly
    try:
        if not target or (len(sys.argv) == 1):
             target, mode, custom_modules = interactive_menu(target)
        else:
            # Fallback for CLI automation with default full scan
            mode = 'full' 
            custom_modules = []
            
        engine = ReconEngine(target, consent_given=consent_given, scan_mode=mode, custom_modules=custom_modules)
        engine.execute()
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(0)
