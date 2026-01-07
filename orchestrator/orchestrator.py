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
from urllib.parse import urlparse

# Configuration
DB_PATH = "../reporter/aether.db"

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
    def __init__(self, target):
        self.target = target
        self.target_id = None
        self.conn = None

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
        print("[+] Running DNS Enumeration (Fast)...")
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
        print("[+] Running SSL Analysis...")
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
            if self.connect_db():
                cursor = self.conn.cursor()
                for sub in subdomains:
                    cursor.execute("INSERT OR IGNORE INTO subdomains (target_id, subdomain) VALUES (?, ?)", (self.target_id, sub))
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
            res = requests.get(f"https://{self.target}", timeout=10, verify=False)
            text = res.text
            # Basic Email Regex
            found = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
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
                    sock.settimeout(2.0)
                    result = sock.connect_ex((self.target, port))
                    
                    banner = ""
                    if result == 0:
                        # Banner Grab
                        try:
                            sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
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

            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                futures = [executor.submit(scan_port, p) for p in common_ports]
                for future in concurrent.futures.as_completed(futures):
                    res = future.result()
                    if res:
                        open_ports.append(res)
                        banner_display = f" | Banner: {res[2]}" if res[2] else ""
                        print(f"    - Open: {res[0]} ({res[1]}){banner_display}")

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
        headers = {'User-Agent': 'Aether-Recon/1.0'}

        def check_url(path):
            url = f"{protocol}{self.target}/{path}"
            try:
                requests.packages.urllib3.disable_warnings()
                res = requests.get(url, headers=headers, timeout=3, allow_redirects=False, verify=False)
                if res.status_code in [200, 301, 302, 401, 403, 500]:
                    print(f"    - Found: /{path} [{res.status_code}]")
                    return (f"/{path}", res.status_code)
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
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
            res = requests.get(f"https://{self.target}", timeout=5, verify=False)
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

    def execute(self):
        print(f"[*] Starting Aether-Recon on {self.target}")
        self.get_or_create_target()
        
        # Passive Phase
        self.run_whois()
        self.run_dns_enum()
        self.run_ssl_analysis()
        self.run_subdomain_discovery()
        self.run_email_harvest()     # NEW
        self.run_smtp_analysis()     # NEW
        
        # Active Phase
        self.run_ping()
        self.run_nmap() # Includes Socket Fallback & Banner Grab
        self.run_tech_detect()
        self.run_dirb_lite()
        self.run_extended_web_recon() # NEW
        
        # Notify
        self.publish_event("scan:complete", self.target)
        print("[*] Scan Completed.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python orchestrator.py <domain>")
        sys.exit(1)
    
    engine = ReconEngine(sys.argv[1])
    engine.execute()
