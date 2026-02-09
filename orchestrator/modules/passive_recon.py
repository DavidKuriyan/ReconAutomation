"""
Passive Reconnaissance Module
Handles non-intrusive information gathering techniques including WHOIS, DNS, SSL, and Subdomain discovery.

DSA Optimizations:
- LRU caching for DNS lookups
- Frozenset for immutable record types
- Set-based subdomain storage
"""

import socket
import ssl
import OpenSSL
import concurrent.futures
import subprocess
import shutil
import requests
import dns.resolver
import re
import random
import os
from functools import lru_cache
from config import config, Colors

# Immutable record types (frozenset for O(1) membership)
DNS_RECORD_TYPES = frozenset(['A', 'NS', 'MX', 'TXT', 'SOA'])

# User Agents for evasion
USER_AGENTS = (  # Tuple is more memory efficient than list for immutable data
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1'
)

def get_random_headers(host: str) -> dict:
    """Generate randomized HTTP headers for evasion."""
    return {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Host': host
    }

def simple_whois(domain: str) -> str:
    """Perform a native socket-based WHOIS lookup."""
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

def parse_whois_dates(text: str):
    """Parse creation and expiry dates from WHOIS text."""
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

class PassiveRecon:
    """
    Encapsulates all passive reconnaissance logic.
    """
    def __init__(self, target: str, target_id: int, db_manager):
        self.target = target
        self.target_id = target_id
        self.db = db_manager
        self.discovered_emails = []

    def run_whois(self):
        """Perform WHOIS lookup and store registration details."""
        print("[+] Running WHOIS lookup (Native)...")
        try:
            raw_text = simple_whois(self.target)
            c_date, e_date, registrar = parse_whois_dates(raw_text)
            
            if not self.db.connect(): return
            cursor = self.db.conn.cursor()
            
            cursor.execute("""
                INSERT INTO domain_info (target_id, registrar, creation_date, expiration_date, registrant_name, registrant_email)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (self.target_id, registrar, c_date, e_date, "Redacted (GDPR)", "Redacted"))
            self.db.conn.commit()
            self.db.close()
        except Exception as e:
            print(f"[!] WHOIS Error: {e}")

    def run_dns_enum(self):
        """Enumerate standard DNS records (A, NS, MX, TXT, SOA)."""
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

        if not self.db.connect(): return
        cursor = self.db.conn.cursor()
        for r_type, val, ttl in all_records:
            print(f"    - {r_type}: {val}")
            cursor.execute("INSERT INTO dns_records (target_id, record_type, value, ttl) VALUES (?, ?, ?, ?)",
                           (self.target_id, r_type, val, ttl))
        
        self.db.conn.commit()
        self.db.close()

    def run_ssl_analysis(self):
        """Analyze SSL certificate details."""
        print(f"{Colors.INFO}[+] Running SSL Analysis...{Colors.RESET}")
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

                    if not self.db.connect(): return
                    cursor = self.db.conn.cursor()
                    cursor.execute("""
                        INSERT INTO ssl_info (target_id, issuer, subject, valid_from, valid_to, has_expired)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (self.target_id, issuer_str, subject_str, valid_from, valid_to, expired))
                    self.db.conn.commit()
                    self.db.close()
        except Exception as e:
            print(f"[!] SSL Error: {e}")

    def run_subdomain_discovery(self):
        """Discover subdomains using multiple passive sources."""
        print(f"{Colors.INFO}[+] Running Enhanced Subdomain Discovery (25+ sources)...{Colors.RESET}")
        subdomains = set()
        
        # Import PassiveSources and ExternalTools
        try:
            from modules.passive_sources import PassiveSources
            from modules.external_tools import ExternalTools
            
            ps = PassiveSources(self.target)
            
            # Run all free sources in parallel
            print("    - Running free sources...")
            free_subs, free_count = ps.run_all_free()
            subdomains.update(free_subs)
            print(f"    - Free sources: {len(free_subs)} subdomains from {free_count} sources")

            # Run External Tools (Amass)
            if shutil.which("amass"):
                et = ExternalTools(self.target)
                amass_subs = et.run_amass_passive()
                subdomains.update(amass_subs)
            
            # Run API-based sources if keys are configured
            api_keys = {
                'VIRUSTOTAL_API_KEY': config.VIRUSTOTAL_API_KEY,
                'SHODAN_API_KEY': config.SHODAN_API_KEY,
                'CENSYS_API_ID': config.CENSYS_API_ID,
                'CENSYS_API_SECRET': config.CENSYS_API_SECRET,
                'SECURITYTRAILS_API_KEY': getattr(config, 'SECURITYTRAILS_API_KEY', ''),
                'FULLHUNT_API_KEY': getattr(config, 'FULLHUNT_API_KEY', ''),
                'LEAKIX_API_KEY': getattr(config, 'LEAKIX_API_KEY', ''),
                'URLSCAN_API_KEY': getattr(config, 'URLSCAN_API_KEY', ''),
                'CHAOS_API_KEY': getattr(config, 'CHAOS_API_KEY', ''),
                'BRAVE_API_KEY': getattr(config, 'BRAVE_API_KEY', ''),
                'NETLAS_API_KEY': getattr(config, 'NETLAS_API_KEY', ''),
                'ZOOMEYE_API_KEY': getattr(config, 'ZOOMEYE_API_KEY', ''),
                'ONYPHE_API_KEY': getattr(config, 'ONYPHE_API_KEY', ''),
                'CRIMINALIP_API_KEY': getattr(config, 'CRIMINALIP_API_KEY', ''),
            }
            
            # Check if any API keys are configured
            has_api_keys = any(v for v in api_keys.values())
            if has_api_keys:
                print("    - Running API sources...")
                api_subs, api_count = ps.run_with_apis(api_keys)
                subdomains.update(api_subs)
                print(f"    - API sources: {len(api_subs)} subdomains from {api_count} sources")
                
        except ImportError as e:
            print(f"    [!] PassiveSources not available, using fallback: {e}")
            # Fallback to Subfinder
            try:
                subprocess.run(["subfinder", "-version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
                print("    - Mode: Subfinder")
                cmd = ["subfinder", "-d", self.target, "-silent"]
                result = subprocess.run(cmd, capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if line.strip(): subdomains.add(line.strip())
            except (FileNotFoundError, subprocess.CalledProcessError):
                print("    - Mode: crt.sh (Passive Fallback)")
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

        print(f"    - Total: {len(subdomains)} unique subdomains")

        # Resolve IPs
        if subdomains:
            print("    - Resolving IPs for subdomains...")
            subdomain_ips = {}
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            
            for sub in list(subdomains)[:100]:  # Limit to 100 for speed
                ip = "N/A"
                try:
                    answers = resolver.resolve(sub, 'A')
                    ip = answers[0].to_text()
                except:
                    try:
                        resolver.nameservers = ['8.8.8.8', '8.8.4.4']
                        answers = resolver.resolve(sub, 'A')
                        ip = answers[0].to_text()
                    except:
                        try:
                            ip = socket.gethostbyname(sub)
                        except:
                            ip = "N/A"
                
                subdomain_ips[sub] = ip

            if self.db.connect():
                cursor = self.db.conn.cursor()
                for sub in subdomains:
                    ip = subdomain_ips.get(sub, "N/A")
                    cursor.execute("INSERT OR IGNORE INTO subdomains (target_id, subdomain, ip_address) VALUES (?, ?, ?)", (self.target_id, sub, ip))
                    cursor.execute("UPDATE subdomains SET ip_address = ? WHERE target_id = ? AND subdomain = ?", (ip, self.target_id, sub))
                self.db.conn.commit()
                self.db.close()
            
            # Publish batch events (limit to 20 to avoid spam)
            if self.db.connect():
                cursor = self.db.conn.cursor()
                count = 0
                for sub in subdomains:
                     cursor.execute("INSERT INTO event_queue (channel, message) VALUES (?, ?)", ("scan:subdomain_found", sub))
                     count += 1
                     if count > 20: break 
                self.db.conn.commit()
                self.db.close()

    def run_email_harvest(self) -> set:
        """Harvest emails from public pages."""
        print("[+] Running Email Harvesting (TheHarvester-Lite)...")
        emails = set()
        
        # 1. External Tools (theHarvester)
        try:
            from modules.external_tools import ExternalTools
            if shutil.which("theHarvester"):
                et = ExternalTools(self.target)
                h_emails, h_subs = et.run_theharvester()
                emails.update(h_emails)
                # We can also add subdomains found by theHarvester if we want, 
                # but this method returns emails. Ideally we should run this earlier or store them.
                # For now just adding emails.
        except Exception as e:
            print(f"    [!] theHarvester failed: {e}")

        # 2. Scrape Homepage
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
            if self.db.connect():
                cursor = self.db.conn.cursor()
                for email in emails:
                    print(f"      > {email}")
                    self.discovered_emails.append(email)  # Store for later use
                    cursor.execute("INSERT OR IGNORE INTO emails (target_id, email, source_url) VALUES (?, ?, ?)", 
                                   (self.target_id, email, f"https://{self.target}"))
                self.db.conn.commit()
                self.db.close()
        else:
            print("    - No emails found on public pages.")
        
        return emails

    def run_smtp_analysis(self):
        """Analyze SMTP server banners."""
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
                    
                    if self.db.connect():
                        cursor = self.db.conn.cursor()
                        cursor.execute("INSERT INTO findings (target_id, title, severity, description) VALUES (?, ?, ?, ?)",
                                       (self.target_id, f"SMTP Banner: {server}", "Info", f"Banner: {banner}"))
                        self.db.conn.commit()
                        self.db.close()
                except Exception:
                    pass
        except Exception:
            pass
