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
from datetime import datetime
import time
from config import config, Colors
from utils import get_random_user_agent as _get_ua, get_random_headers

# Immutable record types (frozenset for O(1) membership)
DNS_RECORD_TYPES = frozenset(['A', 'NS', 'MX', 'TXT', 'SOA'])

def _get_whois_server(domain: str) -> str:
    """Determine the appropriate WHOIS server for a given domain TLD.
    Uses IANA WHOIS as the authority, with common TLD shortcuts for speed.
    Returns a list of servers in priority order for fallback support.
    """
    # Common TLD -> WHOIS server mapping with fallback alternatives
    # Format: primary | alternative1 | alternative2
    known_servers = {
        '.com': ['whois.verisign-grs.com'],
        '.net': ['whois.verisign-grs.com'],
        '.org': ['whois.pir.org'],
        '.in': ['whois.nixiregistry.in', 'whois.registry.in'],
        # Indian multi-part TLDs (subdomains of .in registry)
        # NOTE: whois.registry.in was deprecated, replaced by whois.nixiregistry.in
        '.ac.in': ['whois.nixiregistry.in', 'whois.registry.in'],
        '.co.in': ['whois.nixiregistry.in', 'whois.registry.in'],
        '.net.in': ['whois.nixiregistry.in', 'whois.registry.in'],
        '.org.in': ['whois.nixiregistry.in', 'whois.registry.in'],
        '.gen.in': ['whois.nixiregistry.in', 'whois.registry.in'],
        '.firm.in': ['whois.nixiregistry.in', 'whois.registry.in'],
        '.ind.in': ['whois.nixiregistry.in', 'whois.registry.in'],
        '.us': ['whois.nic.us'],
        '.io': ['whois.nic.io'],
        '.gov': ['whois.dotgov.gov'],
        '.edu': ['whois.educause.edu'],
        '.mil': ['whois.nic.mil'],
        '.int': ['whois.iana.int'],
        '.uk': ['whois.nic.uk'],
        '.de': ['whois.denic.de'],
        '.jp': ['whois.jprs.jp'],
        '.au': ['whois.auda.org.au'],
        '.ca': ['whois.cira.ca'],
        '.fr': ['whois.nic.fr'],
        '.br': ['whois.registro.br'],
        '.cn': ['whois.cnnic.cn'],
        '.ru': ['whois.tcinet.ru'],
        '.eu': ['whois.eu'],
        '.xyz': ['whois.nic.xyz'],
        '.top': ['whois.nic.top'],
    }
    
    # Extract TLD (handle multi-part TLDs like .ac.in, .co.uk)
    parts = domain.lower().split('.')
    if len(parts) >= 2:
        # Check multi-part TLDs first (e.g., .ac.in, .co.uk)
        if len(parts) >= 3:
            multi_tld = '.' + '.'.join(parts[-2:])
            if multi_tld in known_servers:
                return known_servers[multi_tld][0], known_servers[multi_tld][1:]
        # Check single TLD
        tld = '.' + parts[-1]
        if tld in known_servers:
            return known_servers[tld][0], known_servers[tld][1:]
    
    # Fallback: Query IANA WHOIS for unknown TLDs to find the authoritative server
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(8)
        s.connect(("whois.iana.org", 43))
        s.send(f"{domain}\r\n".encode())
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
        s.close()
        
        text = response.decode(errors='ignore')
        # Look for whois server reference in IANA response
        for line in text.splitlines():
            line = line.strip()
            if line.lower().startswith('whois:'):
                server = line.split(':', 1)[1].strip()
                if server:
                    return server, []
    except Exception:
        pass
    
    # Ultimate fallback: try Verisign (covers many TLDs, returns referral info)
    return 'whois.verisign-grs.com', []


def simple_whois(domain: str) -> str:
    """Perform a native socket-based WHOIS lookup with automatic server selection.
    Routes to the correct WHOIS server based on TLD, with multi-server fallback.
    """
    primary_server, alt_servers = _get_whois_server(domain)
    
    # Build server attempt list: primary -> referral follow -> alternatives -> ultimate fallback
    servers_to_try = [primary_server] + alt_servers
    
    last_error = None
    for whois_server in servers_to_try:
        try:
            # Resolve hostname first to catch DNS failures early
            try:
                socket.gethostbyname(whois_server)
            except socket.gaierror:
                last_error = f"DNS resolution failed for {whois_server}"
                continue
            
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((whois_server, 43))
            s.send(f"{domain}\r\n".encode())
            
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
            s.close()
            
            text = response.decode(errors='ignore')
            
            # Skip empty responses or "not found" responses
            if not text.strip() or "No Data Found" in text or "NOT FOUND" in text.upper() or "No match for" in text:
                # Try next server
                continue
            
            # Check if server returned a referral to a different WHOIS server
            if 'Whois Server:' in text or 'WHOIS Server:' in text or 'Registrar WHOIS Server:' in text:
                for line in text.splitlines():
                    line = line.strip()
                    if 'Whois Server:' in line or 'WHOIS Server:' in line or 'Registrar WHOIS Server:' in line:
                        referred_server = line.split(':', 1)[1].strip()
                        if referred_server and referred_server != whois_server and referred_server not in servers_to_try:
                            # Follow the referral
                            try:
                                socket.gethostbyname(referred_server)
                            except socket.gaierror:
                                continue
                            try:
                                s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                s2.settimeout(10)
                                s2.connect((referred_server, 43))
                                s2.send(f"{domain}\r\n".encode())
                                response2 = b""
                                while True:
                                    data = s2.recv(4096)
                                    if not data:
                                        break
                                    response2 += data
                                s2.close()
                                referred_text = response2.decode(errors='ignore')
                                if referred_text.strip():
                                    return referred_text
                            except Exception:
                                pass
                        break
            
            # If we got here, we have a non-empty response
            if text.strip():
                return text
                
        except Exception as e:
            last_error = str(e)
            continue
    
    return f"WHOIS Lookup Failed: {last_error or 'All WHOIS servers unreachable'}"

def parse_whois_dates(text: str):
    """Parse creation and expiry dates from WHOIS text using flexible regex matching.
    Handles multiple formats across different registries (.com, .in, .org, etc.).
    Enhanced patterns for .IN registry format (whois.registry.in).
    """
    created = ""
    expires = ""
    registrar = ""
    registrant_name = ""
    registrant_email = ""
    
    # Flexible regex patterns for creation dates
    # .IN registry format: "Created On:15-Jan-2002 16:59:29 UTC"
    created_patterns = [
        r'(?i)(?:creation\s*date|created\s*(?:on|date)?|registered\s*(?:on|date)?|domain\s*created|created\s*on|created)\s*[:=]\s*(.+)$',
        r'(?i)^Created\s*On\s*[:=]\s*(.+)$',
    ]
    
    # Flexible regex patterns for expiration dates
    # .IN registry format: "Expiration Date:31-Jan-2021 16:59:29 UTC"
    expires_patterns = [
        r'(?i)(?:registry\s*expiry\s*date|expiration\s*date|expires\s*(?:on|date)?|expiry\s*date|valid\s*until|paid\s*until|renewal\s*date|expires|expiry)\s*[:=]\s*(.+)$',
        r'(?i)^Expiration\s*Date\s*[:=]\s*(.+)$',
    ]
    
    # Flexible regex patterns for registrar
    # .IN registry format: "Registrar Name:abc"
    # IMPORTANT: Order matters - more specific patterns first
    registrar_patterns = [
        # Exact match for "Registrar: Name" (most common) - must NOT match "Registrar URL", "Registrar IANA ID", "Registrar WHOIS Server"
        r'(?i)^Registrar\s*[:=]\s*(.+)$',
        # Match "Sponsoring Registrar: Name"
        r'(?i)^Sponsoring\s+Registrar\s*[:=]\s*(.+)$',
        # Match "Registrar Name: Name"
        r'(?i)^Registrar\s+Name\s*[:=]\s*(.+)$',
    ]
    
    # Flexible regex patterns for registrant name
    # .IN registry format: "Registrant Contact Name:xyz"
    registrant_name_patterns = [
        r'(?i)(?:registrant\s*(?:name|organization|org)|owner\s*(?:name|organization|org)|org\s*name|organisation\s*name|registrant\s*contact\s*name)\s*[:=]\s*(.+)$',
    ]
    
    # Flexible regex patterns for registrant email
    registrant_email_patterns = [
        r'(?i)(?:registrant\s*email|owner\s*email|contact\s*email|email|registrant\s*contact\s*email)\s*[:=]\s*(.+)$',
    ]
    
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        lower = line.lower()
        
        # Skip lines with redacted/not disclosed info
        is_redacted = any(x in lower for x in ['redacted', 'not disclosed', 'data not shown', 'private'])
        
        # Match creation dates
        if not created:
            for pattern in created_patterns:
                m = re.search(pattern, line)
                if m:
                    val = m.group(1).strip().strip('.').strip()
                    if val and val != 'N/A' and not is_redacted:
                        created = val
                        break
        
        # Match expiration dates
        if not expires:
            for pattern in expires_patterns:
                m = re.search(pattern, line)
                if m:
                    val = m.group(1).strip().strip('.').strip()
                    if val and val != 'N/A' and not is_redacted:
                        expires = val
                        break
        
        # Match registrar (skip registrant/registration/registry URL/Registrar IANA/Registrar WHOIS)
        if not registrar:
            if not any(x in lower for x in ['registrant', 'registration', 'registry url', 'registrar url', 'registrar iana', 'registrar whois', 'whois server', 'registrar registration']):
                for pattern in registrar_patterns:
                    m = re.search(pattern, line)
                    if m:
                        val = m.group(1).strip().strip('.').strip()
                        if val and val != 'N/A' and not is_redacted:
                            registrar = val
                            break
        
        # Match registrant name
        if not registrant_name:
            for pattern in registrant_name_patterns:
                m = re.search(pattern, line)
                if m:
                    val = m.group(1).strip().strip('.').strip()
                    if val and val != 'N/A' and not is_redacted and len(val) > 2:
                        registrant_name = val
                        break
        
        # Match registrant email
        if not registrant_email:
            for pattern in registrant_email_patterns:
                m = re.search(pattern, line)
                if m:
                    val = m.group(1).strip().strip('.').strip()
                    if val and '@' in val and not is_redacted:
                        registrant_email = val
                        break
    
    return created, expires, registrar, registrant_name, registrant_email

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
        """Perform WHOIS lookup and store registration details.
        Uses native socket WHOIS first, then WhoisXML API as backfill if key is configured.
        Includes retry logic for transient network failures.
        """
        print("[+] Running WHOIS lookup (Native)...")
        c_date = e_date = registrar = r_name = r_email = ""
        
        # Retry native WHOIS up to 2 times if it returns empty critical fields
        for attempt in range(2):
            try:
                raw_text = simple_whois(self.target)
                if raw_text.startswith("WHOIS Lookup Failed:"):
                    if attempt == 0:
                        print(f"    [!] {raw_text} (retrying...)")
                        time.sleep(1)
                        continue
                    else:
                        print(f"    [!] {raw_text}")
                else:
                    c_date, e_date, registrar, r_name, r_email = parse_whois_dates(raw_text)
                    # If critical fields are empty, retry once
                    if not c_date and not e_date and not registrar:
                        if attempt == 0:
                            print("    [!] WHOIS returned empty fields, retrying...")
                            time.sleep(1)
                            continue
                    break
            except Exception as e:
                if attempt == 0:
                    print(f"    [!] Native WHOIS error: {e} (retrying...)")
                    time.sleep(1)
                else:
                    print(f"    [!] Native WHOIS error: {e}")
        
        # Backfill with WhoisXML API if native lookup returned empty fields and key is configured
        if config.WHOISXML_API_KEY and (not c_date or not e_date or not registrar):
            print("    [+] Backfilling with WhoisXML API...")
            try:
                url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
                params = {
                    'apiKey': config.WHOISXML_API_KEY,
                    'domainName': self.target,
                    'outputFormat': 'JSON'
                }
                res = requests.get(url, params=params, timeout=15)
                if res.status_code == 200:
                    data = res.json()
                    whois_data = data.get('WhoisRecord', {}) or data.get('whoisRecord', {})
                    
                    if whois_data:
                        if not c_date:
                            c_date = whois_data.get('createdDate', '') or \
                                     whois_data.get('createdDateNormalized', '') or c_date
                        if not e_date:
                            e_date = whois_data.get('expiresDate', '') or \
                                     whois_data.get('expiresDateNormalized', '') or e_date
                        if not registrar:
                            registrar = whois_data.get('registrarName', '') or \
                                        whois_data.get('registrar', {}).get('name', '') or registrar
                        if not r_name:
                            r_name = whois_data.get('registrant', {}).get('name', '') or r_name
                        if not r_email:
                            r_email = whois_data.get('registrant', {}).get('emailAddress', '') or \
                                      whois_data.get('contactEmail', '') or r_email
                        
                        print(f"    ✓ WhoisXML API backfill: registrar={registrar}, created={c_date}")
            except Exception as e:
                print(f"    [!] WhoisXML API backfill error: {e}")
        
        # Display results
        print(f"    - Registrar: {registrar or 'N/A'}")
        print(f"    - Created: {c_date or 'N/A'}")
        print(f"    - Expires: {e_date or 'N/A'}")
        print(f"    - Registrant: {r_name or 'Redacted (GDPR)'}")
        print(f"    - Email: {r_email or 'Redacted'}")
        
        # Save to database
        try:
            if not self.db.connect(): return
            cursor = self.db.conn.cursor()
            cursor.execute("""
                INSERT INTO domain_info (target_id, registrar, creation_date, expiration_date, registrant_name, registrant_email)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (self.target_id, registrar, c_date, e_date, r_name or "Redacted (GDPR)", r_email or "Redacted"))
            self.db.conn.commit()
            self.db.close()
        except Exception as e:
            print(f"    [!] DB save error: {e}")

    def run_rir_whois(self):
        """Route WHOIS query to the correct Regional Internet Registry."""
        print("[+] Running RIR-based WHOIS lookup...")
        rir_servers = {
            'arin': 'whois.arin.net',
            'ripe': 'whois.ripe.net',
            'apnic': 'whois.apnic.net',
            'afrinic': 'whois.afrinic.net',
            'lacnic': 'whois.lacnic.net',
        }
        
        # Try to resolve IP first to determine RIR
        try:
            ip = socket.gethostbyname(self.target)
            first_octet = int(ip.split('.')[0])
            
            # Rough IP-to-RIR mapping (more accurate would use IANA data)
            if first_octet < 50:
                preferred = 'arin'
            elif first_octet < 90:
                preferred = 'arin'
            elif first_octet < 130:
                preferred = 'ripe'
            elif first_octet < 200:
                preferred = 'apnic'
            else:
                preferred = 'lacnic'
                
            # Query the preferred RIR
            rir_list = [preferred] + [r for r in rir_servers if r != preferred]
            
            for rir_name in rir_list[:3]:
                server = rir_servers[rir_name]
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(8)
                    s.connect((server, 43))
                    s.send(f"{self.target}\r\n".encode())
                    
                    response = b""
                    while True:
                        data = s.recv(4096)
                        if not data: break
                        response += data
                    s.close()
                    
                    text = response.decode(errors='ignore')
                    if text and "NOT FOUND" not in text.upper() and "No match" not in text:
                        print(f"    - RIR: {rir_name.upper()} ({server})")
                        c, e, r, rn, re = parse_whois_dates(text)
                        print(f"    - Registrar: {r}, Created: {c}")
                        
                        if self.db.connect():
                            try:
                                cursor = self.db.conn.cursor()
                                cursor.execute("""UPDATE domain_info SET registrar=?, creation_date=?, expiration_date=?,
                                    registrant_name=?, registrant_email=?
                                    WHERE target_id=?""", (r, c, e, rn or "Redacted (GDPR)", re or "Redacted", self.target_id))
                                self.db.conn.commit()
                            except: pass
                            finally: self.db.close()
                        return
                except:
                    continue
        except:
            pass
        print("    - RIR lookup not available")

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

    def run_dnsbl_check(self):
        """Check IP reputation via DNS-based Blackhole Lists (DNSBL)."""
        print("[+] Running DNSBL / Blacklist Reputation Check...")
        try:
            ip = socket.gethostbyname(self.target)
            reversed_ip = '.'.join(reversed(ip.split('.')))
            
            # Common DNSBLs (free, DNS-based queries)
            dnsbls = [
                ('Spamhaus', 'zen.spamhaus.org'),
                ('SpamCop', 'bl.spamcop.net'),
                ('Barracuda', 'b.barracudacentral.org'),
                ('Sorbs', 'dnsbl.sorbs.net'),
                ('AHBL', 'dnsbl.ahbl.org'),
                ('NJABL', 'dnsbl.njabl.org'),
                ('CBL', 'cbl.abuseat.org'),
                ('URIBL', 'multi.uribl.com'),
            ]
            
            listed_on = []
            for name, dnsbl in dnsbls:
                try:
                    query = f"{reversed_ip}.{dnsbl}"
                    answers = socket.gethostbyname_ex(query)
                    if answers:
                        listed_on.append(name)
                        print(f"      ⚠ Listed on {name} ({dnsbl})")
                except socket.gaierror:
                    pass  # Not listed
                except Exception:
                    pass
            
            if listed_on:
                print(f"    - Blacklisted on {len(listed_on)} DNSBL(s): {', '.join(listed_on)}")
                self._db_save_finding(f"IP Blacklisted: {', '.join(listed_on)}", "High",
                    f"Target IP {ip} listed on DNSBLs: {', '.join(listed_on)}")
                
                if self.db.connect():
                    try:
                        cursor = self.db.conn.cursor()
                        cursor.execute("""INSERT INTO ip_reputation 
                            (target_id, ip_address, blacklisted, blacklist_sources)
                            VALUES (?, ?, 1, ?)""",
                            (self.target_id, ip, ', '.join(listed_on)))
                        self.db.conn.commit()
                    except: pass
                    finally: self.db.close()
            else:
                print(f"    - IP {ip} is not blacklisted on major DNSBLs")
                
                if self.db.connect():
                    try:
                        cursor = self.db.conn.cursor()
                        cursor.execute("""INSERT INTO ip_reputation 
                            (target_id, ip_address, blacklisted, blacklist_sources)
                            VALUES (?, ?, 0, 'Clean on all tested DNSBLs')""",
                            (self.target_id, ip))
                        self.db.conn.commit()
                    except: pass
                    finally: self.db.close()
                    
        except Exception as e:
            print(f"    [!] DNSBL check failed: {e}")

    def run_abuseipdb_check(self):
        """Check IP reputation via AbuseIPDB API (if key configured)."""
        if not config.ABUSEIPDB_API_KEY:
            print("[!] AbuseIPDB API key not configured, skipping")
            return
            
        print("[+] Checking AbuseIPDB reputation...")
        try:
            ip = socket.gethostbyname(self.target)
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                'Key': config.ABUSEIPDB_API_KEY,
                'Accept': 'application/json'
            }
            params = {'ipAddress': ip, 'maxAgeInDays': '90'}
            
            res = requests.get(url, headers=headers, params=params, timeout=10)
            if res.status_code == 200:
                data = res.json().get('data', {})
                abuse_score = data.get('abuseConfidenceScore', 0)
                total_reports = data.get('totalReports', 0)
                isp = data.get('isp', '')
                usage = data.get('usageType', '')
                
                print(f"    - Abuse Score: {abuse_score}/100")
                print(f"    - Reports: {total_reports}")
                print(f"    - ISP: {isp}")
                
                if abuse_score > 50:
                    self._db_save_finding(f"AbuseIPDB: High Abuse Score ({abuse_score})", "High",
                        f"IP {ip} has {total_reports} abuse reports, score: {abuse_score}, ISP: {isp}")
                
                if self.db.connect():
                    try:
                        cursor = self.db.conn.cursor()
                        cursor.execute("""UPDATE ip_reputation SET 
                            abuse_reports=?, threat_score=?, isp=?, usage_type=?
                            WHERE target_id=? AND ip_address=?""",
                            (total_reports, abuse_score, isp, usage, self.target_id, ip))
                        self.db.conn.commit()
                    except: pass
                    finally: self.db.close()
        except Exception as e:
            print(f"    [!] AbuseIPDB check failed: {e}")

    def run_bgp_analysis(self):
        """Query BGP information via public sources."""
        print("[+] Running BGP Route Analysis...")
        try:
            ip = socket.gethostbyname(self.target)
            
            # Use ipapi.co for ASN info (free, no key required)
            url = f"https://ipapi.co/{ip}/json/"
            res = requests.get(url, timeout=10)
            if res.status_code == 200:
                data = res.json()
                asn = data.get('asn', '')
                asn_org = data.get('org', '')
                country = data.get('country_name', '')
                
                if asn:
                    asn_num = asn.replace('AS', '')
                    print(f"    - ASN: {asn} ({asn_org})")
                    print(f"    - Country: {country}")
                    
                    # Get BGP route info from HackerTarget (free)
                    try:
                        bgp_url = f"https://api.hackertarget.com/aslookup/?q={asn_num}"
                        bgp_res = requests.get(bgp_url, timeout=10)
                        if bgp_res.status_code == 200:
                            print(f"    - BGP Routes (prefixes):")
                            routes = bgp_res.text.strip().split('\n')[:10]
                            for route in routes:
                                print(f"      {route}")
                            
                            if self.db.connect():
                                try:
                                    cursor = self.db.conn.cursor()
                                    cursor.execute("""INSERT INTO bgp_info
                                        (target_id, ip_address, asn, asn_name, asn_country, asn_routes)
                                        VALUES (?, ?, ?, ?, ?, ?)""",
                                        (self.target_id, ip, int(asn_num), asn_org, country, '\n'.join(routes)))
                                    self.db.conn.commit()
                                except: pass
                                finally: self.db.close()
                    except:
                        pass
                
        except Exception as e:
            print(f"    [!] BGP analysis failed: {e}")

    def run_whoisxml_history(self):
        """Query historical WHOIS via WhoisXML API (if key configured)."""
        if not config.WHOISXML_API_KEY:
            print("    [!] WhoisXML API key not configured - using free fallback source")
            return
        
        print("[+] Querying WhoisXML Historical WHOIS Database...")
        try:
            url = "https://whois-history.whoisxmlapi.com/api/v1"
            params = {
                'apiKey': config.WHOISXML_API_KEY,
                'domainName': self.target
            }
            res = requests.get(url, params=params, timeout=15)
            if res.status_code == 200:
                data = res.json()
                records = data.get('result', {}).get('records', []) or data.get('records', [])
                if records:
                    print(f"    - Found {len(records)} historical WHOIS records")
                    for i, rec in enumerate(records[:5]):
                        created = rec.get('createdDateNormalized', 'N/A')
                        registrar = rec.get('registrarName', 'N/A')
                        registrant = rec.get('registrantName', 'N/A') or rec.get('ownerName', 'N/A')
                        email = rec.get('registrantEmail', 'N/A') or rec.get('contactEmail', 'N/A')
                        print(f"    - [{i+1}] Created: {created}, Registrar: {registrar}")
                        
                        if self.db.connect():
                            try:
                                cursor = self.db.conn.cursor()
                                cursor.execute("""INSERT INTO whois_history
                                    (target_id, domain, snapshot_date, registrar, registrant_name, registrant_email, source)
                                    VALUES (?, ?, ?, ?, ?, ?, 'whoisxmlapi')""",
                                    (self.target_id, self.target, created, registrar, registrant, email))
                                self.db.conn.commit()
                            except: pass
                            finally: self.db.close()
                else:
                    print("    - No historical records found via WhoisXML")
        except Exception as e:
            print(f"    [!] WhoisXML Historical API error: {e}")

    def run_reverse_whois(self):
        """Reverse WHOIS lookup via WhoisXML API (if key configured).
        Finds other domains registered by the same registrant/email."""
        if not config.WHOISXML_API_KEY:
            print("    [!] WhoisXML API key not configured for reverse WHOIS")
            return
        
        print("[+] Running Reverse WHOIS Lookup...")
        try:
            # First try to get registrant email from domain WHOIS
            email = ""
            registrant = ""
            if self.db.connect():
                try:
                    cursor = self.db.conn.cursor()
                    cursor.execute("SELECT registrant_email, registrant_name FROM domain_info WHERE target_id=?", (self.target_id,))
                    row = cursor.fetchone()
                    if row:
                        email = row[0] or ''
                        registrant = row[1] or ''
                        if 'Redacted' in email:
                            email = ''
                        if 'Redacted' in registrant:
                            registrant = ''
                except: pass
                finally: self.db.close()
            
            search_terms = []
            if email and '@' in email:
                search_terms.append(('email', email))
            if registrant:
                search_terms.append(('registrant', registrant))
            
            if not search_terms:
                print("    - No registrant data available for reverse lookup")
                return
            
            url = "https://reverse-whois.whoisxmlapi.com/api/v2"
            for term_type, term in search_terms[:1]:  # Use first available term
                try:
                    payload = {
                        'apiKey': config.WHOISXML_API_KEY,
                        'searchType': 'current',
                        'mode': 'purchase',
                        'basicSearchTerms': {
                            'term': term,
                            'exclude': False
                        }
                    }
                    res = requests.post(url, json=payload, timeout=15)
                    if res.status_code == 200:
                        data = res.json()
                        domains = data.get('result', {}).get('domainsList', []) or data.get('domainsList', [])
                        if domains:
                            print(f"    - Found {len(domains)} related domains via {term_type}: '{term[:30]}...'")
                            for d in domains[:10]:
                                domain_name = d.get('domainName', d) if isinstance(d, dict) else d
                                print(f"      > {domain_name}")
                                # Save as subdomain-like finding
                                self._db_save_finding(
                                    f"Related Domain ({term_type}): {domain_name}",
                                    "Info",
                                    f"Domain {domain_name} shares registrar contact with {self.target}"
                                )
                        else:
                            print(f"    - No related domains found for {term_type}")
                except Exception as e:
                    print(f"    [!] Reverse WHOIS API error for {term_type}: {e}")
        except Exception as e:
            print(f"    [!] Reverse WHOIS error: {e}")

    def run_historical_whois(self):
        """Query historical WHOIS data from public sources."""
        print("[+] Running Historical WHOIS Lookup...")
        # First try WhoisXML API (if key configured)
        self.run_whoisxml_history()
        
        # Fallback: Try WHOIS history via whois.domaintools.com (free, limited)
        registrar = ""
        registrant = ""
        snap_date = ""
        try:
            url = f"https://whois.domaintools.com/{self.target}"
            headers = {'User-Agent': _get_ua()}
            res = requests.get(url, headers=headers, timeout=10)
            
            if res.status_code == 200:
                text = res.text
                # Extract registrar
                reg_match = re.search(r'Registrar[^<]*<[^>]*>([^<]+)', text, re.IGNORECASE)
                if reg_match:
                    registrar = reg_match.group(1).strip()
                    print(f"    - Registrar: {registrar}")
                
                # Extract creation date
                date_patterns = [
                    r'Creation Date[^<]*<[^>]*>([^<]+)',
                    r'Created on[^:]*:[\s]*([^<]+)',
                    r'Registered[\s]*on[^:]*:[\s]*([^<]+)',
                    r'>Created[^<]*<[^>]*>([^<]+)'
                ]
                for pattern in date_patterns:
                    match = re.search(pattern, text, re.IGNORECASE)
                    if match:
                        snap_date = match.group(1).strip()
                        print(f"    - Historical data: Created {snap_date}")
                        break
        except Exception as e:
            print(f"    [!] Historical WHOIS error: {e}")
        
        # Only save record if we have meaningful data or it's a new entry
        if snap_date or registrar:
            if self.db.connect():
                try:
                    cursor = self.db.conn.cursor()
                    cursor.execute("""INSERT INTO whois_history
                        (target_id, domain, snapshot_date, registrar, registrant_name, source)
                        VALUES (?, ?, ?, ?, ?, 'whois.domaintools.com')""",
                        (self.target_id, self.target, snap_date or datetime.now().strftime('%Y-%m-%d'),
                         registrar or '', registrant or ''))
                    self.db.conn.commit()
                    print(f"    - Saved historical WHOIS record")
                except: pass
                finally: self.db.close()
        else:
            print(f"    - No historical WHOIS data available for {self.target}")

    def run_search_engine_ip(self):
        """Search search engines for IP references."""
        print("[+] Checking search engines for IP references...")
        try:
            ip = socket.gethostbyname(self.target)
            
            # DuckDuckGo search for IP (no API key needed)
            search_urls = [
                f"https://html.duckduckgo.com/html/?q=%22{ip}%22+security+threat",
                f"https://html.duckduckgo.com/html/?q=%22{ip}%22+malware+report",
                f"https://html.duckduckgo.com/html/?q=%22{ip}%22+hacker+incident",
            ]
            
            for search_url in search_urls:
                try:
                    res = requests.get(search_url, 
                        headers={'User-Agent': _get_ua()},
                        timeout=8)
                    if res.status_code == 200 and 'did not match' not in res.text:
                        # Extract result snippets
                        snippets = re.findall(r'class="result__snippet"[^>]*>(.*?)</a>', res.text, re.DOTALL)[:3]
                        if snippets:
                            print(f"    - Results found for: {search_url.split('q=')[1][:60]}...")
                            for s in snippets:
                                clean = re.sub(r'<[^>]+>', '', s).strip()
                                print(f"      > {clean[:120]}...") if len(clean) > 120 else print(f"      > {clean}")
                            break
                except:
                    pass
        except Exception as e:
            print(f"    [!] Search engine check failed: {e}")

    def _db_save_finding(self, title, severity, description):
        """Helper: save a finding."""
        if self.db.connect():
            try:
                cursor = self.db.conn.cursor()
                cursor.execute("""INSERT INTO findings (target_id, title, severity, description, url)
                    VALUES (?, ?, ?, ?, ?)""",
                    (self.target_id, title, severity, description, f"https://{self.target}"))
                self.db.conn.commit()
            except:
                pass
            finally:
                self.db.close()

    # =========================================================================
    # IP-SPECIFIC WRAPPER METHODS (called by orchestrator for IP targets)
    # These methods take an IP argument directly instead of resolving from self.target
    # =========================================================================

    def run_dnsbl_check_with_ip(self, ip):
        """DNSBL check using a pre-resolved IP address (for IP targets)."""
        print("[+] Running DNSBL / Blacklist Reputation Check (IP target)...")
        try:
            reversed_ip = '.'.join(reversed(ip.split('.')))
            
            dnsbls = [
                ('Spamhaus', 'zen.spamhaus.org'),
                ('SpamCop', 'bl.spamcop.net'),
                ('Barracuda', 'b.barracudacentral.org'),
                ('Sorbs', 'dnsbl.sorbs.net'),
                ('AHBL', 'dnsbl.ahbl.org'),
                ('NJABL', 'dnsbl.njabl.org'),
                ('CBL', 'cbl.abuseat.org'),
                ('URIBL', 'multi.uribl.com'),
            ]
            
            listed_on = []
            for name, dnsbl in dnsbls:
                try:
                    query = f"{reversed_ip}.{dnsbl}"
                    answers = socket.gethostbyname_ex(query)
                    if answers:
                        listed_on.append(name)
                        print(f"      ⚠ Listed on {name} ({dnsbl})")
                except socket.gaierror:
                    pass
                except Exception:
                    pass
            
            if listed_on:
                print(f"    - Blacklisted on {len(listed_on)} DNSBL(s): {', '.join(listed_on)}")
                self._db_save_finding(f"IP Blacklisted: {', '.join(listed_on)}", "High",
                    f"Target IP {ip} listed on DNSBLs: {', '.join(listed_on)}")
                
                if self.db.connect():
                    try:
                        cursor = self.db.conn.cursor()
                        cursor.execute("""INSERT INTO ip_reputation 
                            (target_id, ip_address, blacklisted, blacklist_sources)
                            VALUES (?, ?, 1, ?)""",
                            (self.target_id, ip, ', '.join(listed_on)))
                        self.db.conn.commit()
                    except: pass
                    finally: self.db.close()
            else:
                print(f"    - IP {ip} is not blacklisted on major DNSBLs")
                if self.db.connect():
                    try:
                        cursor = self.db.conn.cursor()
                        cursor.execute("""INSERT INTO ip_reputation 
                            (target_id, ip_address, blacklisted, blacklist_sources)
                            VALUES (?, ?, 0, 'Clean on all tested DNSBLs')""",
                            (self.target_id, ip))
                        self.db.conn.commit()
                    except: pass
                    finally: self.db.close()
        except Exception as e:
            print(f"    [!] DNSBL check failed: {e}")

    def run_bgp_analysis_with_ip(self, ip):
        """BGP/ASN analysis using a pre-resolved IP address."""
        print("[+] Running BGP Route Analysis (IP target)...")
        try:
            # Use ipapi.co for ASN info
            url = f"https://ipapi.co/{ip}/json/"
            res = requests.get(url, timeout=10)
            if res.status_code == 200:
                data = res.json()
                asn = data.get('asn', '')
                asn_org = data.get('org', '')
                country = data.get('country_name', '')
                
                if asn:
                    asn_num = asn.replace('AS', '')
                    print(f"    - ASN: {asn} ({asn_org})")
                    print(f"    - Country: {country}")
                    
                    try:
                        bgp_url = f"https://api.hackertarget.com/aslookup/?q={asn_num}"
                        bgp_res = requests.get(bgp_url, timeout=10)
                        if bgp_res.status_code == 200:
                            print(f"    - BGP Routes (prefixes):")
                            routes = bgp_res.text.strip().split('\n')[:10]
                            for route in routes:
                                print(f"      {route}")
                            
                            if self.db.connect():
                                try:
                                    cursor = self.db.conn.cursor()
                                    cursor.execute("""INSERT INTO bgp_info
                                        (target_id, ip_address, asn, asn_name, asn_country, asn_routes)
                                        VALUES (?, ?, ?, ?, ?, ?)""",
                                        (self.target_id, ip, int(asn_num), asn_org, country, '\n'.join(routes)))
                                    self.db.conn.commit()
                                except: pass
                                finally: self.db.close()
                    except:
                        pass
        except Exception as e:
            print(f"    [!] BGP analysis failed: {e}")

    def run_search_engine_ip_with_ip(self, ip):
        """Search search engines for IP references (using pre-resolved IP)."""
        print("[+] Checking search engines for IP references (IP target)...")
        try:
            search_urls = [
                f"https://html.duckduckgo.com/html/?q=%22{ip}%22+security+threat",
                f"https://html.duckduckgo.com/html/?q=%22{ip}%22+malware+report",
                f"https://html.duckduckgo.com/html/?q=%22{ip}%22+hacker+incident",
            ]
            
            for search_url in search_urls:
                try:
                    res = requests.get(search_url, 
                        headers={'User-Agent': _get_ua()},
                        timeout=8)
                    if res.status_code == 200 and 'did not match' not in res.text:
                        snippets = re.findall(r'class="result__snippet"[^>]*>(.*?)</a>', res.text, re.DOTALL)[:3]
                        if snippets:
                            print(f"    - Results found for: {search_url.split('q=')[1][:60]}...")
                            for s in snippets:
                                clean = re.sub(r'<[^>]+>', '', s).strip()
                                print(f"      > {clean[:120]}...") if len(clean) > 120 else print(f"      > {clean}")
                            break
                except:
                    pass
        except Exception as e:
            print(f"    [!] Search engine check failed: {e}")

    def run_abuseipdb_check_with_ip(self, ip):
        """Check IP reputation via AbuseIPDB API using a pre-resolved IP."""
        if not config.ABUSEIPDB_API_KEY:
            print("[!] AbuseIPDB API key not configured, skipping")
            return
        
        print("[+] Checking AbuseIPDB reputation (IP target)...")
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                'Key': config.ABUSEIPDB_API_KEY,
                'Accept': 'application/json'
            }
            params = {'ipAddress': ip, 'maxAgeInDays': '90'}
            
            res = requests.get(url, headers=headers, params=params, timeout=10)
            if res.status_code == 200:
                data = res.json().get('data', {})
                abuse_score = data.get('abuseConfidenceScore', 0)
                total_reports = data.get('totalReports', 0)
                isp = data.get('isp', '')
                usage = data.get('usageType', '')
                
                print(f"    - Abuse Score: {abuse_score}/100")
                print(f"    - Reports: {total_reports}")
                print(f"    - ISP: {isp}")
                
                if abuse_score > 50:
                    self._db_save_finding(f"AbuseIPDB: High Abuse Score ({abuse_score})", "High",
                        f"IP {ip} has {total_reports} abuse reports, score: {abuse_score}, ISP: {isp}")
                
                if self.db.connect():
                    try:
                        cursor = self.db.conn.cursor()
                        cursor.execute("""UPDATE ip_reputation SET 
                            abuse_reports=?, threat_score=?, isp=?, usage_type=?
                            WHERE target_id=? AND ip_address=?""",
                            (total_reports, abuse_score, isp, usage, self.target_id, ip))
                        self.db.conn.commit()
                    except: pass
                    finally: self.db.close()
        except Exception as e:
            print(f"    [!] AbuseIPDB check failed: {e}")

    def run_certificate_transparency_with_ip(self, ip):
        """Check certificate transparency logs for certificates issued to this IP."""
        print("[+] Checking Certificate Transparency logs for IP...")
        try:
            # crt.sh supports IP search: https://crt.sh/?q=ip.address
            url = f"https://crt.sh/?q={ip}&output=json"
            res = requests.get(url, timeout=15, headers={'User-Agent': _get_ua()})
            
            if res.status_code == 200:
                data = res.json()
                if data and len(data) > 0:
                    cert_count = len(data)
                    print(f"    - Found {cert_count} certificates issued for this IP")
                    
                    # Collect unique domains/subdomains
                    domains = set()
                    for entry in data[:50]:  # Limit to first 50
                        name = entry.get('name_value', '')
                        for sub in name.split('\n'):
                            if sub and '*' not in sub:
                                domains.add(sub.strip())
                    
                    if domains:
                        print(f"    - Associated domains ({len(domains)}):")
                        for domain in list(domains)[:15]:
                            print(f"      > {domain}")
                        
                        # Store findings
                        self._db_save_finding(
                            f"Certificates Found for IP", "Info",
                            f"IP {ip} has {cert_count} certificates across {len(domains)} domains"
                        )
                else:
                    print(f"    - No certificates found for this IP")
            else:
                print(f"    - crt.sh returned status {res.status_code}")
        except Exception as e:
            print(f"    [!] Certificate Transparency check failed: {e}")
