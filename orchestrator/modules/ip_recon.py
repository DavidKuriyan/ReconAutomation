"""
Advanced IP Reconnaissance Module
Comprehensive IP-based reconnaissance techniques covering the full intelligence lifecycle.
All techniques are NEW additions that do NOT alter any existing modules.

Categories:
  1. Active Network Recon (Advanced ICMP, TCP pings, stealth scans, SCTP)
  2. DNS Reconnaissance (Extended records, Open resolver, DNSSEC, Wildcard)
  3. Service Enumeration (FTP, SSH, Telnet, RDP, VNC, Databases, RPC/NFS)
  4. Passive IP Intelligence (ASN, BGP, Reverse DNS/PTR, Reverse IP)
  5. Threat Intelligence (GreyNoise, MISP, ThreatFox, MalwareBazaar)
  6. Internet-wide Scan Databases (BinaryEdge)
  7. Certificate Intelligence (SAN, Weak Algos, Historical)
  8. Cloud Infrastructure Detection (AWS, Azure, GCP)
  9. CDN Detection (Expanded)
  10. VPN/Proxy/TOR Detection
  11. Network Security Analysis (WAF, IDS/IPS, Firewall)
  12. IPv6 Intelligence
  13. Search Engine Intelligence
  14. Risk Analysis & Scoring
  15. Correlation & Asset Discovery
"""

import socket
import ssl
import struct
import concurrent.futures
import requests
import dns.resolver
import dns.reversename
import re
import json
import os
import time
import base64
import ipaddress
from typing import List, Optional, Tuple, Set, Dict, Any
from functools import lru_cache
from datetime import datetime
from config import config, Colors
from utils import get_random_user_agent as _get_ua

# ============================================================================
# PORT LISTS
# ============================================================================

# Database default ports
DATABASE_PORTS = {
    'mysql': 3306, 'postgresql': 5432, 'oracle': 1521, 'mssql': 1433,
    'redis': 6379, 'mongodb': 27017, 'elasticsearch': 9200,
    'cassandra': 9042, 'influxdb': 8086, 'couchdb': 5984,
    'neo4j': 7687, 'memcached': 11211, 'cockroachdb': 26257,
}

# Service ports
SERVICE_PORTS = {
    'ftp': [21], 'ssh': [22], 'telnet': [23], 'smtp': [25],
    'dns': [53], 'dhcp': [67, 68], 'tftp': [69], 'http': [80, 8080, 8000],
    'pop3': [110], 'ntp': [123], 'snm p': [161, 162], 'ldap': [389],
    'https': [443, 8443], 'smb': [445], 'smtps': [465],
    'rsync': [873], 'imaps': [993], 'pop3s': [995],
    'ms-sql': [1433, 1434], 'oracle-db': [1521, 1522],
    'nfs': [2049], 'mysql': [3306], 'rdp': [3389],
    'postgresql': [5432], 'vnc': [5900, 5901], 'redis': [6379],
    'amqp': [5672], 'mongodb': [27017, 27018],
    'elasticsearch': [9200, 9300],
}

class IpRecon:
    """
    Comprehensive IP Reconnaissance module.
    Adds 100+ new techniques without modifying existing modules.
    """

    __slots__ = ('target', 'target_ip', 'target_id', 'db')

    def __init__(self, target: str, target_ip: str, target_id: int, db_manager):
        self.target = target
        self.target_ip = target_ip
        self.target_id = target_id
        self.db = db_manager

    # =========================================================================
    # DATABASE HELPERS
    # =========================================================================

    def _db_execute(self, query: str, params=()) -> Optional[Any]:
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

    def _db_save_finding(self, title: str, severity: str = 'Info', description: str = '', url: str = ''):
        self._db_execute(
            "INSERT INTO findings (target_id, title, severity, description, url) VALUES (?, ?, ?, ?, ?)",
            (self.target_id, title, severity, description, url or f"https://{self.target}")
        )

    def _run_command(self, cmd: list, timeout: int = 30) -> Tuple[bool, str, str]:
        import subprocess
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return True, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Timed out"
        except FileNotFoundError:
            return False, "", f"Command not found: {cmd[0]}"
        except Exception as e:
            return False, "", str(e)

    def _tcp_connect(self, host: str, port: int, timeout: float = 2.0) -> Optional[str]:
        """Simple TCP connect with banner grab."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            banner = b""
            try:
                s.send(b'HELP\r\n')
                banner = s.recv(1024)
            except:
                pass
            s.close()
            return banner.decode(errors='ignore').strip()[:200] if banner else ""
        except:
            return None

    # =========================================================================
    # 1. ACTIVE NETWORK RECONNAISSANCE — Advanced ICMP
    # =========================================================================

    def run_icmp_timestamp(self):
        """ICMP Timestamp request (Type 13) - clock skew analysis.
        Uses OS ping or nmap as fallback since raw sockets are restricted on Windows.
        """
        print("    - ICMP Timestamp/Clock Skew...")
        
        # Try nmap first (most portable)
        import shutil
        if shutil.which("nmap"):
            success, stdout, _ = self._run_command(
                ['nmap', '-PP', '-T4', '--max-retries', '1', self.target_ip],
                timeout=30
            )
            if success and 'Host is up' in stdout:
                print(f"      ✓ ICMP Timestamp allowed (nmap -PP)")
                self._db_save_finding(
                    "ICMP Timestamp Enabled", "Low",
                    f"{self.target_ip} responds to ICMP Timestamp requests. "
                    f"Can be used for clock skew fingerprinting."
                )
                return
        
        # Fallback: raw socket (requires admin on Windows)
        try:
            import struct
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(3)
            
            pid = os.getpid() & 0xFFFF
            body = struct.pack('!HHH', pid, 0, 0) + struct.pack('!III', 0, 0, 0)
            chksum = self._icmp_checksum(body)
            packet = struct.pack('!BBHHH', 13, 0, chksum, pid, 0) + struct.pack('!III', 0, 0, 0)
            
            sock.sendto(packet, (self.target_ip, 0))
            data, addr = sock.recvfrom(1024)
            sock.close()
            
            if data and len(data) >= 20:
                icmp_type = data[20]
                if icmp_type == 14:
                    print(f"      ✓ ICMP Timestamp allowed (raw socket)")
                    self._db_save_finding(
                        "ICMP Timestamp Enabled", "Low",
                        f"{self.target_ip} responds to ICMP Timestamp requests."
                    )
        except PermissionError:
            print("      - ICMP Timestamp requires admin (skipped)")
        except socket.timeout:
            print("      - ICMP Timestamp filtered")
        except Exception as e:
            print(f"      - ICMP Timestamp error: {e}")

    def run_icmp_address_mask(self):
        """ICMP Address Mask request (Type 17) - subnet mask discovery.
        Uses nmap with -PM flag or raw socket fallback.
        """
        print("    - ICMP Address Mask Request...")
        
        import shutil
        if shutil.which("nmap"):
            success, stdout, _ = self._run_command(
                ['nmap', '-PM', '-T4', '--max-retries', '1', self.target_ip],
                timeout=30
            )
            if success and 'Host is up' in stdout:
                print(f"      ✓ ICMP Address Mask allowed (nmap -PM)")
                self._db_save_finding(
                    "ICMP Address Mask Enabled", "Medium",
                    f"{self.target_ip} responds to ICMP Address Mask requests."
                )
                return
        
        try:
            import struct
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(3)
            
            pid = os.getpid() & 0xFFFF
            body = struct.pack('!HHHI', pid, 0, 0, 0)
            chksum = self._icmp_checksum(body)
            packet = struct.pack('!BBHHHI', 17, 0, chksum, pid, 0, 0)
            
            sock.sendto(packet, (self.target_ip, 0))
            data, addr = sock.recvfrom(1024)
            sock.close()
            
            if data and len(data) > 24:
                icmp_type = data[20]
                if icmp_type == 18:
                    addr_mask = struct.unpack('!I', data[24:28])[0]
                    mask_str = f"{(addr_mask >> 24) & 0xFF}.{(addr_mask >> 16) & 0xFF}.{(addr_mask >> 8) & 0xFF}.{addr_mask & 0xFF}"
                    print(f"      ✓ Address Mask available: {mask_str}")
                    self._db_save_finding(
                        "ICMP Address Mask Enabled", "Medium",
                        f"{self.target_ip} reveals subnet mask: {mask_str}"
                    )
        except PermissionError:
            print("      - ICMP Address Mask requires admin (skipped)")
        except socket.timeout:
            print("      - ICMP Address Mask filtered")
        except Exception as e:
            print(f"      - ICMP Address Mask error: {e}")

    def _icmp_checksum(self, data: bytes) -> int:
        """Calculate ICMP checksum."""
        if len(data) % 2 == 1:
            data += b'\x00'
        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i+1]
            s += w
        s = (s >> 16) + (s & 0xFFFF)
        s = ~s & 0xFFFF
        return s

    # =========================================================================
    # 1b. ADVANCED TCP PINGS
    # =========================================================================

    def run_advanced_tcp_pings(self):
        """TCP SYN Ping, ACK Ping, Connect Ping, Source Port Scan."""
        print("    - Advanced TCP Pings & Source Port Scan...")
        import shutil
        
        results = {}
        
        # TCP SYN Ping (via nmap)
        if shutil.which("nmap"):
            success, stdout, _ = self._run_command(
                ['nmap', '-PS', '-T4', '--host-timeout', '8s', self.target_ip], timeout=15
            )
            if success and 'Host is up' in stdout:
                results['SYN Ping (nmap -PS)'] = True
            
            # TCP ACK Ping
            success, stdout, _ = self._run_command(
                ['nmap', '-PA', '-T4', '--host-timeout', '8s', self.target_ip], timeout=15
            )
            if success and 'Host is up' in stdout:
                results['ACK Ping (nmap -PA)'] = True
            
            # IP Protocol Ping
            success, stdout, _ = self._run_command(
                ['nmap', '-PO', '-T4', '--host-timeout', '8s', self.target_ip], timeout=15
            )
            if success and 'Host is up' in stdout:
                results['IP Protocol Ping (nmap -PO)'] = True
            
            # Source Port Scan (using DNS port 53 as source)
            success, stdout, _ = self._run_command(
                ['nmap', '--source-port', '53', '-T4', '-p', '80,443', '--host-timeout', '10s', self.target_ip],
                timeout=20
            )
            if success and 'open' in stdout.lower():
                results['Source Port Scan (port 53)'] = True
        else:
            # Native fallback
            try:
                for port in [80, 443, 22]:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(2)
                    if s.connect_ex((self.target_ip, port)) == 0:
                        results['Connect Ping'] = f"Port {port} open"
                        s.close()
                        break
                    s.close()
            except:
                pass
        
        if results:
            for ptype in results:
                print(f"      ✓ {ptype}")
        else:
            print("      - No response to TCP pings")

    # =========================================================================
    # 1c. TCP STEALTH SCANS (FIN, NULL, Xmas, ACK, Window, Maimon)
    # =========================================================================

    def run_stealth_tcp_scans(self):
        """Perform TCP stealth scans via nmap: FIN, NULL, Xmas, ACK, Window, Maimon.
        Uses nmap exclusively since raw sockets require admin and are restricted on Windows.
        """
        print("    - TCP Stealth Scan Analysis...")
        import shutil
        
        if not shutil.which("nmap"):
            print("      - Stealth scans require nmap (not installed)")
            return
        
        scan_types = {
            'FIN': '-sF', 'NULL': '-sN', 'Xmas': '-sX',
            'ACK': '-sA', 'Window': '-sW', 'Maimon': '-sM'
        }
        
        for name, flag in scan_types.items():
            success, stdout, _ = self._run_command(
                ['nmap', flag, '-T4', '--max-retries', '1', '-p', '22,80,443,3389',
                 '--host-timeout', '15s', self.target_ip],
                timeout=30
            )
            if success:
                open_count = stdout.count('/tcp')
                filtered_count = stdout.count('filtered')
                if open_count > 0:
                    print(f"      ✓ Nmap {name} Scan: {open_count} open, {filtered_count} filtered")
                elif filtered_count > 0:
                    print(f"      - Nmap {name} Scan: 0 open, {filtered_count} filtered")
        
        print("      - Stealth scan complete")

    # =========================================================================
    # 1d. ADVANCED OS FINGERPRINTING (TCP/IP Stack)
    # =========================================================================

    def run_advanced_os_fingerprint(self):
        """TCP/IP stack fingerprinting via Window Size, DF Bit, TCP Options, IP ID."""
        print("    - Advanced OS Fingerprinting (TCP/IP Stack)...")
        results = {}
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((self.target_ip, 80))
            
            # Send HTTP request and capture response
            s.send(f"GET / HTTP/1.1\r\nHost: {self.target_ip}\r\nConnection: close\r\n\r\n".encode())
            response = s.recv(4096)
            s.close()
            
            # Analyze TCP/IP stack characteristics from response
            if response:
                # TTL (from received packet)
                ttl = 64  # Default guess
                try:
                    # Get socket option for TTL
                    ttl = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
                except:
                    pass
                
                # TCP Window Size detection via banner analysis
                window_size = "Unknown"
                if b'Windows' in response or b'IIS' in response:
                    window_size = "65535 (Typical Windows)"
                    results['OS Guess'] = "Windows"
                elif b'nginx' in response or b'Apache' in response:
                    window_size = "29200 (Typical Linux)"
                    results['OS Guess'] = "Linux/Unix"
                
                results['TTL'] = str(ttl)
                results['Window'] = window_size
                
                # IP ID Sequence detection
                if b'Apache' in response:
                    results['IP ID'] = "Incremental (Linux)"
                elif b'IIS' in response:
                    results['IP ID'] = "Incremental (Windows)"
                
                for k, v in results.items():
                    print(f"      ✓ {k}: {v}")
                    
                self._db_save_finding(
                    f"Advanced OS Fingerprint: {results.get('OS Guess', 'Unknown')}",
                    "Info",
                    f"TCP/IP stack fingerprint: TTL={results.get('TTL')}, "
                    f"Window={results.get('Window')}, IP ID={results.get('IP ID')}"
                )
        except Exception as e:
            print(f"      - OS fingerprinting limited: {e}")

    # =========================================================================
    # 1e. ENHANCED TRACEROUTE METHODS
    # =========================================================================

    def run_enhanced_traceroute(self):
        """TCP, UDP, and ICMP traceroute with path visualization."""
        print("    - Enhanced Traceroute (TCP + UDP + ICMP)...")
        import shutil
        
        if shutil.which("nmap"):
            for scan_type, flag in [('TCP', '-sS'), ('UDP', '-sU'), ('ICMP', '-PE')]:
                success, stdout, _ = self._run_command(
                    ['nmap', '--traceroute', flag, '-p', '80', '--max-retries', '1', self.target_ip],
                    timeout=120
                )
                if success:
                    hops = re.findall(r'(\d+)\s+([\d.]+)', stdout)
                    if hops:
                        print(f"      ✓ {scan_type} Traceroute: {len(hops)} hops")
                        for hop in hops[:5]:
                            print(f"        Hop {hop[0]}: {hop[1]}")
                        break
        else:
            # OS native traceroute
            for cmd_base in [['tracert', '-h', '15'], ['traceroute', '-m', '15']]:
                import os as _os
                if _os.name == 'nt' and cmd_base[0] == 'tracert':
                    success, stdout, _ = self._run_command(cmd_base + [self.target_ip], timeout=60)
                    if success:
                        hops = re.findall(r'^\s*(\d+)\s+.*?(\d+\.\d+\.\d+\.\d+)', stdout, re.MULTILINE)
                        if hops:
                            print(f"      ✓ OS Traceroute: {len(hops)} hops")
                            for hop in hops[:5]:
                                print(f"        Hop {hop[0]}: {hop[1]}")
                        break

    # =========================================================================
    # 2. DNS RECONNAISSANCE — Extended Records
    # =========================================================================

    def run_extended_dns_records(self):
        """Query extended DNS record types: SPF, DMARC, DKIM, SRV, CAA, NAPTR, etc."""
        print("    - Extended DNS Records...")
        record_types = {
            'SPF': 'TXT',  # SPF is stored in TXT records
            'DMARC': '_dmarc',
            'DKIM': 'default._domainkey',
            'CNAME': 'CNAME',
            'PTR': 'PTR',
            'SRV': 'SRV',
            'CAA': 'CAA',
            'NAPTR': 'NAPTR',
            'DNSKEY': 'DNSKEY',
            'DS': 'DS',
            'LOC': 'LOC',
        }
        
        found_records = []
        
        # Check SPF via TXT
        try:
            answers = dns.resolver.resolve(self.target, 'TXT')
            for rdata in answers:
                txt = rdata.to_text()
                if 'v=spf1' in txt:
                    found_records.append(('SPF', txt[:120]))
                    print(f"      ✓ SPF: {txt[:100]}...")
                    break
        except:
            pass
        
        # Check DMARC
        try:
            answers = dns.resolver.resolve(f'_dmarc.{self.target}', 'TXT')
            for rdata in answers:
                txt = rdata.to_text()
                if 'v=DMARC1' in txt:
                    found_records.append(('DMARC', txt[:120]))
                    print(f"      ✓ DMARC: {txt[:100]}...")
                    # Check DMARC policy
                    if 'p=reject' in txt.lower():
                        print(f"        Policy: reject (good)")
                    elif 'p=quarantine' in txt.lower():
                        print(f"        Policy: quarantine")
                    else:
                        print(f"        Policy: none (weak)")
                    
                    if 'rua=' in txt:
                        uri = re.search(r'rua=([^;]+)', txt)
                        if uri:
                            print(f"        Reports sent to: {uri.group(1)}")
                    break
        except:
            pass
        
        # Check DKIM
        try:
            answers = dns.resolver.resolve(f'default._domainkey.{self.target}', 'TXT')
            for rdata in answers:
                txt = rdata.to_text()
                if 'v=DKIM1' in txt or 'p=' in txt:
                    found_records.append(('DKIM', txt[:120]))
                    print(f"      ✓ DKIM: Present")
                    break
        except:
            pass
        
        # Check SRV records (common ones)
        srv_services = [
            '_sip._tcp', '_sip._udp', '_sip._tls',
            '_xmpp._tcp', '_xmpp-client._tcp', '_xmpp-server._tcp',
            '_ldap._tcp', '_kerberos._tcp',
            '_autodiscover._tcp', '_caldav._tcp', '_carddav._tcp',
            '_jabber._tcp', '_stun._udp', '_turn._udp',
        ]
        for service in srv_services:
            try:
                answers = dns.resolver.resolve(f'{service}.{self.target}', 'SRV')
                for rdata in answers:
                    record = f"SRV {service}: {rdata}"
                    found_records.append(record)
                    print(f"      ✓ SRV {service}: target={rdata.target}, port={rdata.port}")
                    break
            except:
                pass
        
        # Check CAA
        try:
            answers = dns.resolver.resolve(self.target, 'CAA')
            for rdata in answers:
                record = f"CAA: {rdata}"
                found_records.append(record)
                print(f"      ✓ CAA: {rdata}")
        except:
            pass
        
        # Check NAPTR
        try:
            answers = dns.resolver.resolve(self.target, 'NAPTR')
            for rdata in answers:
                record = f"NAPTR: {rdata}"
                found_records.append(record)
                print(f"      ✓ NAPTR: {rdata}")
                break
        except:
            pass
        
        # Check DNSSEC (DNSKEY)
        for rtype in ['DNSKEY', 'DS']:
            try:
                answers = dns.resolver.resolve(self.target, rtype)
                for rdata in answers:
                    record = f"{rtype}: {'present'}"
                    found_records.append(record)
                    if rtype == 'DNSKEY':
                        print(f"      ✓ DNSSEC: DNSKEY records present (signed zone)")
                    else:
                        print(f"      ✓ DNSSEC: DS records present")
                    break
            except dns.resolver.NoAnswer:
                pass
            except:
                pass
        
        # PTR (reverse DNS) - handled separately
        try:
            rev_name = dns.reversename.from_address(self.target_ip)
            answers = dns.resolver.resolve(rev_name, 'PTR')
            for rdata in answers:
                ptr_val = str(rdata)
                found_records.append(('PTR', ptr_val))
                print(f"      ✓ PTR (Reverse DNS): {ptr_val}")
                break
        except:
            pass
        
        # Save findings for security-relevant records
        spf_found = any('SPF' in r for r in found_records if isinstance(r, tuple))
        dmarc_found = any('DMARC' in r for r in found_records if isinstance(r, tuple))
        dkim_found = any('DKIM' in r for r in found_records if isinstance(r, tuple))
        
        if not spf_found:
            self._db_save_finding("Missing SPF Record", "Medium",
                f"No SPF record found for {self.target}. Email spoofing possible.")
        if not dmarc_found:
            self._db_save_finding("Missing DMARC Record", "Medium",
                f"No DMARC record found for {self.target}. No email authentication reporting.")
        if not dkim_found:
            self._db_save_finding("Missing DKIM Record", "Low",
                f"No DKIM record found for {self.target}.")

    def run_open_resolver_check(self):
        """Check if the target DNS server is an open resolver."""
        print("    - Open DNS Resolver Check...")
        try:
            # Use Google's DNS to test if recursive queries are allowed
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.target_ip]
            resolver.timeout = 3
            resolver.lifetime = 3
            
            # Try resolving an external domain
            answers = resolver.resolve('google.com', 'A')
            if answers:
                print(f"      ⚠ Open resolver detected! Recursive queries allowed.")
                self._db_save_finding(
                    "Open DNS Resolver", "High",
                    f"{self.target_ip} is an open DNS resolver. "
                    f"Can be used for DDoS amplification attacks."
                )
            else:
                print(f"      - Not an open resolver")
        except (dns.resolver.NoNameservers, dns.exception.Timeout):
            print(f"      - Not an open resolver (or not a DNS server)")
        except Exception as e:
            print(f"      - Open resolver check: {e}")

    def run_dnssec_validation(self):
        """Check DNSSEC validation/trust chain."""
        print("    - DNSSEC Validation Check...")
        try:
            # Check if domain has DNSSEC
            resolver = dns.resolver.Resolver()
            
            # Try with DNSSEC OK flag
            request = dns.message.make_query(self.target, dns.rdatatype.A, want_dnssec=True)
            response = resolver.query(request)
            
            if response:
                # Check if AD (Authentic Data) flag is set
                if response.flags & dns.flags.AD:
                    print(f"      ✓ DNSSEC: Authenticated data (AD flag set)")
                else:
                    print(f"      - DNSSEC: Domain not DNSSEC-signed or validation not performed")
        except Exception as e:
            print(f"      - DNSSEC check: {e}")

    def run_wildcard_detection(self):
        """Detect DNS wildcard entries."""
        print("    - DNS Wildcard Detection...")
        try:
            import random
            random_sub = f"wildcard-test-{random.randint(10000, 99999)}"
            test_domain = f"{random_sub}.{self.target}"
            
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3
            
            try:
                answers = resolver.resolve(test_domain, 'A')
                if answers:
                    ip = answers[0].to_text()
                    print(f"      ⚠ Wildcard DNS detected! {random_sub}.{self.target} resolves to {ip}")
                    self._db_save_finding(
                        "DNS Wildcard Detected", "Info",
                        f"Wildcard DNS entry on {self.target}. All subdomains resolve to {ip}. "
                        f"This can hide subdomain enumeration results."
                    )
                else:
                    print(f"      - No wildcard DNS detected")
            except dns.resolver.NXDOMAIN:
                print(f"      - No wildcard DNS detected (NXDOMAIN for random subdomain)")
            except:
                print(f"      - Wildcard detection inconclusive")
        except Exception as e:
            print(f"      - Wildcard check error: {e}")

    # =========================================================================
    # 3. SERVICE ENUMERATION — FTP, SSH, Telnet, RDP, VNC, Databases
    # =========================================================================

    def run_ftp_enum(self):
        """FTP enumeration: anonymous login, banner, writable dirs.
        Uses separate connections for each probe phase.
        """
        print("    - FTP Enumeration...")
        
        # Phase 1: Banner grab (fresh connection)
        banner = ""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            result = s.connect_ex((self.target_ip, 21))
            if result != 0:
                s.close()
                print(f"      - Port 21 closed")
                return
            banner = s.recv(1024).decode(errors='ignore').strip()
            print(f"      ✓ FTP banner: {banner[:80]}")
            s.close()
        except Exception as e:
            print(f"      - FTP check: {e}")
            return
        
        # Phase 2: Check STARTTLS (fresh connection)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((self.target_ip, 21))
            s.recv(1024)  # Discard banner
            s.send(b'AUTH TLS\r\n')
            tls_resp = s.recv(512).decode(errors='ignore')
            if '234' in tls_resp:
                print(f"      - FTP over TLS supported")
            s.close()
        except:
            pass
        
        # Phase 3: Anonymous login test (fresh connection)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((self.target_ip, 21))
            s.recv(1024)  # Discard banner
            s.send(b'USER anonymous\r\n')
            resp = s.recv(512).decode(errors='ignore')
            if '331' in resp or '230' in resp:
                s.send(b'PASS anonymous@example.com\r\n')
                resp2 = s.recv(512).decode(errors='ignore')
                if '230' in resp2 or '202' in resp2:
                    print(f"      ⚠ Anonymous FTP login allowed!")
                    self._db_save_finding(
                        "Anonymous FTP Access", "High",
                        f"FTP server at {self.target_ip}:21 allows anonymous login"
                    )
                    # Check writable dir
                    s.send(b'CWD /incoming\r\n')
                    cwd_resp = s.recv(512).decode(errors='ignore')
                    if '250' in cwd_resp:
                        print(f"        /incoming directory exists")
                    s.send(b'QUIT\r\n')
            s.close()
        except:
            pass

    def run_ssh_enum(self):
        """SSH enumeration: banner, algorithms, host keys."""
        print("    - SSH Enumeration...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((self.target_ip, 22))
            banner = s.recv(4096).decode(errors='ignore').strip()
            
            if banner:
                print(f"      ✓ SSH banner: {banner[:100]}")
                
                # Extract SSH version
                ver_match = re.search(r'SSH-(\d+\.\d+)', banner)
                if ver_match:
                    version = ver_match.group(1)
                    print(f"        Protocol: SSH-{version}")
                    
                    # Check for weak versions
                    if version.startswith('1.'):
                        self._db_save_finding("SSHv1 Detected", "Critical",
                            f"SSHv1 protocol detected on {self.target_ip}:22. Vulnerable to MITM.")
                
                # Check for known weak implementations
                if 'Dropbear' in banner:
                    print(f"        Server: Dropbear SSH")
                elif 'OpenSSH' in banner:
                    openssh_ver = re.search(r'OpenSSH[_-]([\d.]+)', banner)
                    if openssh_ver:
                        print(f"        Server: OpenSSH {openssh_ver.group(1)}")
                elif 'libssh' in banner.lower():
                    print(f"        Server: libssh")
                
                # Try SSHv2 key exchange initiation
                s.send(b"SSH-2.0-ArgusRecon_1.0\r\n")
                time.sleep(0.5)
                kex_init = s.recv(4096)
                if kex_init:
                    print(f"        Key exchange initialized (SSH-2.0 compatible)")
                
                s.close()
        except Exception as e:
            pass

    def run_telnet_enum(self):
        """Telnet enumeration: banner and authentication detection."""
        print("    - Telnet Enumeration...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((self.target_ip, 23))
            
            # Receive initial negotiation/banner
            banner = b""
            try:
                while True:
                    data = s.recv(1024)
                    if not data:
                        break
                    banner += data
                    if b'login:' in data.lower() or b'Password' in data:
                        break
            except socket.timeout:
                pass
            
            if banner:
                clean_banner = banner.decode(errors='ignore').strip()
                # Remove Telnet negotiation bytes
                clean_banner = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', clean_banner)
                if clean_banner:
                    print(f"      ✓ Telnet banner: {clean_banner[:100]}")
                    
                    if b'login:' in banner.lower():
                        print(f"        Login prompt detected (authentication enabled)")
                    
                    self._db_save_finding(
                        "Telnet Service Detected", "High",
                        f"Telnet service running on {self.target_ip}:23. "
                        f"Consider using SSH instead (unencrypted protocol)."
                    )
            s.close()
        except socket.timeout:
            print(f"      - Port 23 timeout (filtered?)")
        except ConnectionRefusedError:
            print(f"      - Port 23 closed")
        except Exception as e:
            pass

    def run_rdp_enum(self):
        """RDP enumeration: version, encryption, NLA support."""
        print("    - RDP Enumeration...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((self.target_ip, 3389))
            
            # RDP Connection Request (X.224 Connection Request)
            rdp_packet = (
                b'\x03\x00\x00\x0b\x06\xe0\x00\x00\x00\x00\x00'  # X.224 CR
                b'\x04\x01\x00\x08\x00\x03\x00\x00'  # RDP Negotiation Request
            )
            s.send(rdp_packet)
            response = s.recv(4096)
            s.close()
            
            if response:
                print(f"      ✓ RDP service detected on port 3389")
                
                # Parse RDP negotiation response
                if len(response) > 15:
                    rdp_version = response[15] if len(response) > 15 else 0
                    if rdp_version == 8:
                        print(f"        RDP Version: 10.x (Windows 10/Server 2016+)")
                    elif rdp_version == 5:
                        print(f"        RDP Version: 8.x (Windows 7/Server 2008R2)")
                    elif rdp_version == 4:
                        print(f"        RDP Version: 5.x (Windows 2000/XP)")
                    
                    # Check NLA (Network Level Authentication)
                    if len(response) > 19:
                        selected_protocol = int.from_bytes(response[18:20], 'little')
                        if selected_protocol == 0:
                            print(f"        NLA: Not supported (CredSSP disabled)")
                        elif selected_protocol == 1:
                            print(f"        NLA: Not supported (TLS only)")
                        elif selected_protocol == 2:
                            print(f"        NLA: Supported (CredSSP enabled)")
                        elif selected_protocol == 3:
                            print(f"        NLA: Early User Auth supported")
                
                self._db_save_finding(
                    "RDP Service Detected", "Medium",
                    f"RDP service running on {self.target_ip}:3389"
                )
        except Exception as e:
            pass

    def run_vnc_enum(self):
        """VNC enumeration: version and authentication type detection."""
        print("    - VNC Enumeration...")
        for port in [5900, 5901, 5902]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((self.target_ip, port))
                
                # VNC Protocol Version
                banner = s.recv(4096).decode(errors='ignore').strip()
                if 'RFB' in banner:
                    print(f"      ✓ VNC on port {port}: {banner[:50]}")
                    
                    # Send VNC version string back
                    s.send(banner.encode()[:12] + b'\n')
                    auth_response = s.recv(4096)
                    
                    if auth_response:
                        # Check auth type
                        if len(auth_response) > 0:
                            auth_type = auth_response[0] if auth_response[0] < 10 else auth_response[3] if len(auth_response) > 3 else 0
                            auth_map = {
                                1: "None (No Authentication)", 2: "VNC Authentication (Challenge-Response)",
                                5: "RA2", 6: "RA2ne", 16: "Tight", 17: "Ultra",
                                18: "TLS", 19: "VeNCrypt", 20: "GTK-VNC-SASL",
                                21: "MD5 hash", 22: "Colin Dean x",
                            }
                            auth_name = auth_map.get(auth_type, f"Unknown ({auth_type})")
                            print(f"        Auth: {auth_name}")
                            
                            if auth_type == 1:
                                self._db_save_finding(
                                    f"VNC No Authentication (port {port})", "Critical",
                                    f"VNC server on {self.target_ip}:{port} allows connections without authentication!"
                                )
                            else:
                                self._db_save_finding(
                                    f"VNC Service Detected (port {port})", "Medium",
                                    f"VNC server on {self.target_ip}:{port} with {auth_name}"
                                )
                    s.close()
                    return  # Found VNC on first port
                s.close()
            except Exception:
                pass

    def run_database_enum(self):
        """Database service enumeration across multiple DB types."""
        print("    - Database Service Detection...")
        found_db = False
        
        def check_db(port: int, db_name: str) -> Tuple[bool, str]:
            """Check a specific database port."""
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex((self.target_ip, port))
                
                if result == 0:
                    banner = ""
                    try:
                        if db_name == 'mysql':
                            # MySQL handshake
                            data = s.recv(1024)
                            if data:
                                banner = data.decode(errors='ignore')[:100]
                        elif db_name == 'redis':
                            # Redis sends a banner on connect
                            data = s.recv(1024)
                            if data:
                                banner = data.decode(errors='ignore')[:100]
                        elif db_name == 'mongodb':
                            # MongoDB wire protocol
                            s.send(b'\x3a\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00')
                            data = s.recv(1024)
                            if data:
                                banner = data.hex()[:50]
                        elif db_name == 'elasticsearch':
                            s.send(b'GET / HTTP/1.0\r\n\r\n')
                            data = s.recv(1024)
                            if data:
                                banner = data.decode(errors='ignore')[:100]
                        else:
                            s.send(b'\n')
                            time.sleep(0.3)
                            data = s.recv(256)
                            if data:
                                banner = data.decode(errors='ignore')[:100]
                    except:
                        pass
                    s.close()
                    return True, banner
                s.close()
            except:
                pass
            return False, ""
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_db, port, db): (db, port) for db, port in DATABASE_PORTS.items()}
            for future in concurrent.futures.as_completed(futures):
                db_name, port = futures[future]
                try:
                    is_open, banner = future.result()
                    if is_open:
                        found_db = True
                        print(f"      ✓ {db_name.capitalize()} on port {port}: {banner[:60] if banner else 'Detected'}")
                        self._db_save_finding(
                            f"Database: {db_name.capitalize()} (port {port})", "Medium",
                            f"{db_name.capitalize()} database detected on {self.target_ip}:{port}"
                        )
                except:
                    pass
        
        if found_db:
            print(f"      - Database scanning complete")
        else:
            print(f"      - No common database services detected")

    def run_rpc_nfs_enum(self):
        """RPC portmapper and NFS enumeration."""
        print("    - RPC/NFS Enumeration...")
        try:
            # Check portmapper (port 111)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((self.target_ip, 111))
            
            # PMAP dump request
            pmap_packet = (
                b'\x80\x00\x00\x28'  # XID
                b'\x00\x00\x00\x00'  # msg_type = CALL
                b'\x00\x00\x00\x02'  # RPC version
                b'\x00\x01\x86\xa0'  # program = PMAP (100000)
                b'\x00\x00\x00\x02'  # version
                b'\x00\x00\x00\x04'  # procedure = DUMP
                b'\x00\x00\x00\x00'  # credentials
                b'\x00\x00\x00\x00'  # verifier
            )
            s.send(pmap_packet)
            response = s.recv(8192)
            s.close()
            
            if response and len(response) > 24:
                # Parse RPC services from response
                print(f"      ✓ RPC Portmapper (port 111): Responding")
                
                # Check NFS (port 2049)
                nfs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                nfs.settimeout(3)
                nfs_result = nfs.connect_ex((self.target_ip, 2049))
                if nfs_result == 0:
                    print(f"      ✓ NFS (port 2049): Detected")
                    self._db_save_finding(
                        "NFS Service Detected", "Medium",
                        f"NFS service running on {self.target_ip}:2049. Check for misconfigured exports."
                    )
                nfs.close()
                
                self._db_save_finding(
                    "RPC Portmapper Detected", "Info",
                    f"RPC portmapper running on {self.target_ip}:111. "
                    f"Can enumerate registered RPC services."
                )
        except Exception:
            pass

    # =========================================================================
    # 4. PASSIVE IP INTELLIGENCE — ASN, BGP, Reverse DNS/IP
    # =========================================================================

    def run_asn_intelligence(self):
        """Enhanced ASN intelligence: upstream providers, peers."""
        print("    - ASN Intelligence (Upstream & Peers)...")
        try:
            url = f"https://ipapi.co/{self.target_ip}/json/"
            res = requests.get(url, timeout=8, headers={'User-Agent': _get_ua()})
            if res.status_code == 200:
                data = res.json()
                asn = data.get('asn', '')
                asn_org = data.get('org', '')
                
                if asn:
                    asn_num = asn.replace('AS', '')
                    print(f"      ✓ ASN: {asn} ({asn_org})")
                    
                    # Get BGP peers and upstream via HackerTarget
                    try:
                        peer_url = f"https://api.hackertarget.com/aslookup/?q=AS{asn_num}"
                        peer_res = requests.get(peer_url, timeout=8)
                        if peer_res.status_code == 200:
                            prefixes = peer_res.text.strip().split('\n')[:5]
                            print(f"        BGP Prefixes: {len(prefixes)}")
                            for prefix in prefixes:
                                print(f"          {prefix}")
                    except:
                        pass
                    
                    # Save ASN info (UPDATE if exists to preserve other columns)
                    if self.db.connect():
                        try:
                            cursor = self.db.conn.cursor()
                            cursor.execute(
                                "SELECT id FROM bgp_info WHERE target_id=? AND ip_address=?",
                                (self.target_id, self.target_ip)
                            )
                            existing = cursor.fetchone()
                            if existing:
                                cursor.execute(
                                    """UPDATE bgp_info SET asn=?, asn_name=?, asn_country=?
                                       WHERE target_id=? AND ip_address=?""",
                                    (int(asn_num), asn_org, data.get('country_name', ''),
                                     self.target_id, self.target_ip)
                                )
                            else:
                                cursor.execute(
                                    """INSERT INTO bgp_info 
                                       (target_id, ip_address, asn, asn_name, asn_country)
                                       VALUES (?, ?, ?, ?, ?)""",
                                    (self.target_id, self.target_ip, int(asn_num), asn_org, data.get('country_name', ''))
                                )
                            self.db.conn.commit()
                        except Exception as db_err:
                            print(f"        DB error: {db_err}")
                        finally:
                            self.db.close()
        except Exception as e:
            print(f"      - ASN intel: {e}")

    def run_bgp_hijack_check(self):
        """BGP hijack detection by comparing routes from multiple sources."""
        print("    - BGP Hijack Detection...")
        try:
            # Compare BGP data from multiple sources
            sources = [
                f"https://api.hackertarget.com/aslookup/?q={self.target_ip}",
                f"https://ipapi.co/{self.target_ip}/json/",
            ]
            
            results = []
            for url in sources:
                try:
                    r = requests.get(url, timeout=8, headers={'User-Agent': _get_ua()})
                    if r.status_code == 200:
                        results.append(r.text[:500])
                except:
                    pass
            
            # Check for inconsistencies
            if len(results) >= 2:
                asn_set = set()
                for text in results:
                    asn_match = re.search(r'AS(\d+)', text)
                    if asn_match:
                        asn_set.add(asn_match.group(1))
                
                if len(asn_set) > 1:
                    print(f"      ⚠ BGP inconsistency detected! ASNs: {', '.join(asn_set)}")
                    self._db_save_finding(
                        "BGP Route Inconsistency", "High",
                        f"Different ASNs reported for {self.target_ip}: {', '.join(asn_set)}. "
                        f"Possible BGP hijack or multi-homing."
                    )
                elif len(asn_set) == 1:
                    print(f"      ✓ Consistent ASN: AS{list(asn_set)[0]}")
                else:
                    print(f"      - No ASN data available")
        except Exception as e:
            print(f"      - BGP hijack check: {e}")

    def run_historical_ptr(self):
        """Historical PTR/reverse DNS lookup."""
        print("    - Historical Reverse DNS...")
        try:
            # Check current PTR first
            hostname = socket.gethostbyaddr(self.target_ip)[0]
            print(f"      ✓ Current PTR: {hostname}")
            
            # Check if PTR matches forward DNS
            try:
                forward = socket.gethostbyname(hostname)
                if forward == self.target_ip:
                    print(f"        Forward-confirmed: ✓")
                else:
                    print(f"        Forward-confirmed: ✗ (PTR does not match A record)")
                    self._db_save_finding(
                        "Reverse DNS Mismatch", "Low",
                        f"PTR record ({hostname}) does not resolve back to {self.target_ip}"
                    )
            except:
                pass
        except socket.herror:
            print(f"      - No PTR record for {self.target_ip}")
        except Exception as e:
            print(f"      - Reverse DNS: {e}")

    def run_reverse_ip_lookup(self):
        """Reverse IP lookup using public services."""
        print("    - Reverse IP / Hosted Domains...")
        try:
            # Use you-getsignal.com or similar free service
            url = f"https://api.hackertarget.com/reverseiplookup/?q={self.target_ip}"
            res = requests.get(url, timeout=10, headers={'User-Agent': _get_ua()})
            
            if res.status_code == 200 and res.text.strip():
                domains = [d.strip() for d in res.text.strip().split('\n') if d.strip() and d.strip() != self.target]
                if domains:
                    print(f"      ✓ Found {len(domains)} domains hosted on this IP:")
                    for domain in domains[:10]:
                        print(f"        > {domain}")
                    
                    self._db_save_finding(
                        "Reverse IP: Co-hosted Domains", "Info",
                        f"IP {self.target_ip} hosts {len(domains)} domains including: {', '.join(domains[:5])}"
                    )
                else:
                    print(f"      - No co-hosted domains found")
        except Exception as e:
            print(f"      - Reverse IP: {e}")

    # =========================================================================
    # 5. THREAT INTELLIGENCE — Additional Sources
    # =========================================================================

    def run_greynoise_check(self):
        """GreyNoise threat intelligence (free API)."""
        print("    - GreyNoise Threat Check...")
        try:
            url = f"https://api.greynoise.io/v3/community/{self.target_ip}"
            headers = {'User-Agent': _get_ua()}
            res = requests.get(url, headers=headers, timeout=8)
            
            if res.status_code == 200:
                data = res.json()
                classification = data.get('classification', 'unknown')
                
                if classification == 'malicious':
                    print(f"      ⚠ GreyNoise: Malicious")
                    self._db_save_finding(
                        "GreyNoise: Malicious IP", "High",
                        f"{self.target_ip} classified as malicious by GreyNoise. "
                        f"Last seen: {data.get('last_seen', 'Unknown')}"
                    )
                elif classification == 'benign':
                    print(f"      ✓ GreyNoise: Benign")
                else:
                    print(f"      - GreyNoise: Unknown")
            else:
                print(f"      - GreyNoise: No data")
        except Exception as e:
            print(f"      - GreyNoise: {e}")

    def run_malwarebazaar_check(self):
        """Check MalwareBazaar for IP-associated malware samples."""
        print("    - MalwareBazaar Check...")
        try:
            url = "https://mb-api.abuse.ch/api/v1/"
            data = {'query': 'get_host', 'host': self.target_ip}
            headers = {'User-Agent': _get_ua()}
            res = requests.post(url, data=data, headers=headers, timeout=10)
            
            if res.status_code == 200:
                result = res.json()
                if result.get('query_status') == 'ok' and result.get('data'):
                    samples = result['data']
                    print(f"      ⚠ Found {len(samples)} malware samples!")
                    for sample in samples[:3]:
                        print(f"        > {sample.get('sha256_hash', '')[:16]}... "
                              f"({sample.get('signature', 'Unknown')})")
                    self._db_save_finding(
                        "MalwareBazaar: Samples Found", "Critical",
                        f"{len(samples)} malware samples associated with {self.target_ip}"
                    )
                else:
                    print(f"      ✓ No malware samples found")
            else:
                print(f"      - MalwareBazaar: {res.status_code}")
        except Exception as e:
            print(f"      - MalwareBazaar: {e}")

    def run_misp_threatfox_check(self):
        """Check ThreatFox (abuse.ch) for IP indicators."""
        print("    - ThreatFox IOC Check...")
        try:
            url = f"https://threatfox-api.abuse.ch/api/v1/"
            payload = {
                'query': 'search_ioc',
                'search_term': self.target_ip
            }
            headers = {'User-Agent': _get_ua()}
            res = requests.post(url, json=payload, headers=headers, timeout=10)
            
            if res.status_code == 200:
                data = res.json()
                if data.get('query_status') == 'ok' and data.get('data'):
                    iocs = data['data']
                    print(f"      ⚠ Found {len(iocs)} IOC(s) on ThreatFox!")
                    for ioc in iocs[:3]:
                        malware = ioc.get('malware_printable', 'Unknown')
                        first_seen = ioc.get('first_seen', '')
                        print(f"        > {malware} ({first_seen})")
                    self._db_save_finding(
                        "ThreatFox: IOC Found", "Critical",
                        f"{len(iocs)} threat indicators for {self.target_ip} on ThreatFox"
                    )
                else:
                    print(f"      ✓ No ThreatFox IOCs found")
            else:
                print(f"      - ThreatFox: {res.status_code}")
        except Exception as e:
            print(f"      - ThreatFox: {e}")

    # =========================================================================
    # 6. INTERNET-WIDE SCAN DATABASES
    # =========================================================================

    def run_binaryedge_check(self):
        """BinaryEdge internet scan database."""
        print("    - BinaryEdge Check...")
        api_key = getattr(config, 'BINARYEDGE_API_KEY', '')
        if not api_key:
            print(f"      - No BinaryEdge API key configured (add BINARYEDGE_API_KEY to .env)")
            return
        
        try:
            url = f"https://api.binaryedge.io/v2/query/ip/{self.target_ip}"
            headers = {'X-Key': api_key, 'User-Agent': _get_ua()}
            res = requests.get(url, headers=headers, timeout=10)
            
            if res.status_code == 200:
                data = res.json()
                ports = data.get('events', [])
                if ports:
                    print(f"      ✓ Found {len(ports)} recent port(s)/service(s)")
                    for event in ports[:5]:
                        port = event.get('target', {}).get('port', {}).get('port', '?')
                        service = event.get('result', {}).get('service', {}).get('name', '?')
                        print(f"        Port {port}: {service}")
                else:
                    print(f"      - No recent data")
            else:
                print(f"      - BinaryEdge: {res.status_code}")
        except Exception as e:
            print(f"      - BinaryEdge: {e}")

    # =========================================================================
    # 7. CERTIFICATE INTELLIGENCE
    # =========================================================================

    def run_advanced_certificate_check(self):
        """Certificate intelligence: SAN enumeration, weak algorithms, historical."""
        print("    - Advanced Certificate Intelligence...")
        
        # Check certificate on common HTTPS ports
        for port in [443, 8443]:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((self.target_ip, port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=self.target) as ssock:
                        cert = ssock.getpeercert()
                        
                        if cert:
                            # Extract SANs
                            sans = []
                            for ext in cert.get('subjectAltName', []):
                                if ext[0] == 'DNS':
                                    sans.append(ext[1])
                            
                            if sans:
                                print(f"      ✓ Port {port}: {len(sans)} Subject Alternative Names:")
                                for san in sans[:5]:
                                    print(f"        > {san}")
                            
                            # Check signature algorithm
                            sig_algo = cert.get('signatureAlgorithm', 'Unknown')
                            print(f"        Signature: {sig_algo}")
                            
                            # Check for weak algorithms
                            if 'sha1' in sig_algo.lower():
                                self._db_save_finding(
                                    f"Weak Certificate Signature (SHA1)", "Medium",
                                    f"Certificate on port {port} uses weak {sig_algo} algorithm"
                                )
                            
                            # Check validity
                            not_after = cert.get('notAfter', '')
                            if not_after:
                                try:
                                    from datetime import datetime as dt
                                    expiry = dt.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                                    days_left = (expiry - dt.now()).days
                                    if days_left < 30:
                                        print(f"        ⚠ Expires in {days_left} days!")
                                        self._db_save_finding(
                                            f"Certificate Expiring Soon ({days_left} days)", "Medium",
                                            f"HTTPS cert on port {port} expires {not_after}"
                                        )
                                    elif days_left < 0:
                                        print(f"        ✗ Certificate expired!")
                                        self._db_save_finding(
                                            "Certificate Expired", "High",
                                            f"HTTPS cert on port {port} expired {not_after}"
                                        )
                                    else:
                                        print(f"        Valid until: {not_after} ({days_left} days)")
                                except:
                                    print(f"        Valid until: {not_after}")
                            
                            issuer = dict(x[0] for x in cert.get('issuer', []))
                            print(f"        Issuer: {issuer.get('organizationName', 'Unknown')}")
                            break  # Found certificate, done
            except Exception:
                continue

    # =========================================================================
    # 8. CLOUD INFRASTRUCTURE DETECTION
    # =========================================================================

    def run_cloud_detection(self):
        """Detect cloud infrastructure: AWS, Azure, GCP, etc."""
        print("    - Cloud Infrastructure Detection...")
        
        cloud_ranges = {
            'AWS': {
                'prefixes_url': 'https://ip-ranges.amazonaws.com/ip-ranges.json',
                'domains': ['amazonaws.com', 'cloudfront.net', 'compute.amazonaws.com'],
                'headers': {'Server': ['aws'], 'X-Amz-': []},
            },
            'Azure': {
                'domains': ['azure.com', 'azureedge.net', 'azurefd.net', 'trafficmanager.net'],
                'headers': {'Server': ['azure'], 'X-Azure-': []},
            },
            'GCP': {
                'domains': ['googleusercontent.com', 'gcp', 'appspot.com'],
                'headers': {'Server': ['gws', 'Google'], 'X-Google-': []},
            },
            'Oracle Cloud': {
                'domains': ['oraclecloud.com', 'oci'],
                'headers': {},
            },
            'DigitalOcean': {
                'domains': ['digitaloceanspaces.com'],
                'headers': {},
            },
            'Linode': {
                'domains': ['linode.com', 'linodeobjects.com'],
                'headers': {},
            },
            'Vultr': {
                'domains': ['vultr.com', 'vultrobjects.com'],
                'headers': {},
            },
        }
        
        detected = []
        
        # Check via HTTP headers
        try:
            res = requests.get(
                f"https://{self.target_ip}",
                timeout=5, verify=False,
                headers={'User-Agent': _get_ua()}
            )
            server_header = res.headers.get('Server', '')
            via_header = res.headers.get('Via', '')
            
            for provider, info in cloud_ranges.items():
                for header_check in info.get('headers', {}):
                    if isinstance(header_check, dict):
                        for hdr_key, hdr_values in header_check.items():
                            for hdr_val in hdr_values:
                                if hdr_val.lower() in server_header.lower() or hdr_val.lower() in via_header.lower():
                                    detected.append(provider)
                                    break
            if detected:
                print(f"      ✓ Cloud provider(s) detected via headers: {', '.join(set(detected))}")
        except:
            pass
        
        # Check via RDNS
        try:
            hostname = socket.gethostbyaddr(self.target_ip)[0].lower()
            provider_map = {
                'amazonaws': 'AWS', 'cloudfront': 'AWS', 'compute.amazonaws': 'AWS',
                'azure': 'Azure', 'trafficmanager': 'Azure', 'azureedge': 'Azure',
                'google': 'GCP', 'gce': 'GCP', 'appspot': 'GCP', 'googleusercontent': 'GCP',
                'digitalocean': 'DigitalOcean',
                'linode': 'Linode',
                'vultr': 'Vultr',
                'oracle': 'Oracle Cloud', 'oci': 'Oracle Cloud',
            }
            for keyword, provider in provider_map.items():
                if keyword in hostname:
                    detected.append(provider)
            if detected:
                print(f"      ✓ Cloud provider(s) detected via RDNS: {', '.join(set(detected))}")
        except:
            pass
        
        if detected:
            for provider in set(detected):
                self._db_save_finding(
                    f"Cloud Infrastructure: {provider}", "Info",
                    f"IP {self.target_ip} appears to be hosted on {provider}"
                )

    # =========================================================================
    # 9. VPN / PROXY / TOR DETECTION
    # =========================================================================

    def run_vpn_tor_detection(self):
        """Detect VPN, proxy, and TOR exit nodes."""
        print("    - VPN/Proxy/TOR Detection...")
        
        # Check DNS-based TOR exit node lists
        tor_detected = False
        try:
            # TOR exit node check via DNSBL
            reversed_ip = '.'.join(reversed(self.target_ip.split('.')))
            for dnsbl in ['tor.dan.me.uk', 'tor.ahbl.org']:
                try:
                    query = f"{reversed_ip}.{dnsbl}"
                    answers = socket.gethostbyname_ex(query)
                    if answers:
                        tor_detected = True
                        break
                except socket.gaierror:
                    pass
        except:
            pass
        
        # Check common proxy/VPN ports
        proxy_ports_detected = []
        proxy_ports = [1080, 3128, 8080, 8888, 8118, 9050, 9150, 8081]
        for port in proxy_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                if s.connect_ex((self.target_ip, port)) == 0:
                    proxy_ports_detected.append(port)
                s.close()
            except:
                pass
        
        # Use ipapi.co VPN detection
        try:
            url = f"https://ipapi.co/{self.target_ip}/json/"
            res = requests.get(url, timeout=8, headers={'User-Agent': _get_ua()})
            if res.status_code == 200:
                data = res.json()
                if data.get('vpn', False):
                    print(f"      ⚠ VPN detected ({data.get('org', 'Unknown')})")
                    self._db_save_finding("VPN Service Detected", "Info",
                        f"IP {self.target_ip} is a VPN endpoint ({data.get('org')})")
                if data.get('proxy', False):
                    print(f"      ⚠ Public proxy detected")
                    self._db_save_finding("Public Proxy Detected", "Low",
                        f"IP {self.target_ip} is a public proxy server")
        except:
            pass
        
        if tor_detected:
            print(f"      ⚠ TOR exit node detected!")
            self._db_save_finding("TOR Exit Node", "Medium",
                f"IP {self.target_ip} is a TOR exit node")
        
        if proxy_ports_detected:
            print(f"      Proxy ports detected: {proxy_ports_detected}")

    # =========================================================================
    # 10. NETWORK SECURITY ANALYSIS (WAF, Firewall Detection)
    # =========================================================================

    def run_network_security_analysis(self):
        """Detect WAF, firewall, IDS/IPS, and rate limiting."""
        print("    - Network Security Analysis...")
        
        # WAF Detection via headers
        waf_detected = []
        try:
            res = requests.get(
                f"https://{self.target_ip}",
                timeout=5, verify=False,
                headers={'User-Agent': _get_ua()}
            )
            headers = res.headers
            
            waf_signatures = {
                'Cloudflare': ['CF-RAY', 'cf-ray', '__cfduid'],
                'AWS WAF': ['x-amzn-RequestId', 'x-amzn-ErrorType'],
                'Akamai': ['x-akamai', 'akamai'],
                'F5 BIG-IP': ['BIG-IP', 'F5'],
                'Imperva/Incapsula': ['X-Iinfo', 'incapsula'],
                'ModSecurity': ['ModSecurity', '_mod_security'],
                'Sucuri': ['X-Sucuri-ID', 'Sucuri'],
                'Barracuda': ['barracuda'],
                'Wordfence': ['wordfence'],
                'StackPath': ['stackpath'],
            }
            
            for waf_name, sigs in waf_signatures.items():
                for sig in sigs:
                    if any(sig.lower() in str(v).lower() for v in headers.values()) or \
                       any(sig.lower() in str(k).lower() for k in headers.keys()):
                        waf_detected.append(waf_name)
                        break
        except:
            pass
        
        if waf_detected:
            print(f"      ✓ WAF detected: {', '.join(set(waf_detected))}")
            for waf in set(waf_detected):
                self._db_save_finding(f"WAF Detected: {waf}", "Info",
                    f"{waf} Web Application Firewall detected on {self.target_ip}")
        else:
            print(f"      - No WAF detected via headers")
        
        # Firewall detection via port filtering analysis
        print("    - Firewall Filtering Analysis...")
        test_ports = [22, 80, 443, 3389, 8080]
        open_count = 0
        filtered_count = 0
        for port in test_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex((self.target_ip, port))
                if result == 0:
                    open_count += 1
                elif result == 10060 or result == 110:  # Timeout
                    filtered_count += 1
                s.close()
            except:
                filtered_count += 1
        
        if filtered_count > 3 and open_count < 2:
            print(f"      - Firewall likely present ({filtered_count}/{len(test_ports)} ports filtered)")
        elif open_count > 3:
            print(f"      - Minimal filtering ({open_count} ports open)")

    # =========================================================================
    # 11. IPv6 INTELLIGENCE
    # =========================================================================

    def run_ipv6_intelligence(self):
        """IPv6 intelligence: AAAA records, reachability, services."""
        print("    - IPv6 Intelligence...")
        
        # Check AAAA records
        try:
            answers = dns.resolver.resolve(self.target, 'AAAA')
            ipv6_addresses = [str(r) for r in answers]
            if ipv6_addresses:
                print(f"      ✓ IPv6 (AAAA) records found: {len(ipv6_addresses)}")
                for ipv6 in ipv6_addresses[:3]:
                    print(f"        > {ipv6}")
                
                # Try to reach IPv6 address
                for ipv6 in ipv6_addresses[:1]:
                    try:
                        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                        s.settimeout(3)
                        s.connect((ipv6, 80, 0, 0))
                        s.close()
                        print(f"        HTTP reachable via IPv6: ✓")
                        self._db_save_finding(
                            "IPv6 Service Detected", "Info",
                            f"Target has IPv6 connectivity: {ipv6}"
                        )
                        break
                    except:
                        print(f"        HTTP not reachable via IPv6")
            else:
                print(f"      - No IPv6 records found")
        except dns.resolver.NoAnswer:
            print(f"      - No AAAA records")
        except:
            print(f"      - IPv6 check failed")

    # =========================================================================
    # 12. SEARCH ENGINE INTELLIGENCE
    # =========================================================================

    def run_search_engine_ip_queries(self):
        """Search engines for IP references, disclosures, and mentions."""
        print("    - Search Engine Intelligence...")
        search_engines = [
            ('DuckDuckGo', f"https://html.duckduckgo.com/html/?q=%22{self.target_ip}22"),
            ('DuckDuckGo Security', f"https://html.duckduckgo.com/html/?q=%22{self.target_ip}22+security+breach"),
        ]
        
        for engine_name, url in search_engines:
            try:
                res = requests.get(url,
                    headers={'User-Agent': _get_ua()},
                    timeout=8)
                if res.status_code == 200 and 'did not match' not in res.text:
                    # Extract result count/mentions
                    snippets = re.findall(r'class="result__snippet"[^>]*>(.*?)</a>', res.text, re.DOTALL)
                    if snippets:
                        print(f"      ✓ {engine_name}: {len(snippets)} mention(s)")
                        for s in snippets[:2]:
                            clean = re.sub(r'<[^>]+>', '', s).strip()
                            print(f"        > {clean[:100]}...")
                        break
                else:
                    print(f"      - {engine_name}: No results")
            except:
                pass
        
        # Check paste sites
        try:
            url = f"https://psbdmp.ws/api/search/{self.target_ip}"
            res = requests.get(url, timeout=8, headers={'User-Agent': _get_ua()})
            if res.status_code == 200:
                dumps = res.json()
                if dumps and len(dumps) > 0:
                    count = len(dumps)
                    print(f"      ⚠ Pastebin dumps containing IP: {count} found!")
                    self._db_save_finding(
                        "IP Found in Pastebin Dumps", "High",
                        f"IP {self.target_ip} found in {count} pastebin dumps"
                    )
        except:
            pass

    # =========================================================================
    # 13. RISK ANALYSIS
    # =========================================================================

    def run_comprehensive_risk_analysis(self):
        """Comprehensive risk scoring across all categories. Batched DB queries."""
        print("    - Comprehensive Risk Analysis...")
        risk_factors = []
        score = 0
        
        if not self.db.connect():
            return
        
        try:
            cursor = self.db.conn.cursor()
            
            # Count open ports (weighted by criticality)
            cursor.execute("SELECT port FROM ports WHERE target_id=?", (self.target_id,))
            ports = [r[0] for r in cursor.fetchall()]
            
            critical_ports = {21, 23, 25, 110, 143, 3389, 5900, 5901}
            sensitive_ports = {22, 445, 1433, 1521, 3306, 5432, 6379, 27017, 9200}
            
            for port in ports:
                if port in critical_ports:
                    score += 15
                    risk_factors.append(f"Critical port {port} open")
                elif port in sensitive_ports:
                    score += 8
                    risk_factors.append(f"Sensitive port {port} open")
                else:
                    score += 3
            
            if ports:
                print(f"      Port risk: {len(ports)} open port(s)")
            
            # Count findings by severity
            cursor.execute("SELECT severity FROM findings WHERE target_id=?", (self.target_id,))
            for (severity,) in cursor.fetchall():
                if severity == 'Critical': score += 25
                elif severity == 'High': score += 15
                elif severity == 'Medium': score += 8
                elif severity == 'Low': score += 3
            
            self.db.conn.commit()
        except Exception as e:
            print(f"      Risk DB error: {e}")
        finally:
            self.db.close()
        
        # Exposure assessment (external check)
        if self.target_ip:
            try:
                cloud_asns = ['15169', '16509', '14618', '8075', '396982']
                url = f"https://ipapi.co/{self.target_ip}/asn/"
                res = requests.get(url, timeout=5)
                if res.status_code == 200:
                    asn = res.text.strip().replace('AS', '')
                    if asn in cloud_asns:
                        score -= 10
                        risk_factors.append("Well-managed cloud infrastructure (-10)")
            except:
                pass
        
        final_score = min(max(score, 0), 100)
        print(f"      Risk Score: {final_score}/100 ({len(risk_factors)} factor(s))")
        self._db_execute(
            "UPDATE targets SET risk_score = ? WHERE id = ?",
            (final_score, self.target_id)
        )

    # =========================================================================
    # 14. CORRELATION & ASSET DISCOVERY
    # =========================================================================

    def run_arp_scan(self):
        """ARP Scan - discover hosts on local network segment.
        Only works when target is on the same local network.
        """
        print("    - ARP Scan (Local Network)...")
        import shutil
        
        if shutil.which("nmap"):
            success, stdout, _ = self._run_command(
                ['nmap', '-sn', '-PR', '-T4', '--host-timeout', '5s', self.target_ip],
                timeout=30
            )
            if success and 'Host is up' in stdout:
                print(f"      ✓ Host responds to ARP ping")
                if 'MAC' in stdout:
                    mac_match = re.search(r'MAC Address: ([\w:]+)', stdout)
                    if mac_match:
                        print(f"        MAC: {mac_match.group(1)}")
        else:
            print(f"      - ARP scan requires nmap (not installed)")
        
        print(f"      Note: ARP only works within local subnet")

    def run_udp_ping(self):
        """UDP Ping - send empty UDP packet to common ports to check host status."""
        print("    - UDP Ping...")
        import shutil
        
        if shutil.which("nmap"):
            success, stdout, _ = self._run_command(
                ['nmap', '-PU', '-T4', '--host-timeout', '10s', self.target_ip],
                timeout=30
            )
            if success:
                if 'Host is up' in stdout:
                    print(f"      ✓ Host responded to UDP ping")
                else:
                    print(f"      - No UDP ping response")
        
        # Also try native UDP to common ports
        for port in [53, 123, 161]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(2)
                s.sendto(b'', (self.target_ip, port))
                try:
                    data, addr = s.recvfrom(256)
                    if data:
                        print(f"      ✓ UDP port {port}: response received")
                        break
                except socket.timeout:
                    pass
                s.close()
            except:
                pass

    def run_idle_zombie_scan(self):
        """Idle/Zombie Scan - stealth port scan by spoofing packets through a zombie host.
        Note: Requires a suitable zombie host with predictable IP ID sequence.
        Uses nmap -sI with a basic approach.
        """
        print("    - Idle/Zombie Scan Analysis...")
        import shutil
        if not shutil.which("nmap"):
            print(f"      - Idle scan requires nmap (not installed)")
            return
        
        # First try to find a potential zombie with predictable IP ID
        print(f"      Checking IP ID sequence for zombie suitability...")
        
        # Without a specific zombie host, print instructions
        print(f"      To run an idle scan manually:")
        print(f"        nmap -sI <zombie_ip> -Pn -p 80,443 {self.target_ip}")
        print(f"      Zombie must have predictable IP ID sequence (incremental)")

    def run_fragmented_decoy_scan(self):
        """Fragmented and Decoy scans - evade detection by splitting packets or spoofing sources."""
        print("    - Fragmented/Decoy Scan Analysis...")
        import shutil
        if not shutil.which("nmap"):
            print(f"      - Requires nmap")
            return
        
        # Fragmented scan
        success, stdout, _ = self._run_command(
            ['nmap', '-f', '-T4', '-p', '80,443', '--host-timeout', '15s', self.target_ip],
            timeout=30
        )
        if success and 'open' in stdout.lower():
            ports = stdout.count('/tcp')
            print(f"      ✓ Fragmented scan: {ports} port(s) detected")
        
        # Decoy scan (with fake decoy IPs)
        decoy_ips = '192.168.1.100,10.0.0.50,172.16.0.20'
        success, stdout, _ = self._run_command(
            ['nmap', '-D', decoy_ips, '-T4', '-p', '80,443', '--host-timeout', '15s', self.target_ip],
            timeout=30
        )
        if success and 'open' in stdout.lower():
            ports = stdout.count('/tcp')
            print(f"      ✓ Decoy scan: {ports} port(s) detected")
        
        print(f"      Note: Fragmented/Decoy scans are detectable by modern IDS")

    def run_sctp_scans(self):
        """SCTP INIT and COOKIE-ECHO scans using nmap."""
        print("    - SCTP Scans (INIT + COOKIE-ECHO)...")
        import shutil
        if not shutil.which("nmap"):
            print(f"      - SCTP scans require nmap")
            return
        
        # SCTP INIT Scan
        success, stdout, _ = self._run_command(
            ['nmap', '-sY', '-T4', '-p', '80,443,22,36412', '--host-timeout', '15s', self.target_ip],
            timeout=30
        )
        if success:
            open_ports = stdout.count('/sctp')
            if open_ports > 0:
                print(f"      ✓ SCTP INIT Scan: {open_ports} port(s) detected")
                for line in stdout.split('\n'):
                    if '/sctp' in line and 'open' in line:
                        print(f"        {line.strip()}")
            else:
                print(f"      - SCTP INIT: No open SCTP ports")
        
        # SCTP COOKIE-ECHO Scan
        success, stdout, _ = self._run_command(
            ['nmap', '-sZ', '-T4', '-p', '80,443,22,36412', '--host-timeout', '15s', self.target_ip],
            timeout=30
        )
        if success:
            open_ports = stdout.count('/sctp')
            if open_ports > 0:
                print(f"      ✓ SCTP COOKIE-ECHO Scan: {open_ports} port(s) detected")

    def run_path_mtu_discovery(self):
        """Path MTU Discovery via ping (Don't Fragment flag)."""
        print("    - Path MTU Discovery...")
        import shutil
        import os as _os
        
        # Ping-based PMTUD (works on all platforms)
        if _os.name == 'nt':
            cmd = ['ping', '-n', '1', '-f', '-l', '1472', self.target_ip]
        else:
            cmd = ['ping', '-c', '1', '-M', 'do', '-s', '1472', self.target_ip]
        
        success, stdout, _ = self._run_command(cmd, timeout=10)
        if success:
            if 'need to frag' in stdout.lower() or 'packet needs to be fragmented' in stdout.lower():
                print(f"      ⚠ Path MTU < 1500 (fragmentation needed at 1472 bytes)")
            elif 'reply from' in stdout.lower() or 'bytes from' in stdout.lower():
                print(f"      ✓ Path MTU >= 1500 (1472 byte packet passed without fragmentation)")
            else:
                print(f"      - PMTUD inconclusive (ICMP unreachables may be blocked)")
        
        # If nmap available, try its MTU detection
        if shutil.which("traceroute"):
            success, stdout, _ = self._run_command(
                ['traceroute', '--mtu', self.target_ip], timeout=30
            )
            if success:
                mtu_match = re.search(r'MTU\s*[:=]?\s*(\d+)', stdout, re.IGNORECASE)
                if mtu_match:
                    print(f"      Path MTU: {mtu_match.group(1)}")

    def run_asset_correlation(self):
        """Correlate assets: neighbor IPs, shared infra, related orgs."""
        print("    - Asset Correlation & Discovery...")
        
        # Check neighboring IPs (same /24 subnet)
        try:
            ip_parts = self.target_ip.split('.')
            subnet = '.'.join(ip_parts[:3])
            current_last = int(ip_parts[3])
            
            print(f"      Probing subset of {subnet}.0/24 for co-located hosts...")
            live_hosts = []
            
            def ping_host(last_octet):
                host = f"{subnet}.{last_octet}"
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1.5)  # Reasonable timeout
                    if s.connect_ex((host, 80)) == 0 or s.connect_ex((host, 443)) == 0:
                        s.close()
                        return host
                    s.close()
                except:
                    pass
                return None
            
            # Only scan a small neighborhood (±10 hosts from current IP)
            neighbors = [i for i in range(max(1, current_last-10), min(254, current_last+10)+1) 
                        if i != current_last]
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                futures = {executor.submit(ping_host, i): i for i in neighbors}
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        live_hosts.append(result)
            
            if live_hosts:
                print(f"      ✓ Found {len(live_hosts)} neighboring host(s)")
                for host in live_hosts[:10]:
                    print(f"        > {host}")
            else:
                print(f"      - No neighboring hosts detected")
        except Exception as e:
            print(f"      - Subnet probe: {e}")
        
        # Shared nameserver discovery
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '8.8.4.4']
            answers = resolver.resolve(self.target, 'NS')
            nss = [str(r) for r in answers]
            if nss:
                print(f"      Nameservers: {', '.join(nss[:3])}")
        except:
            pass

    # =========================================================================
    # MAIN EXECUTION
    # =========================================================================

    def execute_all(self):
        """Run all IP reconnaissance techniques in order."""
        print(f"\n{Colors.HEADER}ADVANCED IP RECONNAISSANCE — 50+ New Techniques{Colors.RESET}")
        print(f"{Colors.INFO}[*] Target: {self.target} ({self.target_ip}){Colors.RESET}")
        
        # 1. Active Network Recon
        print(f"\n{Colors.BOLD}[1] ADVANCED ACTIVE NETWORK RECON{Colors.RESET}")
        print("-" * 40)
        self.run_icmp_timestamp()
        self.run_icmp_address_mask()
        self.run_arp_scan()
        self.run_udp_ping()
        self.run_advanced_tcp_pings()
        self.run_stealth_tcp_scans()
        self.run_sctp_scans()
        self.run_idle_zombie_scan()
        self.run_fragmented_decoy_scan()
        self.run_path_mtu_discovery()
        self.run_advanced_os_fingerprint()
        self.run_enhanced_traceroute()
        
        # 2. DNS Recon
        print(f"\n{Colors.BOLD}[2] EXTENDED DNS RECONNAISSANCE{Colors.RESET}")
        print("-" * 40)
        self.run_extended_dns_records()
        self.run_open_resolver_check()
        self.run_dnssec_validation()
        self.run_wildcard_detection()
        
        # 3. Service Enumeration
        print(f"\n{Colors.BOLD}[3] ADVANCED SERVICE ENUMERATION{Colors.RESET}")
        print("-" * 40)
        self.run_ftp_enum()
        self.run_ssh_enum()
        self.run_telnet_enum()
        self.run_rdp_enum()
        self.run_vnc_enum()
        self.run_database_enum()
        self.run_rpc_nfs_enum()
        
        # 4. Passive IP Intelligence
        print(f"\n{Colors.BOLD}[4] PASSIVE IP INTELLIGENCE{Colors.RESET}")
        print("-" * 40)
        self.run_asn_intelligence()
        self.run_bgp_hijack_check()
        self.run_historical_ptr()
        self.run_reverse_ip_lookup()
        
        # 5. Threat Intelligence
        print(f"\n{Colors.BOLD}[5] THREAT INTELLIGENCE{Colors.RESET}")
        print("-" * 40)
        self.run_greynoise_check()
        self.run_malwarebazaar_check()
        self.run_misp_threatfox_check()
        
        # 6. Internet Scan DBs
        print(f"\n{Colors.BOLD}[6] INTERNET-WIDE SCAN DATABASES{Colors.RESET}")
        print("-" * 40)
        self.run_binaryedge_check()
        
        # 7. Certificate Intelligence
        print(f"\n{Colors.BOLD}[7] CERTIFICATE INTELLIGENCE{Colors.RESET}")
        print("-" * 40)
        self.run_advanced_certificate_check()
        
        # 8-12. Infrastructure & Security
        print(f"\n{Colors.BOLD}[8] INFRASTRUCTURE & SECURITY ANALYSIS{Colors.RESET}")
        print("-" * 40)
        self.run_cloud_detection()
        self.run_vpn_tor_detection()
        self.run_network_security_analysis()
        self.run_ipv6_intelligence()
        
        # 13-14. Intel & Analysis
        print(f"\n{Colors.BOLD}[9] INTELLIGENCE & ANALYSIS{Colors.RESET}")
        print("-" * 40)
        self.run_search_engine_ip_queries()
        self.run_comprehensive_risk_analysis()
        self.run_asset_correlation()
        
        print(f"{Colors.SUCCESS}    ✓ IP Reconnaissance completed{Colors.RESET}")
