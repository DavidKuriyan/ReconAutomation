"""
Active Reconnaissance Module
Handles intrusive scanning techniques including Port Scanning, Directory Busting, and Tech Detection.
Extended with: SYN Scan, UDP Scan, OS Fingerprinting, DNS Zone Transfer,
SNMP/SMB/LDAP/NTP Enumeration, expanded port scanning, enhanced SMTP enumeration.

DSA Optimizations:
- Tuple/frozenset for immutable data
- __slots__ for memory efficiency
- Batch database inserts
"""

import socket
import ssl
import time
import concurrent.futures
import subprocess
import requests
import os
import re
import json
from config import config, Colors
from utils import get_random_user_agent as _get_ua, get_random_headers as _get_random_headers, check_tool as _check_tool

# TCP/UDP ports loaded from config (config-driven)
COMMON_PORTS = tuple(int(p) for p in config.COMMON_TCP_PORTS.split(',') if p.strip())
UDP_PORTS = tuple(int(p) for p in config.COMMON_UDP_PORTS.split(',') if p.strip())

# HTTP/HTTPS port sets loaded from config (config-driven)
HTTP_PORTS = frozenset(int(p) for p in config.HTTP_PORTS.split(',') if p.strip())
HTTPS_PORTS = frozenset(int(p) for p in config.HTTPS_PORTS.split(',') if p.strip())

# Service fingerprints for banner-based version detection
SERVICE_FINGERPRINTS = {
    'ssh': (22, [r'SSH-\d+\.\d+', r'OpenSSH', r'Dropbear']),
    'ftp': (21, [r'FTP', r'220.*FTP', r'Pure-FTPd', r'vsFTPd', r'ProFTPD', r'FileZilla']),
    'smtp': (25, [r'ESMTP', r'SMTP', r'Postfix', r'Exim', r'Sendmail', r'Microsoft ESMTP']),
    'http': (80, [r'HTTP/\d\.\d', r'Apache', r'nginx', r'IIS', r'Cloudflare']),
    'mysql': (3306, [r'mysql', r'MariaDB', r'5\.\d+\.\d+']),
    'rdp': (3389, [r'RDP', r'MS-Terminal', r'rdp']),
    'pop3': (110, [r'POP3', r'Ready', r'Dovecot']),
    'imap': (143, [r'IMAP', r'Dovecot', r'Ready']),
}


class ActiveRecon:
    """
    Encapsulates all active (intrusive) reconnaissance logic.
    DSA: Uses __slots__ for memory efficiency.
    """

    __slots__ = ('target', 'target_id', 'db')

    def __init__(self, target: str, target_id: int, db_manager):
        self.target = target
        self.target_id = target_id
        self.db = db_manager

    # =========================================================================
    # DATABASE HELPERS
    # =========================================================================

    def _db_execute(self, query, params=()):
        """Execute a database query with auto-connect/close."""
        if not self.db.connect():
            return None
        try:
            cursor = self.db.conn.cursor()
            cursor.execute(query, params)
            self.db.conn.commit()
            return cursor
        except Exception as e:
            return None
        finally:
            self.db.close()

    def _db_save_finding(self, title, severity='Info', description=''):
        """Save a finding to the database."""
        self._db_execute(
            "INSERT INTO findings (target_id, title, severity, description, url) VALUES (?, ?, ?, ?, ?)",
            (self.target_id, title, severity, description, f"https://{self.target}")
        )

    def _run_command(self, cmd: list, timeout: int = 60) -> tuple:
        """Run an external command with timeout.
        
        Uses a list-based command (shell=False) to avoid shell injection.
        """
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                                    shell=False)
            return True, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out"
        except FileNotFoundError:
            return False, "", f"Command not found: {cmd[0] if cmd else 'empty'}"
        except Exception as e:
            return False, "", str(e)

    # =========================================================================
    # 1. PING SWEEP
    # =========================================================================

    def run_ping(self):
        """Check if host is up using ICMP ping."""
        print("[+] Running Ping check...")
        param = '-n' if os.name == 'nt' else '-c'
        command = ['ping', param, '1', self.target]
        success, stdout, _ = self._run_command(command, timeout=15)
        # ping returns 0 on success, non-zero on failure
        is_up = success and ('TTL=' in stdout.upper() or 'reply from' in stdout.lower() or 'bytes from' in stdout.lower())
        status = "UP" if is_up else "DOWN"
        print(f"    - Status: {status}")

    # =========================================================================
    # 2. TCP CONNECT / SYN / UDP SCAN + VERSION DETECTION + OS FINGERPRINTING
    # =========================================================================

    def run_nmap(self):
        """Perform comprehensive port scanning using Nmap or native socket fallback.
        Includes: TCP Connect, SYN scan, UDP scan, OS fingerprinting, version detection."""
        print("[+] Running Enhanced Port Scan (TCP + UDP + OS Detection)...")
        nmap_available = _check_tool('nmap')

        if nmap_available:
            self._run_enhanced_nmap_scan()
        else:
            self._run_native_tcp_scan()
            self._run_native_udp_scan()
            self.run_os_fingerprint()

    def _run_enhanced_nmap_scan(self):
        """Run Nmap with all enhanced options: SYN, UDP, OS, version detection."""
        try:
            print("    - Mode: Nmap Enhanced (-sS -sU -O -sV -T4)")
            cmd = ["nmap", "-sS", "-sU", "-O", "-sV", "-T4", "--top-ports", "200", self.target]
            success, stdout, stderr = self._run_command(cmd, timeout=300)

            if not success:
                print(f"    [!] Nmap failed: {stderr}")
                # Fallback to basic nmap
                cmd = ["nmap", "-sV", "-F", self.target]
                success, stdout, stderr = self._run_command(cmd, timeout=120)

            if success:
                self._parse_nmap_output(stdout)
        except Exception as e:
            print(f"    [!] Nmap Error: {e}")

    def _parse_nmap_output(self, output):
        """Parse Nmap output for ports, services, OS info."""
        # Parse ports
        if self.db.connect():
            try:
                cursor = self.db.conn.cursor()
                for line in output.split('\n'):
                    if "/tcp" in line and "open" in line:
                        parts = line.split()
                        port = int(parts[0].split('/')[0])
                        service = parts[2] if len(parts) > 2 else "unknown"
                        version = " ".join(parts[3:]) if len(parts) > 3 else ""
                        cursor.execute("INSERT OR IGNORE INTO ports (target_id, port, protocol, service, version, state) VALUES (?, ?, 'tcp', ?, ?, 'open')",
                                       (self.target_id, port, service, version))
                        print(f"    ✓ Port {port}/tcp: {service} {version}")
                    elif "/udp" in line and "open" in line:
                        parts = line.split()
                        port = int(parts[0].split('/')[0])
                        service = parts[2] if len(parts) > 2 else "unknown"
                        version = " ".join(parts[3:]) if len(parts) > 3 else ""
                        cursor.execute("INSERT OR IGNORE INTO ports (target_id, port, protocol, service, version, state) VALUES (?, ?, 'udp', ?, ?, 'open')",
                                       (self.target_id, port, service, version))
                        print(f"    ✓ Port {port}/udp: {service} {version}")

                    # Parse OS detection
                    if "OS details:" in line:
                        os_info = line.split("OS details:")[1].strip()
                        self._db_save_finding(f"OS Detected: {os_info}", "Info", f"OS Fingerprint: {os_info}")

                self.db.conn.commit()
            except Exception as e:
                print(f"    [!] Parse error: {e}")
            finally:
                self.db.close()

    def _run_native_tcp_scan(self):
        """Native TCP connect scan with extended port list and banner grabbing."""
        print("    - Mode: Native TCP Connect Scan")
        open_ports = []

        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.8)
                result = sock.connect_ex((self.target, port))

                banner = ""
                service = "unknown"

                if result == 0:
                    # Banner grabbing with protocol-specific probes
                    try:
                        if port in HTTP_PORTS:
                            req = f"GET / HTTP/1.1\r\nHost: {self.target}\r\nUser-Agent: {_get_ua()}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
                            sock.send(req.encode())
                        elif port in HTTPS_PORTS:
                            context = ssl.create_default_context()
                            context.check_hostname = False
                            context.verify_mode = ssl.CERT_NONE
                            ssock = context.wrap_socket(sock, server_hostname=self.target)
                            try:
                                req = f"GET / HTTP/1.1\r\nHost: {self.target}\r\nUser-Agent: {_get_ua()}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
                                ssock.send(req.encode())
                                banner_data = ssock.recv(4096).decode('utf-8', errors='ignore').strip()
                                banner = banner_data.split('\n')[0][:100] if banner_data else ""
                                service = "https"
                            finally:
                                ssock.close()
                            return (port, service, banner, "tcp")
                        else:
                            # Generic probe
                            sock.send(b'HELP\r\n')
                            banner_data = sock.recv(2048).decode('utf-8', errors='ignore').strip()
                            banner = banner_data.split('\n')[0][:100] if banner_data else ""
                            if not banner:
                                sock.send(b'\r\n')
                                banner_data = sock.recv(2048).decode('utf-8', errors='ignore').strip()
                                banner = banner_data.split('\n')[0][:100] if banner_data else ""
                    except (socket.timeout, OSError):
                        pass

                    try:
                        service = socket.getservbyport(port)
                    except (OSError, OverflowError):
                        pass

                    # Enhanced version extraction from banners
                    version = self._extract_version_from_banner(port, banner, service)
                    sock.close()
                    return (port, service, version, banner, "tcp")

                sock.close()
            except (socket.timeout, OSError, ConnectionError):
                pass
            return None

        print(f"    - Scanning {len(COMMON_PORTS)} common TCP ports...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(scan_port, p) for p in COMMON_PORTS]
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    open_ports.append(res)
                    print(f"    ✓ Port {res[0]}/tcp: {res[1]} {res[2]}")

        if not open_ports:
            print("    - No open TCP ports found")
        else:
            print(f"    - Found {len(open_ports)} open TCP ports")

        if open_ports and self.db.connect():
            try:
                cursor = self.db.conn.cursor()
                for p, s, v, b, proto in open_ports:
                    cursor.execute("INSERT OR IGNORE INTO ports (target_id, port, protocol, service, version, state) VALUES (?, ?, ?, ?, ?, 'open')",
                                   (self.target_id, p, proto, s, v or b))
                self.db.conn.commit()
            except Exception as e:
                print(f"    [!] DB save error (TCP ports): {e}")
            finally:
                self.db.close()

    def _run_native_udp_scan(self):
        """Native UDP port scanning."""
        print("    - Mode: Native UDP Scan")
        open_ports = []

        def scan_udp_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(1.0)

                # Send empty UDP datagram
                sock.sendto(b'', (self.target, port))

                # Wait for response (ICMP unreachable = closed, any data = open)
                try:
                    data, addr = sock.recvfrom(1024)
                    sock.close()
                    if data:
                        return (port, socket.getservbyport(port) if port < 1024 else "unknown", "udp")
                except socket.timeout:
                    # No response - port might be open/filtered
                    pass

                sock.close()
            except (socket.timeout, OSError):
                pass
            return None

        print(f"    - Scanning {len(UDP_PORTS)} common UDP ports...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(scan_udp_port, p) for p in UDP_PORTS]
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    open_ports.append(res)
                    print(f"    ✓ Port {res[0]}/udp: {res[1]}")

        if open_ports and self.db.connect():
            try:
                cursor = self.db.conn.cursor()
                for p, s, proto in open_ports:
                    cursor.execute("INSERT OR IGNORE INTO ports (target_id, port, protocol, service, version, state) VALUES (?, ?, ?, '', 'open')",
                                   (self.target_id, p, proto, s))
                self.db.conn.commit()
            except Exception as e:
                print(f"    [!] DB save error (TCP ports): {e}")
            finally:
                self.db.close()

        if not open_ports:
            print("    - No open UDP ports detected")

    def _extract_version_from_banner(self, port, banner, service):
        """Extract software version from banner text."""
        if not banner:
            return ""

        # Check known service fingerprints
        for svc_name, (svc_port, patterns) in SERVICE_FINGERPRINTS.items():
            if port == svc_port or svc_name in service.lower():
                for pattern in patterns:
                    match = re.search(pattern, banner, re.IGNORECASE)
                    if match:
                        return match.group(0)

        # Generic version extraction (look for version patterns)
        version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', banner)
        if version_match:
            return f"{service} {version_match.group(1)}"

        return banner[:80]

    # =========================================================================
    # 3. OS FINGERPRINTING (Passive via TTL/Window + nmap fallback)
    # =========================================================================

    def run_os_fingerprint(self):
        """Passive OS fingerprinting using TTL analysis via ping."""
        print("    - Passive OS Fingerprinting via TTL analysis...")
        # Use ping to get TTL (works on all platforms without special privileges)
        param = '-n' if os.name == 'nt' else '-c'
        success, stdout, _ = self._run_command(['ping', param, '1', self.target], timeout=10)
        if success:
            ttl_match = re.search(r'TTL=(\d+)', stdout, re.IGNORECASE)
            if ttl_match:
                ttl = int(ttl_match.group(1))
                os_guess = self._guess_os_by_ttl(ttl)
                print(f"    ✓ Detected OS: {os_guess} (TTL={ttl})")
                self._db_save_finding(f"OS Detected: {os_guess}", "Info", f"Passive fingerprint via TTL={ttl}")
            else:
                print("    - Could not determine TTL from ping")
        else:
            print("    - Could not execute ping (tool may not be available)")

        # Try nmap -O as fallback for deeper analysis
        if _check_tool('nmap'):
            success, stdout, _ = self._run_command(['nmap', '-O', '--osscan-guess', self.target], timeout=120)
            if success:
                for line in stdout.split('\n'):
                    if 'OS details:' in line or 'Aggressive OS' in line:
                        os_info = line.split(':', 1)[1].strip() if ':' in line else line.strip()
                        print(f"    ✓ Detected OS: {os_info}")
                        self._db_save_finding(f"OS Detected: {os_info}", "Info", f"Nmap OS fingerprint")

    def _guess_os_by_ttl(self, ttl):
        """Guess OS based on initial TTL value."""
        if ttl <= 32:
            return "Router / Embedded (TTL < 32)"
        elif ttl <= 64:
            return "Linux / Unix / macOS (TTL ~64)"
        elif ttl <= 128:
            return "Windows (TTL ~128)"
        elif ttl <= 255:
            return "Solaris / AIX (TTL ~255)"
        return "Unknown"

    # =========================================================================
    # 4. DNS ZONE TRANSFER ATTEMPT
    # =========================================================================

    def run_dns_zone_transfer(self):
        """Attempt DNS zone transfer (AXFR) from authoritative nameservers."""
        print("[+] Running DNS Zone Transfer Attempt...")
        try:
            import dns.resolver
            import dns.query
            import dns.zone
        except ImportError:
            print("    [!] dnspython not installed, skipping zone transfer")
            return

        try:
            # Get authoritative nameservers
            answers = dns.resolver.resolve(self.target, 'NS')
            nameservers = [str(rdata) for rdata in answers]

            if not nameservers:
                print("    [!] No nameservers found")
                return

            print(f"    - Found {len(nameservers)} nameserver(s)")

            for ns in nameservers[:3]:  # Try first 3 NS
                try:
                    ns_ip = socket.gethostbyname(ns)
                    print(f"    - Attempting AXFR from {ns} ({ns_ip})...")

                    zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, self.target, timeout=5, lifetime=10))

                    if zone and zone.nodes:
                        records = list(zone.nodes.keys())[:50]
                        record_count = len(zone.nodes)
                        print(f"      ⚠ ZONE TRANSFER SUCCEEDED! {record_count} records from {ns}")
                        self._db_save_finding(f"DNS Zone Transfer Allowed: {ns}",
                                              "Critical",
                                              f"Zone transfer allowed from {ns} ({ns_ip}). {record_count} records exposed.")

                        # Save to db
                        if self.db.connect():
                            try:
                                cursor = self.db.conn.cursor()
                                cursor.execute("""INSERT INTO dns_zone_info
                                    (target_id, nameserver, zone_transfer_allowed, record_count, records_snippet)
                                    VALUES (?, ?, 1, ?, ?)""",
                                    (self.target_id, ns, record_count, str(records[:20])))
                                self.db.conn.commit()
                            except Exception as db_err:
                                print(f"      [!] DB save error (zone transfer): {db_err}")
                            finally:
                                self.db.close()
                    else:
                        print(f"      - Zone transfer denied from {ns} (empty response)")

                except dns.exception.DNSException as e:
                    print(f"      - Zone transfer denied from {ns}: {e}")
                    if self.db.connect():
                        try:
                            cursor = self.db.conn.cursor()
                            cursor.execute("""INSERT INTO dns_zone_info
                                (target_id, nameserver, zone_transfer_allowed, error)
                                VALUES (?, ?, 0, ?)""",
                                (self.target_id, ns, str(e)[:200]))
                            self.db.conn.commit()
                        except Exception as db_err:
                            print(f"      [!] DB save error (zone transfer deny): {db_err}")
                        finally:
                            self.db.close()
                except Exception as e:
                    print(f"      - Error with {ns}: {e}")

        except Exception as e:
            print(f"    [!] Zone transfer error: {e}")

    # =========================================================================
    # 5. SNMP ENUMERATION (basic socket probe)
    # =========================================================================

    def run_snmp_enum(self):
        """Basic SNMP enumeration via socket probe."""
        print("[+] Running SNMP Enumeration...")
        community_strings = ['public', 'private', 'manager', 'snmp']

        for community in community_strings:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)

                # Build a simple SNMP GET-NEXT request for sysDescr (1.3.6.1.2.1.1.1.0)
                # SNMP v1 packet
                pdu = self._build_snmp_request(community)
                sock.sendto(pdu, (self.target, 161))

                data, addr = sock.recvfrom(4096)
                if data:
                    print(f"      ✓ SNMP accessible with community '{community}'")
                    self._db_save_finding(f"SNMP Enumeration: community '{community}' accessible",
                                          "High",
                                          f"SNMP service accessible on {self.target}:161 with community string '{community}'")

                    # Store in db
                    if self.db.connect():
                        try:
                            cursor = self.db.conn.cursor()
                            cursor.execute("""INSERT INTO snmp_info
                                (target_id, host, community_string, accessible)
                                VALUES (?, ?, ?, 1)""",
                                (self.target_id, self.target, community))
                            self.db.conn.commit()
                        except Exception as db_err:
                            print(f"      [!] DB save error (SNMP): {db_err}")
                        finally:
                            self.db.close()
                    return  # Found accessible SNMP
                sock.close()
            except socket.timeout:
                pass
            except OSError:
                pass

        print("    - No accessible SNMP service found")

    def _build_snmp_request(self, community):
        """Build a minimal SNMP GET-NEXT request for sysDescr."""
        # Very basic SNMP v1 packet structure
        pdu = b"\x30"  # Sequence tag
        # Version (0 = v1)
        pdu += b"\x02\x01\x00"
        # Community string
        pdu += b"\x04" + bytes([len(community)]) + community.encode()
        # PDU type (0xA0 = GetNextRequest)
        pdu += b"\xa0\x1c"
        # Request ID
        pdu += b"\x02\x04\x00\x00\x00\x01"
        # Error status
        pdu += b"\x02\x01\x00"
        # Error index
        pdu += b"\x02\x01\x00"
        # Varbind list
        pdu += b"\x30\x0e" + b"\x30\x0c"
        # sysDescr OID: 1.3.6.1.2.1.1.1.0
        pdu += b"\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00"
        pdu += b"\x05\x00"

        # Wrap in sequence with length
        length = len(pdu)
        result = b"\x30" + bytes([length]) + pdu
        return result

    # =========================================================================
    # 6. SMB ENUMERATION (basic socket probe)
    # =========================================================================

    def run_smb_enum(self):
        """Basic SMB enumeration via socket probe."""
        print("[+] Running SMB Enumeration...")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((self.target, 445))

            if result == 0:
                # SMB port open, try to grab banner
                # Send SMBv2 negotiation request
                smb_negotiate = (
                    b"\x00\x00\x00\x2f"  # NetBIOS session size
                    b"\xfe\x53\x4d\x42"  # SMBv2 magic
                    b"\x40\x00"          # Structure size
                    b"\x00\x00\x00\x00"  # Credit charge
                    b"\x00\x00\x00\x00"  # Status
                    b"\x00\x00"          # Command: Negotiate
                    b"\x00\x00"          # Credits
                    b"\x00\x00"          # Flags
                    b"\x00\x00\x00\x00"  # Next command
                    b"\x00\x00\x00\x00"  # Message ID
                    b"\x00\x00\x00\x00"  # Reserved
                    b"\x00\x00\x00\x00"  # Tree ID
                    b"\x00\x00\x00\x00"  # Session ID
                    b"\x00\x00\x00\x00"  # Signature (8 bytes)
                    b"\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00"  # Capabilities
                    b"\x00\x00\x00\x00"  # Client GUID
                    b"\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00"
                    b"\x00\x00"          # Security mode
                    b"\x00\x00"          # Dialect count: 1
                    b"\x02\x02"          # Dialect: SMBv2.0.2
                )

                sock.send(smb_negotiate)
                response = sock.recv(1024)
                sock.close()

                if response and b"\xfe\x53\x4d\x42" in response:
                    print("      ✓ SMB service detected on port 445")
                    self._db_save_finding("SMB Service Detected", "Medium",
                                          f"SMB service running on {self.target}:445. Potential for share enumeration.")

                    if self.db.connect():
                        try:
                            cursor = self.db.conn.cursor()
                            cursor.execute("""INSERT INTO smb_shares
                                (target_id, host, share_name, share_type, accessible)
                                VALUES (?, ?, 'SMB_SERVICE', 'SMB-Port', 1)""",
                                (self.target_id, self.target))
                            self.db.conn.commit()
                        except Exception as db_err:
                            print(f"      [!] DB save error (SMB): {db_err}")
                        finally:
                            self.db.close()
                else:
                    print("      - Port 445 open but SMB not confirmed")
            else:
                print("    - Port 445 closed (no SMB)")

            sock.close()
        except Exception as e:
            print(f"    [!] SMB error: {e}")

    # =========================================================================
    # 7. LDAP ENUMERATION (basic socket probe)
    # =========================================================================

    def run_ldap_enum(self):
        """Basic LDAP enumeration via socket probe."""
        print("[+] Running LDAP Enumeration...")
        for port, ssl_mode in [(389, False), (636, True)]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)

                if ssl_mode:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock, server_hostname=self.target)

                result = sock.connect_ex((self.target, port))

                if result == 0:
                    # Send LDAP bind request (anonymous)
                    ldap_req = (
                        b"\x30\x0c"  # SEQUENCE
                        b"\x02\x01\x01"  # Message ID = 1
                        b"\x60\x07"  # Bind request
                        b"\x02\x01\x02"  # Version 3
                        b"\x04\x00"  # Empty bind DN
                        b"\x80\x00"  # No password
                    )

                    # Prepend LDAP message length
                    ldap_pdu = b"\x30" + bytes([len(ldap_req)]) + ldap_req
                    sock.send(ldap_pdu)
                    response = sock.recv(4096)
                    sock.close()

                    if response:
                        print(f"      ✓ LDAP service detected on port {port}")
                        self._db_save_finding(f"LDAP Service Detected", "Medium",
                                              f"LDAP service running on {self.target}:{port}")

                        if self.db.connect():
                            try:
                                cursor = self.db.conn.cursor()
                                cursor.execute("""INSERT INTO ldap_info
                                    (target_id, server, port, accessible, ssl_supported)
                                    VALUES (?, ?, ?, 1, ?)""",
                                    (self.target_id, self.target, port, 1 if ssl_mode else 0))
                                self.db.conn.commit()
                            except Exception as db_err:
                                print(f"      [!] DB save error (LDAP): {db_err}")
                            finally:
                                self.db.close()
                    else:
                        print(f"      - Port {port} open but no LDAP response")
                sock.close()
            except Exception:
                pass

        print("    - No LDAP service detected")

    # =========================================================================
    # 8. NTP ENUMERATION
    # =========================================================================

    def run_ntp_enum(self):
        """NTP enumeration - query server for monlist and peer info."""
        print("[+] Running NTP Enumeration...")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)

            # NTP version 3 mode 7 (readvar) request packet
            ntp_packet = b"\x17\x00\x03\x2a" + b"\x00" * 8
            sock.sendto(ntp_packet, (self.target, 123))
            data, addr = sock.recvfrom(1024)
            sock.close()

            if data:
                print("      ✓ NTP service detected on port 123")

                # Try monlist (NTP mode 7, opcode 42) - potential DDoS reflection risk
                monlist_packet = b"\x17\x00\x03\x2a" + b"\x00" + bytes([42]) + b"\x00" * 5
                try:
                    sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock2.settimeout(3)
                    sock2.sendto(monlist_packet, (self.target, 123))
                    monlist_data, _ = sock2.recvfrom(4096)
                    sock2.close()

                    monlist_enabled = len(monlist_data) > 100
                    peers = len(monlist_data) // 48 if monlist_enabled else 0
                except (socket.timeout, OSError):
                    monlist_enabled = False
                    peers = 0

                if monlist_enabled:
                    print(f"      ⚠ NTP monlist enabled! {peers} peers exposed. DDoS risk!")
                    self._db_save_finding("NTP Monlist Enabled (DDoS Risk)", "High",
                                          f"NTP monlist query allowed on {self.target}:123. {peers} peers exposed. Do not use this server for NTP.")

                if self.db.connect():
                    try:
                        cursor = self.db.conn.cursor()
                        cursor.execute("""INSERT INTO ntp_info
                            (target_id, server, peers_found, monlist_enabled)
                            VALUES (?, ?, ?, ?)""",
                            (self.target_id, self.target, peers, 1 if monlist_enabled else 0))
                        self.db.conn.commit()
                    except Exception as db_err:
                        print(f"      [!] DB save error (NTP): {db_err}")
                    finally:
                        self.db.close()
            else:
                print("    - No NTP response")
        except socket.timeout:
            print("    - NTP port not responding")
        except Exception as e:
            print(f"    [!] NTP error: {e}")

    # =========================================================================
    # 9. ENHANCED SMTP ENUMERATION
    # =========================================================================

    def run_smtp_enum(self):
        """Enhanced SMTP enumeration: banner, VRFY, EXPN, EHLO capabilities."""
        print("[+] Running Enhanced SMTP Enumeration...")
        try:
            import dns.resolver
            mx_records = dns.resolver.resolve(self.target, 'MX')
        except ImportError:
            mx_records = []

        if not mx_records:
            # Try direct SMTP on port 25
            self._check_smtp_server(self.target)
            return

        for mx in mx_records:
            params = mx.to_text().split()
            server = params[1].rstrip('.')

            if server:
                print(f"    - Checking MX: {server}")
                self._check_smtp_server(server)

    def _check_smtp_server(self, server):
        """Check an SMTP server for banner, user enumeration, and capabilities."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((server, 25))

            # Grab banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            print(f"    - Banner: {banner[:80]}")
            self._db_save_finding(f"SMTP Server: {server}", "Info", f"Banner: {banner[:200]}")

            # EHLO
            sock.send(f"EHLO recon-check\r\n".encode())
            ehlo_response = sock.recv(2048).decode('utf-8', errors='ignore')
            capabilities = set()
            for line in ehlo_response.split('\n'):
                line = line.strip()
                if line.startswith('250-') or line.startswith('250 '):
                    cap = line[4:].strip() if line.startswith('250-') else line[3:].strip()
                    capabilities.add(cap.split(' ')[0])

            print(f"    - Capabilities: {', '.join(list(capabilities)[:10])}")

            # Try VRFY with common usernames
            if 'VRFY' in capabilities:
                print("    - VRFY supported, attempting user enumeration...")
                common_users = ['admin', 'root', 'info', 'contact', 'support', 'sales', 'webmaster']
                for user in common_users[:3]:  # Limit to avoid detection
                    sock.send(f"VRFY {user}\r\n".encode())
                    vrfy_resp = sock.recv(512).decode('utf-8', errors='ignore').strip()
                    if '252' in vrfy_resp or '250' in vrfy_resp:
                        print(f"      ✓ User '{user}' might exist: {vrfy_resp[:80]}")
                        self._db_save_finding(f"SMTP User Found: {user}@{server}", "Medium",
                                              f"VRFY confirms user: {vrfy_resp[:200]}")

            # Try EXPN
            if 'EXPN' in capabilities:
                sock.send(b"EXPN root\r\n")
                expn_resp = sock.recv(512).decode('utf-8', errors='ignore').strip()
                if '252' in expn_resp or '250' in expn_resp:
                    print(f"      ⚠ EXPN succeeded: {expn_resp[:80]}")
                    self._db_save_finding(f"SMTP EXPN Enabled", "Medium",
                                          f"EXPN command allowed on {server}: {expn_resp[:200]}")

            sock.send(b"QUIT\r\n")
            sock.close()

        except Exception as e:
            print(f"    [!] SMTP check failed for {server}: {e}")

    # =========================================================================
    # 10. DIRECTORY BUSTING
    # =========================================================================

    def run_dirb_lite(self):
        """Run lightweight directory brute-forcing."""
        print("[+] Running Directory Busting (Enhanced)...")
        wordlist = [
            'admin', 'login', 'dashboard', 'api', 'uploads', 'images', 'css', 'js', 'config', 'backup', 'db',
            'wordpress', 'robots.txt', '.git', '.env', 'public', 'assets', 'static', 'media', 'files',
            'admin.php', 'login.php', 'config.php', 'wp-admin', 'wp-content', 'shell.php', 'backup.zip',
            'sitemap.xml', 'security.txt', '.well-known', '.well-known/security.txt', 'crossdomain.xml',
            'phpinfo.php', 'info.php', 'test.php'
        ]
        protocol = "https://"
        found_dirs = []
        headers = _get_random_headers(self.target)

        def check_url(path):
            url = f"{protocol}{self.target}/{path}"
            try:
                requests.packages.urllib3.disable_warnings()
                req_headers = headers.copy()
                req_headers['User-Agent'] = _get_ua()

                res = requests.get(url, headers=req_headers, timeout=5, allow_redirects=False, verify=False)

                if "Attention Required! | Cloudflare" in res.text:
                    return None

                if res.status_code in [200, 301, 302, 401, 403, 500]:
                    print(f"    - Found: /{path} [{res.status_code}]")
                    return (f"/{path}", res.status_code)
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
            future_to_url = {executor.submit(check_url, path): path for path in wordlist}
            for future in concurrent.futures.as_completed(future_to_url):
                res = future.result()
                if res:
                    found_dirs.append(res)

        if found_dirs and self.db.connect():
            cursor = self.db.conn.cursor()
            for path, code in found_dirs:
                cursor.execute("INSERT INTO directories (target_id, path, status_code) VALUES (?, ?, ?)",
                               (self.target_id, path, code))
            self.db.conn.commit()
            self.db.close()

    # =========================================================================
    # 11. SECURITY HEADER ANALYSIS
    # =========================================================================

    def run_extended_web_recon(self):
        """Check for security headers and analyze robots.txt / security.txt / sitemap.xml."""
        print("[+] Running Security Header & File Analysis...")
        try:
            requests.packages.urllib3.disable_warnings()
            res = requests.get(f"https://{self.target}", timeout=5, verify=False)

            headers = res.headers
            security_headers = {
                'Strict-Transport-Security': 'HSTS',
                'Content-Security-Policy': 'CSP',
                'X-Frame-Options': 'X-Frame-Options',
                'X-Content-Type-Options': 'X-Content-Type-Options',
                'Referrer-Policy': 'Referrer-Policy',
                'Permissions-Policy': 'Permissions-Policy',
                'X-XSS-Protection': 'X-XSS-Protection',
            }

            present = []
            missing = []
            for hdr, name in security_headers.items():
                if hdr in headers:
                    present.append(name)
                else:
                    missing.append(name)

            if self.db.connect():
                cursor = self.db.conn.cursor()
                for mh in missing:
                    cursor.execute("""INSERT INTO findings (target_id, title, severity, description, url)
                        VALUES (?, ?, 'Low', ?, ?)""",
                        (self.target_id, f"Missing Header: {mh}",
                         f"The site is missing the {mh} security header.", f"https://{self.target}"))
                self.db.conn.commit()
                self.db.close()

            if present:
                print(f"    - Present: {', '.join(present)}")
            if missing:
                print(f"    - Missing: {', '.join(missing)}")

            # Check common files
            common_files = ['robots.txt', 'security.txt', 'sitemap.xml', 'crossdomain.xml', '.well-known/security.txt']
            for file_path in common_files:
                try:
                    fr = requests.get(f"https://{self.target}/{file_path}", timeout=3, verify=False, allow_redirects=False)
                    if fr.status_code == 200:
                        print(f"    - Found: /{file_path} [{fr.status_code}]")
                        self._db_save_finding(f"File Found: /{file_path}", "Info",
                                              f"Accessible file: https://{self.target}/{file_path}")
                except requests.RequestException:
                    pass

        except Exception as e:
            print(f"    [!] Extended Recon failed: {e}")

    # =========================================================================
    # 12. TECH DETECTION
    # =========================================================================

    def run_tech_detect(self):
        """Identify web technologies using advanced TechDetector.
        Probes both HTTP and HTTPS, follows redirects, checks favicon."""
        print(f"{Colors.INFO}[+] Detecting Technologies (Enhanced)...{Colors.RESET}")
        try:
            from modules.tech_detector import TechDetector

            requests.packages.urllib3.disable_warnings()
            headers = _get_random_headers(self.target)

            # Probe multiple URLs: HTTPS, HTTP, www variants
            urls = [
                f"https://{self.target}",
                f"http://{self.target}",
                f"https://www.{self.target}",
            ]

            responses = []
            for url in urls:
                try:
                    res = requests.get(
                        url, timeout=8, verify=False,
                        headers=headers, allow_redirects=False
                    )
                    # Include all non-error responses: redirects (301, 302) still have headers
                    if res.status_code < 400 or res.status_code in [403, 500]:
                        responses.append(res)
                        print(f"    ✓ Probed {url} -> {res.status_code}")
                except requests.exceptions.SSLError:
                    pass  # HTTPS may fail, try HTTP
                except requests.exceptions.ConnectionError:
                    pass
                except Exception:
                    pass

            if not responses:
                print(f"{Colors.WARNING}    [!] Could not reach any URL for {self.target}{Colors.RESET}")
                return

            detector = TechDetector(self.target, self.target_id, self.db)

            # Analyze all successful responses
            for resp in responses:
                detector.analyze(resp)

            # Try favicon analysis on first successful response
            try:
                first_url = responses[0].url
                detector.analyze_favicon(first_url)
            except Exception:
                pass

            # Save technologies and findings
            tech_count, finding_count = detector.save_results()

            if tech_count > 0:
                print(f"{Colors.SUCCESS}    ✓ Identified {tech_count} technologies | {finding_count} findings created{Colors.RESET}")
            else:
                print(f"{Colors.INFO}    - No new technologies identified{Colors.RESET}")

        except Exception as e:
            print(f"{Colors.WARNING}    [!] Tech detection error: {e}{Colors.RESET}")

    def run_traceroute(self):
        """Perform traceroute to map network path between source and target.
        Wraps OS tracert (Windows) / traceroute (Linux/macOS).
        Captures hop IPs and stores route as JSON.
        """
        print("[+] Running Traceroute (Network Path Mapping)...")
        try:
            import json
            
            if os.name == 'nt':
                cmd = ['tracert', '-h', '30', '-w', '3000', self.target]
            else:
                cmd = ['traceroute', '-m', '30', '-w', '3', '-q', '1', self.target]
            
            success, stdout, stderr = self._run_command(cmd, timeout=120)
            
            if success and stdout:
                hops = []
                for line in stdout.split('\n'):
                    line = line.strip()
                    if not line or not line[0].isdigit():
                        continue
                    # Non-capturing groups (?:...) are NOT counted in group index.
                    # Groups: (1)=\d+ (hop), (2)=.+ (host)
                    hop_match = re.match(
                        r'\s*(\d+)\s+'
                        r'(?:\*|<?[\d.]+)\s+ms\s+'
                        r'(?:\*|<?[\d.]+)\s+ms\s+'
                        r'(?:\*|<?[\d.]+)\s+ms\s+'
                        r'(.+)$',
                        line
                    )
                    if hop_match:
                        hop_num = int(hop_match.group(1))
                        hop_ip = hop_match.group(2).strip()
                        # Extract just the IP if format is "hostname (IP)"
                        ip_extract = re.search(r'\(([\d.]+)\)', hop_ip)
                        if ip_extract:
                            hop_ip = ip_extract.group(1)
                        else:
                            # Clean up hostname before IP
                            hop_ip = hop_ip.split()[-1] if ' ' in hop_ip else hop_ip
                        hops.append({'hop': hop_num, 'ip': hop_ip})
                
                if hops:
                    total_hops = len(hops)
                    print(f"    - {total_hops} hops mapped")
                    for hop in hops[:10]:
                        print(f"      Hop {hop['hop']}: {hop['ip']}")
                    if total_hops > 10:
                        print(f"      ... and {total_hops - 10} more hops")
                    
                    if self.db.connect():
                        try:
                            cursor = self.db.conn.cursor()
                            cursor.execute("""INSERT INTO traceroute 
                                (target_id, target_host, hop_count, hops_json, avg_rtt_ms)
                                VALUES (?, ?, ?, ?, 0)""",
                                (self.target_id, self.target, total_hops, json.dumps(hops)))
                            self.db.conn.commit()
                        except Exception as db_err:
                            print(f"    [!] DB error (traceroute): {db_err}")
                        finally:
                            self.db.close()
                else:
                    print("    - Could not parse traceroute output")
            else:
                print(f"    - Traceroute failed: {stderr[:100] if stderr else 'No output'}")
                
        except Exception as e:
            print(f"    [!] Traceroute error: {e}")

    def run_techchecker_api(self):
        """Query TechnologyChecker.io API for comprehensive tech stack detection.
        Integrates external API for broader coverage beyond local signature matching."""
        print(f"{Colors.INFO}[+] Running Tech Checker API...{Colors.RESET}")
        try:
            from modules.tech_detector import TechDetector
            detector = TechDetector(self.target, self.target_id, self.db)
            detector.run_techchecker_api()
        except Exception as e:
            print(f"{Colors.WARNING}    [!] Tech Checker API error: {e}{Colors.RESET}")
