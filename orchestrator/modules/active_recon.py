"""
Active Reconnaissance Module
Handles intrusive scanning techniques including Port Scanning, Directory Busting, and Tech Detection.

DSA Optimizations:
- Tuple/frozenset for immutable data
- __slots__ for memory efficiency
- Batch database inserts
"""

import socket
import ssl
import concurrent.futures
import subprocess
import requests
import random
import os
from config import config, Colors

# User Agents for evasion (tuple - immutable, memory efficient)
USER_AGENTS = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1'
)

# Common ports - tuple for O(1) membership check on sorted data
COMMON_PORTS = (21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8000, 8080, 8443)

# HTTP/HTTPS port sets for O(1) lookup
HTTP_PORTS = frozenset({80, 8080, 8000})
HTTPS_PORTS = frozenset({443, 8443})

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

class ActiveRecon:
    """
    Encapsulates all active (intrusive) reconnaissance logic.
    DSA: Uses __slots__ for memory efficiency.
    """
    
    __slots__ = ('target', 'target_id', 'db', '_port_batch')
    
    def __init__(self, target: str, target_id: int, db_manager):
        self.target = target
        self.target_id = target_id
        self.db = db_manager
        self._port_batch = []  # Batch for single DB commit

    def run_ping(self):
        """Check if host is up using ICMP ping."""
        print("[+] Running Ping check...")
        param = '-n' if os.name == 'nt' else '-c'
        command = ['ping', param, '1', self.target]
        result = subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        status = "UP" if result == 0 else "DOWN"
        print(f"    - Status: {status}")

    def run_nmap(self):
        """Perform port scanning using Nmap or native socket fallback."""
        print("[+] Running Port Scan & Banner Grabbing...")
        nmap_available = False
        try:
            subprocess.run(["nmap", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            nmap_available = True
        except (FileNotFoundError, subprocess.CalledProcessError):
            nmap_available = False

        if nmap_available:
            self._run_nmap_scan()
        else:
            self._run_native_scan()

    def _run_nmap_scan(self):
        """Internal method to run Nmap."""
        try:
            print("    - Mode: Nmap (Active)")
            cmd = ["nmap", "-F", "-sV", self.target]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if self.db.connect():
                cursor = self.db.conn.cursor()
                for line in result.stdout.split('\n'):
                    if "/tcp" in line and "open" in line:
                        parts = line.split()
                        port = int(parts[0].split('/')[0])
                        service = parts[2] if len(parts) > 2 else "unknown"
                        version = " ".join(parts[3:]) if len(parts) > 3 else ""
                        cursor.execute("INSERT INTO ports (target_id, port, service, version, state) VALUES (?, ?, ?, ?, 'open')", 
                                       (self.target_id, port, service, version))
                self.db.conn.commit()
                self.db.close()
        except Exception as e:
            print(f"[!] Nmap Error: {e}")

    def _run_native_scan(self):
        """Internal method to run native python socket scan."""
        print("    - Mode: Native Socket Scan (Fallback with Banner Grabbing)")
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8000, 8080, 8443]
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0) # Faster timeout
                result = sock.connect_ex((self.target, port))
                
                banner = ""
                service = "unknown"
                
                if result == 0:
                    # Improved Banner Grab
                    try:
                        if port in [80, 8080, 8000]:
                            req = f"GET / HTTP/1.1\r\nHost: {self.target}\r\nUser-Agent: {random.choice(USER_AGENTS)}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
                            sock.send(req.encode())
                        elif port in [443, 8443]:
                            context = ssl.create_default_context()
                            context.check_hostname = False
                            context.verify_mode = ssl.CERT_NONE
                            with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                                    req = f"GET / HTTP/1.1\r\nHost: {self.target}\r\nUser-Agent: {random.choice(USER_AGENTS)}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
                                    ssock.send(req.encode())
                                    banner_data = ssock.recv(1024).decode('utf-8', errors='ignore').strip()
                                    banner = banner_data.split('\n')[0][:50] if banner_data else ""
                                    service = "https"
                                    return (port, service, banner)
                        else:
                            sock.send(b'Hello\r\n')
                            banner_data = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                            banner = banner_data.split('\n')[0][:50] if banner_data else ""

                        if not banner:
                            banner_data = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                            banner = banner_data.split('\n')[0][:50] if banner_data else ""
                    except:
                        pass
                    
                    try:
                        service = socket.getservbyport(port)
                    except:
                        pass
                    
                    sock.close()
                    return (port, service, banner)
                sock.close()
            except:
                pass
            return None

        max_threads = 50
        print(f"{Colors.INFO}[+] Running Port Scan (Top {len(common_ports)} ports)...{Colors.RESET}")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = [executor.submit(scan_port, p) for p in common_ports]
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    open_ports.append(res)
                    print(f"{Colors.SUCCESS}    ✓ Found open port: {res[0]} ({res[1]}){Colors.RESET}")
                    if res[2]:
                        print(f"{Colors.INFO}      Banner: {res[2]}{Colors.RESET}")

        if not open_ports:
            print(f"{Colors.WARNING}    [-] No open ports found{Colors.RESET}")
        
        if open_ports and self.db.connect():
            cursor = self.db.conn.cursor()
            for p, s, b in open_ports:
                    cursor.execute("INSERT INTO ports (target_id, port, service, version, state) VALUES (?, ?, ?, ?, 'open')", 
                                (self.target_id, p, s, b))
            self.db.conn.commit()
            self.db.close()

    def run_dirb_lite(self):
        """Run lightweight directory brute-forcing."""
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
                req_headers = headers.copy()
                req_headers['User-Agent'] = random.choice(USER_AGENTS)
                
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

    def run_extended_web_recon(self):
        """Check for security headers and analyze robots.txt."""
        print("[+] Running Security Header & Robots Analysis...")
        try:
            requests.packages.urllib3.disable_warnings()
            res = requests.get(f"https://{self.target}", timeout=5, verify=False)
            
            headers = res.headers
            missing_headers = []
            
            if 'Strict-Transport-Security' not in headers: missing_headers.append('HSTS')
            if 'Content-Security-Policy' not in headers: missing_headers.append('CSP')
            if 'X-Frame-Options' not in headers: missing_headers.append('X-Frame-Options')
            
            if self.db.connect():
                cursor = self.db.conn.cursor()
                for mh in missing_headers:
                    cursor.execute("""
                        INSERT INTO findings (target_id, title, severity, description, url)
                        VALUES (?, ?, 'Low', ?, ?)
                    """, (self.target_id, f"Missing Header: {mh}", f"The site is missing the {mh} security header.", f"https://{self.target}"))
                self.db.conn.commit()
                self.db.close()
                if missing_headers:
                    print(f"    - Missing Headers: {', '.join(missing_headers)}")

            res_rob = requests.get(f"https://{self.target}/robots.txt", timeout=5, verify=False)
            if res_rob.status_code == 200:
                print("    - Robots.txt found")
                for line in res_rob.text.splitlines():
                    if "Disallow:" in line:
                        path = line.split(":", 1)[1].strip()
                        if self.db.connect():
                            cursor = self.db.conn.cursor()
                            cursor.execute("INSERT INTO directories (target_id, path, status_code) VALUES (?, ?, ?)",
                                          (self.target_id, f"{path} [ROBOTS]", 200))
                            self.db.conn.commit()
                            self.db.close()
        except Exception as e:
            print(f"    [!] Extended Recon failed: {e}")

    def run_tech_detect(self):
        """Identify web technologies using advanced TechDetector."""
        print(f"{Colors.INFO}[+] Detecting Technologies (Enhanced)...{Colors.RESET}")
        try:
            from modules.tech_detector import TechDetector
            
            requests.packages.urllib3.disable_warnings()
            
            # Fetch target page once
            try:
                res = requests.get(
                    f"https://{self.target}", 
                    timeout=8, 
                    verify=False,
                    headers=get_random_headers(self.target)
                )
            except:
                return

            detector = TechDetector(self.target, self.target_id, self.db)
            
            # Run analysis
            detector.analyze(res)
            
            # Save results
            count = detector.save_results()
            if count > 0:
                print(f"{Colors.SUCCESS}    ✓ Identified {count} new technologies{Colors.RESET}")
            else:
                print(f"{Colors.INFO}    - No new technologies identified{Colors.RESET}")
                
        except Exception as e:
            print(f"{Colors.WARNING}    [!] Tech detection error: {e}{Colors.RESET}")
