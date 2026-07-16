"""
Geolocation Intelligence Module
Provides IP geolocation, ASN lookup, reverse IP capabilities, and IPinfo integration
"""

import socket
import requests
import sqlite3
import re
from config import config

class GeoIntelligence:
    def __init__(self, target, target_id):
        self.target = target
        self.target_id = target_id
        self.target_ip = None
        
    @staticmethod
    def is_valid_ip(value):
        """Check if a string is a valid IPv4 address"""
        pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
        match = re.match(pattern, value)
        if not match:
            return False
        return all(0 <= int(g) <= 255 for g in match.groups())
    
    def get_target_ip(self):
        """Resolve target domain to IP address. If already an IP, return as-is."""
        if self.is_valid_ip(self.target):
            return self.target
        try:
            ip = socket.gethostbyname(self.target)
            return ip
        except Exception as e:
            print(f"    [!] IP resolution failed: {e}")
            return None
    
    def lookup_ipapi(self, ip):
        """Use ipapi.co for geolocation (free, no API key required)"""
        try:
            url = f"https://ipapi.co/{ip}/json/"
            headers = {'User-Agent': config.USER_AGENT}
            res = requests.get(url, headers=headers, timeout=config.HTTP_TIMEOUT)
            
            if res.status_code == 200:
                data = res.json()
                return {
                    'ip': ip,
                    'country': data.get('country_name', ''),
                    'region': data.get('region', ''),
                    'city': data.get('city', ''),
                    'latitude': data.get('latitude'),
                    'longitude': data.get('longitude'),
                    'isp': data.get('org', ''),
                    'asn': data.get('asn', ''),
                    'asn_org': data.get('org', ''),
                    'timezone': data.get('timezone', '')
                }
        except Exception as e:
            print(f"    [!] ipapi.co lookup failed: {e}")
        return None
    
    def lookup_ipinfo(self, ip):
        """
        Use ipinfo.io for enhanced geolocation (requires API key for higher rate limits).
        Falls back gracefully if no API key is configured.
        """
        try:
            headers = {
                'Authorization': f'Bearer {config.IPINFO_API_KEY}',
                'User-Agent': config.USER_AGENT
            } if config.IPINFO_API_KEY else {
                'User-Agent': config.USER_AGENT
            }
            
            url = f"https://ipinfo.io/{ip}/json"
            res = requests.get(url, headers=headers, timeout=config.HTTP_TIMEOUT)
            
            if res.status_code == 200:
                data = res.json()
                
                # Parse loc (lat,lng) into separate values
                lat, lng = None, None
                loc = data.get('loc', '')
                if loc and ',' in loc:
                    parts = loc.split(',')
                    try:
                        lat = float(parts[0])
                        lng = float(parts[1])
                    except (ValueError, IndexError):
                        pass
                
                # Parse ASN from org field (e.g., "AS15169 Google LLC")
                org = data.get('org', '')
                asn = ''
                if org:
                    asn_match = re.match(r'AS(\d+)', org)
                    if asn_match:
                        asn = f'AS{asn_match.group(1)}'
                
                return {
                    'ip': ip,
                    'country': data.get('country', ''),
                    'region': data.get('region', ''),
                    'city': data.get('city', ''),
                    'latitude': lat,
                    'longitude': lng,
                    'isp': org,  # ipinfo puts ISP/org in 'org' field
                    'asn': asn,
                    'asn_org': org,
                    'timezone': data.get('timezone', ''),
                    'postal': data.get('postal', ''),
                    'hostname': data.get('hostname', ''),
                    'source': 'ipinfo.io'
                }
        except Exception as e:
            print(f"    [!] ipinfo.io lookup failed: {e}")
        return None
    
    def reverse_ip_lookup(self, ip):
        """Find other domains hosted on the same IP"""
        try:
            # Use simple PTR record lookup
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except Exception:
            pass
        return None
    
    def store_geolocation(self, geo_data):
        """Store geolocation data in database"""
        try:
            conn = sqlite3.connect(config.DB_PATH, timeout=30.0)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO geolocation (target_id, ip_address, country, region, city, 
                                        latitude, longitude, isp, organization, asn, asn_org, timezone)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                self.target_id,
                geo_data.get('ip', ''),
                geo_data.get('country', ''),
                geo_data.get('region', ''),
                geo_data.get('city', ''),
                geo_data.get('latitude'),
                geo_data.get('longitude'),
                geo_data.get('isp', ''),
                geo_data.get('isp', ''),
                geo_data.get('asn', ''),
                geo_data.get('asn_org', ''),
                geo_data.get('timezone', '')
            ))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"    [!] Database error: {e}")
            return False
    
    def execute(self):
        """Run complete geolocation intelligence gathering"""
        print("[+] Running Geolocation Intelligence...")
        
        # Get target IP
        ip = self.get_target_ip()
        if not ip:
            print("    [!] Could not resolve IP address")
            return
        
        self.target_ip = ip
        print(f"    - Target IP: {ip}")
        
        # Geolocation lookup with fallback chain: ipapi.co -> ipinfo.io
        geo_data = self.lookup_ipapi(ip)
        source = "ipapi.co"
        
        if not geo_data and config.IPINFO_API_KEY:
            geo_data = self.lookup_ipinfo(ip)
            source = "ipinfo.io"
        elif not geo_data:
            # Try ipinfo.io without API key (rate-limited but free)
            geo_data = self.lookup_ipinfo(ip)
            source = "ipinfo.io (no key)"
        
        if geo_data:
            print(f"    - Source: {source}")
            print(f"    - Location: {geo_data.get('city', 'Unknown')}, {geo_data.get('country', 'Unknown')}")
            print(f"    - ISP: {geo_data.get('isp', 'Unknown')}")
            if geo_data.get('asn'):
                print(f"    - ASN: {geo_data.get('asn', 'Unknown')}")
            if geo_data.get('hostname'):
                print(f"    - Hostname: {geo_data.get('hostname')}")
            if geo_data.get('postal'):
                print(f"    - Postal Code: {geo_data.get('postal')}")
            
            # Store in database
            self.store_geolocation(geo_data)
        else:
            print("    [!] All geolocation sources failed")
        
        # Reverse IP lookup
        reverse_host = self.reverse_ip_lookup(ip)
        if reverse_host and reverse_host != self.target:
            print(f"    - Reverse DNS: {reverse_host}")
