"""
Geolocation Intelligence Module
Provides IP geolocation, ASN lookup, and reverse IP capabilities
"""

import socket
import requests
import sqlite3
from config import config

class GeoIntelligence:
    def __init__(self, target, target_id):
        self.target = target
        self.target_id = target_id
        self.target_ip = None
        
    def get_target_ip(self):
        """Resolve target domain to IP address"""
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
                geo_data.get('isp', ''),  # organization = isp for ipapi
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
        print(f"    - Resolved IP: {ip}")
        
        # Geolocation lookup
        geo_data = self.lookup_ipapi(ip)
        if geo_data:
            print(f"    - Location: {geo_data.get('city', 'Unknown')}, {geo_data.get('country', 'Unknown')}")
            print(f"    - ISP: {geo_data.get('isp', 'Unknown')}")
            print(f"    - ASN: {geo_data.get('asn', 'Unknown')}")
            
            # Store in database
            self.store_geolocation(geo_data)
        
        # Reverse IP lookup
        reverse_host = self.reverse_ip_lookup(ip)
        if reverse_host and reverse_host != self.target:
            print(f"    - Reverse DNS: {reverse_host}")
