"""
Historical Intelligence Module
Wayback Machine and Archive.today integration
"""

import requests
import sqlite3
import json
from datetime import datetime
from config import config

class HistoricalIntelligence:
    def __init__(self, target, target_id):
        self.target = target
        self.target_id = target_id
    
    def check_wayback_machine(self):
        """Check Wayback Machine for archived snapshots"""
        try:
            # Wayback Machine CDX API
            url = f"https://web.archive.org/cdx/search/cdx"
            params = {
                'url': self.target,
                'output': 'json',
                'limit': '100',
                'fl': 'timestamp,original,statuscode,mimetype'
            }
            
            headers = {'User-Agent': config.USER_AGENT}
            res = requests.get(url, params=params, headers=headers, timeout=15)
            
            if res.status_code == 200:
                data = res.json()
                
                if len(data) > 1:  # First row is headers
                    snapshots = data[1:]  # Skip header row
                    
                    # Get first and last snapshot dates
                    first_timestamp = snapshots[0][0]
                    last_timestamp = snapshots[-1][0]
                    
                    # Parse timestamps (format: YYYYMMDDhhmmss)
                    first_date = datetime.strptime(first_timestamp[:8], '%Y%m%d').strftime('%Y-%m-%d')
                    last_date = datetime.strptime(last_timestamp[:8], '%Y%m%d').strftime('%Y-%m-%d')
                    
                    # Generate snapshot URL for most recent
                    snapshot_url = f"https://web.archive.org/web/{last_timestamp}/{self.target}"
                    
                    return {
                        'source': 'WaybackMachine',
                        'snapshot_count': len(snapshots),
                        'first_seen': first_date,
                        'last_seen': last_date,
                        'snapshot_url': snapshot_url,
                        'status': 'Available'
                    }
                else:
                    return {
                        'source': 'WaybackMachine',
                        'snapshot_count': 0,
                        'status': 'Not Found'
                    }
                    
        except Exception as e:
            print(f"    [!] Wayback Machine check failed: {e}")
        
        return None

    def extract_wayback_urls(self):
        """Extract all unique URLs archived by Wayback Machine"""
        urls = set()
        print("    - extracting all archived URLs from Wayback Machine...")
        try:
            # CDX API to get all URLs for domain
            # collapse=urlkey filters out duplicates to some extent
            url = "https://web.archive.org/cdx/search/cdx"
            params = {
                'url': f"*.{self.target}/*",
                'output': 'json',
                'fl': 'original',
                'collapse': 'urlkey'
            }
            
            headers = {'User-Agent': config.USER_AGENT}
            res = requests.get(url, params=params, headers=headers, timeout=30)
            
            if res.status_code == 200:
                data = res.json()
                if len(data) > 1:
                    # Skip header
                    for row in data[1:]:
                        if row and len(row) > 0:
                            urls.add(row[0])
                    
                    print(f"      ✓ Found {len(urls)} unique archived URLs")
            
        except Exception as e:
            print(f"      [!] Failed to extract Wayback URLs: {e}")
            
        return urls
    
    def check_archive_today(self):
        """Check Archive.today for snapshots"""
        try:
            # Archive.today search
            url = f"https://archive.ph/{self.target}"
            headers = {'User-Agent': config.USER_AGENT}
            
            res = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
            
            if res.status_code == 200 and 'archive.ph' in res.url:
                # Successfully found archive
                return {
                    'source': 'Archive.today',
                    'snapshot_url': res.url,
                    'status': 'Available'
                }
            else:
                return {
                    'source': 'Archive.today',
                    'status': 'Not Found'
                }
                
        except Exception as e:
            print(f"    [!] Archive.today check failed: {e}")
        
        return None
    
    def store_historical_data(self, historical_data):
        """Store historical intelligence in database"""
        try:
            conn = sqlite3.connect(config.DB_PATH, timeout=30.0)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO historical_data (target_id, source, snapshot_url, snapshot_date,
                                            snapshot_count, first_seen, last_seen, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                self.target_id,
                historical_data.get('source', ''),
                historical_data.get('snapshot_url', ''),
                historical_data.get('last_seen', ''),
                historical_data.get('snapshot_count', 0),
                historical_data.get('first_seen', ''),
                historical_data.get('last_seen', ''),
                historical_data.get('status', '')
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"    [!] Database error: {e}")
    
    def execute(self):
        """Run complete historical intelligence gathering"""
        print("[+] Running Historical Intelligence (Archive Data)...")
        
        if not config.ENABLE_HISTORICAL:
            print("    [!] Historical Intelligence disabled in configuration")
            return
        
        # Check Wayback Machine
        print("    - Checking Wayback Machine...")
        wayback_data = self.check_wayback_machine()
        
        if wayback_data:
            if wayback_data.get('snapshot_count', 0) > 0:
                print(f"      ✓ Found {wayback_data['snapshot_count']} snapshots")
                print(f"      - First seen: {wayback_data.get('first_seen', 'Unknown')}")
                print(f"      - Last seen: {wayback_data.get('last_seen', 'Unknown')}")
                print(f"      - Latest: {wayback_data.get('snapshot_url', '')}")
            else:
                print(f"      ✗ No snapshots found")
            
            self.store_historical_data(wayback_data)
        
        # Check Archive.today
        print("    - Checking Archive.today...")
        archive_data = self.check_archive_today()
        
        if archive_data:
            if archive_data.get('status') == 'Available':
                print(f"      ✓ Snapshot available: {archive_data.get('snapshot_url', '')}")
            else:
                print(f"      ✗ No snapshot found")
            
            self.store_historical_data(archive_data)
