"""
Social Media Intelligence (SOCMINT) Module
Username enumeration and social profile discovery
"""

import requests
import subprocess
import sqlite3
import json
import time
from config import config

class SocialIntelligence:
    def __init__(self, target, target_id, emails=None):
        self.target = target
        self.target_id = target_id
        self.emails = emails or []
        
        # Top social media platforms to check manually
        self.platforms = [
            {'name': 'GitHub', 'url': 'https://github.com/{username}'},
            {'name': 'Twitter', 'url': 'https://twitter.com/{username}'},
            {'name': 'LinkedIn', 'url': 'https://linkedin.com/in/{username}'},
            {'name': 'Instagram', 'url': 'https://instagram.com/{username}'},
            {'name': 'Facebook', 'url': 'https://facebook.com/{username}'},
            {'name': 'Reddit', 'url': 'https://reddit.com/user/{username}'},
            {'name': 'Medium', 'url': 'https://medium.com/@{username}'},
            {'name': 'YouTube', 'url': 'https://youtube.com/@{username}'},
        ]
    
    def check_sherlock(self, username):
        """Use Sherlock for comprehensive username search (if installed)"""
        try:
            # Check if Sherlock is installed
            result = subprocess.run(['sherlock', '--version'], 
                                  capture_output=True, 
                                  text=True,
                                  timeout=5)
            
            if result.returncode == 0:
                print(f"    - Running Sherlock for username: {username}")
                # Run Sherlock with JSON output
                cmd = ['sherlock', username, '--timeout', '5', '--json', '--print-found']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                if result.stdout:
                    # Sherlock doesn't output valid JSON, parse text output
                    found_profiles = []
                    for line in result.stdout.split('\n'):
                        if 'http' in line.lower():
                            found_profiles.append(line.strip())
                    return found_profiles[:20]  # Limit to 20 results
                    
        except (FileNotFoundError, subprocess.TimeoutExpired):
            print("    [!] Sherlock not installed, using manual checks")
        except Exception as e:
            print(f"    [!] Sherlock error: {e}")
        
        return []
    
    def check_platform_manual(self, platform, username):
        """Manual check for social media profile existence"""
        try:
            url = platform['url'].format(username=username)
            headers = {'User-Agent': config.USER_AGENT}
            
            res = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
            
            # Common status codes indicating profile exists
            if res.status_code == 200:
                # Additional check: some platforms return 200 for "not found" pages
                not_found_indicators = ['not found', 'doesn\'t exist', 'page not found', 'user not found']
                if not any(indicator in res.text.lower() for indicator in not_found_indicators):
                    return {
                        'platform': platform['name'],
                        'username': username,
                        'url': url,
                        'status': 'Found'
                    }
            
            time.sleep(0.5)  # Rate limiting
            
        except Exception:
            pass
        
        return None
    
    def extract_username_from_email(self, email):
        """Extract potential username from email address"""
        if '@' in email:
            return email.split('@')[0]
        return email
    
    def extract_username_from_domain(self):
        """Extract potential username from domain name"""
        # Remove common TLDs and return base name
        domain = self.target.lower()
        for tld in ['.com', '.net', '.org', '.io', '.co', '.dev']:
            domain = domain.replace(tld, '')
        return domain
    
    def store_profile(self, profile_data):
        """Store social media profile in database"""
        try:
            conn = sqlite3.connect(config.DB_PATH, timeout=30.0)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO social_profiles (target_id, platform, username, profile_url, email, status, additional_info)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                self.target_id,
                profile_data.get('platform', ''),
                profile_data.get('username', ''),
                profile_data.get('url', ''),
                profile_data.get('email', ''),
                profile_data.get('status', 'Found'),
                json.dumps(profile_data.get('extra', {}))
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"    [!] Database error: {e}")
    
    def execute(self):
        """Run complete social media intelligence gathering"""
        print("[+] Running Social Media Intelligence (SOCMINT)...")
        
        if not config.ENABLE_SOCMINT:
            print("    [!] SOCMINT disabled in configuration")
            return
        
        usernames_to_check = set()
        
        # Extract usernames from emails
        for email in self.emails:
            username = self.extract_username_from_email(email)
            if username and len(username) > 2:
                usernames_to_check.add(username)
        
        # Add domain-based username
        domain_username = self.extract_username_from_domain()
        if len(domain_username) > 2:
            usernames_to_check.add(domain_username)
        
        if not usernames_to_check:
            print("    [!] No usernames to check")
            return
        
        print(f"    - Checking {len(usernames_to_check)} potential usernames")
        
        total_found = 0
        
        for username in list(usernames_to_check)[:5]:  # Limit to 5 usernames to avoid excessive scanning
            print(f"    - Username: {username}")
            
            # Try Sherlock first
            sherlock_results = self.check_sherlock(username)
            if sherlock_results:
                for profile_url in sherlock_results:
                    profile_data = {
                        'platform': 'Multiple',
                        'username': username,
                        'url': profile_url,
                        'status': 'Found'
                    }
                    self.store_profile(profile_data)
                    total_found += 1
                    print(f"      ✓ {profile_url}")
            else:
                # Manual platform checks
                for platform in self.platforms:
                    result = self.check_platform_manual(platform, username)
                    if result:
                        self.store_profile(result)
                        total_found += 1
                        print(f"      ✓ {platform['name']}: {result['url']}")
        
        if total_found > 0:
            print(f"    - Found {total_found} social media profiles")
        else:
            print("    - No social media profiles found")
