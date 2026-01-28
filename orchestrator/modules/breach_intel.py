"""
Breach Intelligence Module
Check email addresses against Have I Been Pwned database
"""

import requests
import sqlite3
import time
from config import config

class BreachIntelligence:
    def __init__(self, target, target_id, emails=None):
        self.target = target
        self.target_id = target_id
        self.emails = emails or []
        self.api_key = config.HIBP_API_KEY
    
    def check_hibp(self, email):
        """Check email against Have I Been Pwned API"""
        if not self.api_key:
            print("    [!] HIBP API key not configured, skipping breach checks")
            return None
        
        try:
            # HIBP API v3 requires API key
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
            headers = {
                'hibp-api-key': self.api_key,
                'User-Agent': config.USER_AGENT
            }
            
            # Rate limiting: 1 request every 1.5 seconds
            time.sleep(1.5)
            
            res = requests.get(url, headers=headers, timeout=config.HTTP_TIMEOUT)
            
            if res.status_code == 200:
                # Email found in breaches
                breaches = res.json()
                return {
                    'email': email,
                    'found': True,
                    'breach_count': len(breaches),
                    'breaches': breaches
                }
            elif res.status_code == 404:
                # Email not found in any breaches
                return {
                    'email': email,
                    'found': False,
                    'breach_count': 0,
                    'breaches': []
                }
            else:
                print(f"    [!] HIBP API returned status {res.status_code}")
                
        except Exception as e:
            print(f"    [!] HIBP check failed for {email}: {e}")
        
        return None
    
    def check_pastes(self, email):
        """Check if email appears in pastes"""
        if not self.api_key:
            return None
        
        try:
            url = f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}"
            headers = {
                'hibp-api-key': self.api_key,
                'User-Agent': config.USER_AGENT
            }
            
            time.sleep(1.5)  # Rate limiting
            
            res = requests.get(url, headers=headers, timeout=config.HTTP_TIMEOUT)
            
            if res.status_code == 200:
                pastes = res.json()
                return {
                    'paste_count': len(pastes),
                    'pastes': pastes
                }
            elif res.status_code == 404:
                return {'paste_count': 0, 'pastes': []}
                
        except Exception as e:
            print(f"    [!] Paste check failed for {email}: {e}")
        
        return None
    
    def store_breach_data(self, breach_data):
        """Store breach intelligence in database"""
        try:
            conn = sqlite3.connect(config.DB_PATH, timeout=30.0)
            cursor = conn.cursor()
            
            # Extract breach names
            breach_names = []
            most_recent = None
            is_sensitive = False
            
            if breach_data.get('breaches'):
                for breach in breach_data['breaches']:
                    breach_names.append(breach.get('Name', 'Unknown'))
                    
                    # Check if any breach is sensitive
                    if breach.get('IsSensitive', False):
                        is_sensitive = True
                    
                    # Track most recent breach
                    breach_date = breach.get('BreachDate', '')
                    if not most_recent or breach_date > most_recent:
                        most_recent = breach_date
            
            cursor.execute("""
                INSERT INTO breach_data (target_id, email, breach_count, breach_names, 
                                        paste_count, most_recent_breach, is_sensitive)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                self.target_id,
                breach_data.get('email', ''),
                breach_data.get('breach_count', 0),
                ', '.join(breach_names),
                breach_data.get('paste_count', 0),
                most_recent,
                is_sensitive
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"    [!] Database error: {e}")
    
    def execute(self):
        """Run complete breach intelligence gathering"""
        print("[+] Running Breach Intelligence (Have I Been Pwned)...")
        
        if not config.ENABLE_BREACH_INTEL:
            print("    [!] Breach Intelligence disabled in configuration")
            return
        
        if not self.api_key:
            print("    [!] HIBP API key not configured - skipping breach checks")
            print("    [*] Get your free API key at: https://haveibeenpwned.com/API/Key")
            return
        
        if not self.emails:
            print("    [!] No emails to check")
            return
        
        print(f"    - Checking {len(self.emails)} email addresses")
        
        total_breached = 0
        total_breaches = 0
        
        for email in self.emails:
            print(f"    - Checking: {email}")
            
            # Check breaches
            breach_result = self.check_hibp(email)
            
            if breach_result and breach_result.get('found'):
                breach_count = breach_result.get('breach_count', 0)
                print(f"      ⚠ FOUND in {breach_count} breaches!")
                
                # List breach names
                for breach in breach_result.get('breaches', [])[:5]:  # Show first 5
                    name = breach.get('Name', 'Unknown')
                    date = breach.get('BreachDate', 'Unknown')
                    print(f"        - {name} ({date})")
                
                total_breached += 1
                total_breaches += breach_count
                
                # Check pastes
                paste_result = self.check_pastes(email)
                if paste_result:
                    breach_result['paste_count'] = paste_result.get('paste_count', 0)
                    if paste_result.get('paste_count', 0) > 0:
                        print(f"      ⚠ Found in {paste_result['paste_count']} pastes")
                
                # Store in database
                self.store_breach_data(breach_result)
                
            elif breach_result and not breach_result.get('found'):
                print(f"      ✓ Not found in any breaches")
        
        if total_breached > 0:
            print(f"    - Summary: {total_breached}/{len(self.emails)} emails compromised in {total_breaches} total breaches")
        else:
            print("    - Summary: No emails found in breach databases")
