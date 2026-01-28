"""
Threat Intelligence Module
Integrates VirusTotal, Shodan, and AlienVault OTX for threat assessment
"""

import requests
import sqlite3
import json
import time
from config import config

class ThreatIntelligence:
    def __init__(self, target, target_id, ip_address=None):
        self.target = target
        self.target_id = target_id
        self.ip_address = ip_address
        self.vt_api_key = config.VIRUSTOTAL_API_KEY
        self.shodan_api_key = config.SHODAN_API_KEY
        self.otx_api_key = config.OTX_API_KEY
    
    def check_virustotal_domain(self):
        """Check domain reputation on VirusTotal"""
        if not self.vt_api_key:
            print("    [!] VirusTotal API key not configured")
            return None
        
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{self.target}"
            headers = {
                'x-apikey': self.vt_api_key,
                'User-Agent': config.USER_AGENT
            }
            
            time.sleep(4)  # Rate limiting: 4 requests/minute on free tier
            
            res = requests.get(url, headers=headers, timeout=config.HTTP_TIMEOUT)
            
            if res.status_code == 200:
                data = res.json()
                attributes = data.get('data', {}).get('attributes', {})
                last_analysis = attributes.get('last_analysis_stats', {})
                
                return {
                    'source': 'VirusTotal',
                    'indicator_type': 'domain',
                    'indicator_value': self.target,
                    'malicious': last_analysis.get('malicious', 0),
                    'suspicious': last_analysis.get('suspicious', 0),
                    'harmless': last_analysis.get('harmless', 0),
                    'undetected': last_analysis.get('undetected', 0),
                    'categories': attributes.get('categories', {}),
                    'reputation': attributes.get('reputation', 0),
                    'last_analysis_date': attributes.get('last_analysis_date', '')
                }
            elif res.status_code == 404:
                print(f"    [!] Domain not found in VirusTotal")
            else:
                print(f"    [!] VirusTotal API returned status {res.status_code}")
                
        except Exception as e:
            print(f"    [!] VirusTotal check failed: {e}")
        
        return None
    
    def check_shodan(self):
        """Check IP/domain on Shodan for exposed services and CVEs"""
        if not self.shodan_api_key:
            print("    [!] Shodan API key not configured")
            return None
        
        if not self.ip_address:
            print("    [!] IP address required for Shodan lookup")
            return None
        
        try:
            import shodan
            api = shodan.Shodan(self.shodan_api_key)
            
            time.sleep(1)  # Rate limiting
            
            # Lookup IP
            host = api.host(self.ip_address)
            
            # Extract CVEs
            cves = []
            for item in host.get('data', []):
                if 'vulns' in item:
                    cves.extend(item['vulns'].keys())
            
            return {
                'source': 'Shodan',
                'indicator_type': 'ip',
                'indicator_value': self.ip_address,
                'os': host.get('os', ''),
                'ports': host.get('ports', []),
                'vulns': list(set(cves)),
                'tags': host.get('tags', []),
                'hostnames': host.get('hostnames', []),
                'isp': host.get('isp', ''),
                'org': host.get('org', ''),
                'asn': host.get('asn', '')
            }
            
        except Exception as e:
            print(f"    [!] Shodan check failed: {e}")
        
        return None
    
    def check_otx(self):
        """Check AlienVault OTX for threat intelligence"""
        try:
            from OTXv2 import OTXv2
            
            if not self.otx_api_key:
                # OTX allows limited access without API key
                print("    [!] OTX API key not configured, using limited access")
                otx = OTXv2("")
            else:
                otx = OTXv2(self.otx_api_key)
            
            # Get domain reputation
            from OTXv2 import IndicatorTypes
            alerts = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, self.target)
            
            if alerts:
                general = alerts.get('general', {})
                validation = alerts.get('validation', [])
                
                return {
                    'source': 'AlienVault OTX',
                    'indicator_type': 'domain',
                    'indicator_value': self.target,
                    'pulse_count': general.get('pulse_info', {}).get('count', 0),
                    'validation': validation,
                    'reputation': general.get('reputation', 0)
                }
                
        except Exception as e:
            print(f"    [!] OTX check failed: {e}")
        
        return None
    
    def calculate_threat_score(self, vt_data, shodan_data, otx_data):
        """Calculate overall threat score (0-100)"""
        score = 0
        
        if vt_data:
            malicious = vt_data.get('malicious', 0)
            suspicious = vt_data.get('suspicious', 0)
            if malicious > 0:
                score += min(malicious * 10, 50)
            if suspicious > 0:
                score += min(suspicious * 5, 20)
        
        if shodan_data:
            vulns = len(shodan_data.get('vulns', []))
            if vulns > 0:
                score += min(vulns * 5, 30)
        
        if otx_data:
            pulses = otx_data.get('pulse_count', 0)
            if pulses > 0:
                score += min(pulses * 2, 20)
        
        return min(score, 100)
    
    def store_threat_intel(self, threat_data):
        """Store threat intelligence in database"""
        try:
            conn = sqlite3.connect(config.DB_PATH, timeout=30.0)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO threat_intel (target_id, source, indicator_type, indicator_value,
                                         threat_score, malicious_count, suspicious_count, harmless_count,
                                         tags, threat_categories, last_analysis_date, cve_list, additional_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                self.target_id,
                threat_data.get('source', ''),
                threat_data.get('indicator_type', ''),
                threat_data.get('indicator_value', ''),
                threat_data.get('threat_score', 0),
                threat_data.get('malicious', 0),
                threat_data.get('suspicious', 0),
                threat_data.get('harmless', 0),
                ', '.join(threat_data.get('tags', [])) if isinstance(threat_data.get('tags'), list) else '',
                threat_data.get('categories', ''),
                threat_data.get('last_analysis_date', ''),
                ', '.join(threat_data.get('vulns', [])) if isinstance(threat_data.get('vulns'), list) else '',
                json.dumps(threat_data)
            ))
            
            conn.commit()
            
            # Update target risk score
            score = threat_data.get('threat_score', 0)
            if score > 0:
                cursor.execute("UPDATE targets SET risk_score = MAX(risk_score, ?) WHERE id = ?", (score, self.target_id))
                conn.commit()
                
            conn.close()
        except Exception as e:
            print(f"    [!] Database error: {e}")
    
    def execute(self):
        """Run complete threat intelligence gathering"""
        print("[+] Running Threat Intelligence Assessment...")
        
        if not config.ENABLE_THREAT_INTEL:
            print("    [!] Threat Intelligence disabled in configuration")
            return
        
        vt_data = None
        shodan_data = None
        otx_data = None
        
        # VirusTotal check
        if self.vt_api_key:
            print("    - Checking VirusTotal...")
            vt_data = self.check_virustotal_domain()
            if vt_data:
                mal = vt_data.get('malicious', 0)
                sus = vt_data.get('suspicious', 0)
                if mal > 0 or sus > 0:
                    print(f"      ⚠ Malicious: {mal}, Suspicious: {sus}")
                else:
                    print(f"      ✓ Clean (Harmless: {vt_data.get('harmless', 0)})")
                self.store_threat_intel(vt_data)
        
       # Shodan check
        if self.shodan_api_key and self.ip_address:
            print("    - Checking Shodan...")
            shodan_data = self.check_shodan()
            if shodan_data:
                vulns = shodan_data.get('vulns', [])
                if vulns:
                    print(f"      ⚠ Found {len(vulns)} CVEs:")
                    for cve in vulns[:5]:  # Show first 5
                        print(f"        - {cve}")
                else:
                    print(f"      ✓ No known vulnerabilities")
                
                ports = shodan_data.get('ports', [])
                if ports:
                    print(f"      - Open ports: {', '.join(map(str, ports[:10]))}")
                
                self.store_threat_intel(shodan_data)
        
        # OTX check
        if self.otx_api_key or True:  # OTX allows limited access
            print("    - Checking AlienVault OTX...")
            otx_data = self.check_otx()
            if otx_data:
                pulses = otx_data.get('pulse_count', 0)
                if pulses > 0:
                    print(f"      ⚠ Found in {pulses} threat pulses")
                else:
                    print(f"      ✓ No threat intelligence found")
                self.store_threat_intel(otx_data)
        
        # Calculate overall threat score
        threat_score = self.calculate_threat_score(vt_data, shodan_data, otx_data)
        
        if threat_score > 0:
            print(f"    - Overall Threat Score: {threat_score}/100")
            # Save to DB
            try:
                conn = sqlite3.connect(config.DB_PATH, timeout=30.0)
                cursor = conn.cursor()
                cursor.execute("UPDATE targets SET risk_score = MAX(risk_score, ?) WHERE id = ?", (threat_score, self.target_id))
                conn.commit()
                conn.close()
            except Exception as e:
                print(f"    [!] Failed to save risk score: {e}")
        else:
            print("    - Overall Threat Score: 0/100 (Clean)")
