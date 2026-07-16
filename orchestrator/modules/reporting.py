"""
Reporting Module
Generates professional HTML and PDF reports for Argus OSINT Framework findings.
Fully restructured to include ALL enhanced reconnaissance techniques.
"""

import os
import sqlite3
import datetime
import hashlib
import sys
import re

# Monkeypatch hashlib.md5 for ReportLab/Python 3.8 compatibility
if sys.version_info < (3, 9):
    _real_md5 = hashlib.md5
    def _patched_md5(*args, **kwargs):
        if 'usedforsecurity' in kwargs:
            kwargs.pop('usedforsecurity')
        return _real_md5(*args, **kwargs)
    hashlib.md5 = _patched_md5

from jinja2 import Environment, FileSystemLoader
from xhtml2pdf import pisa
from config import config

class ReportGenerator:
    def __init__(self, target, target_id):
        self.target = target
        self.target_id = target_id
        self.report_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../reporter/reports'))
        self.logo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../reporter/static/img/logo.jpg'))
        
        # Set up Jinja2 with external template file
        self.template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../reporter/templates'))
        self.jinja_env = Environment(loader=FileSystemLoader(self.template_dir))
        
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)

    def _fetch_data(self):
        """Fetch ALL scan data from database with proper column mapping"""
        data = {}
        conn = sqlite3.connect(config.DB_PATH, timeout=30.0)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        tid = self.target_id

        def safe_fetch(query, params=()):
            try:
                cursor.execute(query, params)
                return [dict(r) for r in cursor.fetchall()]
            except Exception:
                return []

        def safe_fetch_one(query, params=()):
            try:
                cursor.execute(query, params)
                row = cursor.fetchone()
                return dict(row) if row else {}
            except Exception:
                return {}

        # =====================================================================
        # CORE TARGET INFO
        # =====================================================================
        data['target'] = safe_fetch_one("SELECT * FROM targets WHERE id=?", (tid,))

        # =====================================================================
        # SECTION 1: DOMAIN & WHOIS
        # =====================================================================
        data['domain_info'] = safe_fetch_one("SELECT * FROM domain_info WHERE target_id=?", (tid,))
        data['rir_whois'] = safe_fetch("SELECT * FROM rir_whois WHERE target_id=?", (tid,))
        data['whois_history'] = safe_fetch(
            "SELECT * FROM whois_history WHERE target_id=? ORDER BY snapshot_date DESC", (tid,)
        )

        # =====================================================================
        # SECTION 2: DNS & NETWORK
        # =====================================================================
        data['dns_records'] = safe_fetch("SELECT DISTINCT record_type, value, ttl FROM dns_records WHERE target_id=? ORDER BY record_type", (tid,))
        data['dns_zone'] = safe_fetch("SELECT * FROM dns_zone_info WHERE target_id=?", (tid,))

        # =====================================================================
        # SECTION 3: GEOLOCATION
        # =====================================================================
        data['geolocation'] = safe_fetch_one("SELECT * FROM geolocation WHERE target_id=?", (tid,))

        # =====================================================================
        # SECTION 4: SSL / TLS
        # =====================================================================
        ssl_raw = safe_fetch_one("SELECT * FROM ssl_info WHERE target_id=?", (tid,))
        # Clean up SSL issuer from raw bytes dict string to readable format
        if ssl_raw and ssl_raw.get('issuer'):
            issuer_raw = str(ssl_raw['issuer'])
            # Remove b'' notation: {b'C': b'US', ...} -> {C: US, ...}
            issuer_clean = re.sub(r"b'([^']*)'", r"'\1'", issuer_raw)
            # Try to parse as dict and format nicely
            try:
                import ast
                issuer_dict = ast.literal_eval(issuer_clean)
                # Format as comma-separated key=value pairs
                formatted = ', '.join(f"{k}: {v}" for k, v in issuer_dict.items())
                ssl_raw['issuer'] = formatted
            except:
                # Fallback: just strip b'' prefixes
                ssl_raw['issuer'] = issuer_clean.replace("{b'", "").replace("': b'", ": ").replace("'}", "").replace("'", "")
        
        # Format SSL valid_to date from raw format (e.g., 20261117235959Z -> Nov 17, 2026)
        if ssl_raw and ssl_raw.get('valid_to'):
            try:
                raw_date = ssl_raw['valid_to'].strip()
                # Handle format: YYYYMMDDHHMMSSZ or YYYYMMDDHHMMSS (ASN.1/OpenSSL format)
                from datetime import datetime
                if raw_date.upper().endswith('Z'):
                    parsed = datetime.strptime(raw_date.rstrip('Zz'), '%Y%m%d%H%M%S')
                elif len(raw_date) >= 14:
                    parsed = datetime.strptime(raw_date[:14], '%Y%m%d%H%M%S')
                else:
                    parsed = None
                if parsed:
                    ssl_raw['valid_to'] = parsed.strftime('%b %d, %Y')
            except Exception:
                pass  # Keep original if parsing fails
        
        data['ssl_info'] = ssl_raw if ssl_raw else {}
        data['ssl_config'] = safe_fetch("SELECT * FROM ssl_config WHERE target_id=?", (tid,))

        # =====================================================================
        # SECTION 5: PORTS & SERVICES
        # =====================================================================
        data['ports'] = safe_fetch(
            "SELECT port, protocol, service, version, state FROM ports WHERE target_id=? GROUP BY port ORDER BY port ASC", (tid,)
        )
        # Removed Traceroute section per user request (network path mapping was unreliable)
        # data['traceroute'] = safe_fetch("SELECT * FROM traceroute WHERE target_id=?", (tid,))

        # =====================================================================
        # SECTION 6: SUBDOMAINS & ATTACK SURFACE
        # =====================================================================
        data['subdomains'] = safe_fetch(
            "SELECT DISTINCT subdomain, ip_address FROM subdomains WHERE target_id=?", (tid,)
        )

        # =====================================================================
        # SECTION 7: WEB TECHNOLOGIES & DIRECTORIES
        # =====================================================================
        data['technologies'] = safe_fetch(
            "SELECT DISTINCT name, version, category FROM technologies WHERE target_id=?", (tid,)
        )
        data['directories'] = safe_fetch(
            "SELECT DISTINCT path, status_code FROM directories WHERE target_id=? ORDER BY status_code", (tid,)
        )
        data['http_methods'] = safe_fetch(
            "SELECT url, method, status_code, allowed FROM http_methods WHERE target_id=?", (tid,)
        )
        data['auth_pages'] = safe_fetch(
            "SELECT page_url, auth_type, status_code, has_login_form, has_password_reset FROM auth_pages WHERE target_id=? ORDER BY status_code", (tid,)
        )
        data['web_forms'] = safe_fetch(
            "SELECT page_url, form_action, form_method, form_type, has_password_field, has_file_upload FROM web_forms WHERE target_id=?", (tid,)
        )
        data['cookie_audit'] = safe_fetch(
            "SELECT cookie_name, domain, secure_flag, httponly, samesite FROM cookie_audit WHERE target_id=?", (tid,)
        )
        data['response_codes'] = safe_fetch(
            "SELECT url, status_code, content_length, content_type FROM response_codes WHERE target_id=? ORDER BY status_code", (tid,)
        )

        # =====================================================================
        # SECTION 8: FINDS & VULNERABILITIES
        # =====================================================================
        all_findings = safe_fetch(
            "SELECT title, severity, description, url FROM findings WHERE target_id=? GROUP BY title", (tid,)
        )
        data['findings'] = [f for f in all_findings if not f.get('title', '').startswith('[Web Analysis]')]
        data['web_analysis'] = [f for f in all_findings if f.get('title', '').startswith('[Web Analysis]')]

        # =====================================================================
        # SECTION 9: THREAT INTELLIGENCE
        # =====================================================================
        try:
            rows = safe_fetch("SELECT * FROM threat_intel WHERE target_id=? ORDER BY id DESC", (tid,))
            threat_intel = []
            seen = set()
            for item in rows:
                try:
                    import json
                    item['details'] = json.loads(item['additional_data']) if item.get('additional_data') else {}
                except:
                    item['details'] = {}
                fp = (item.get('source'), item.get('threat_score'))
                if fp not in seen:
                    seen.add(fp)
                    threat_intel.append(item)
            data['threat_intel'] = threat_intel
        except:
            data['threat_intel'] = []

        # =====================================================================
        # SECTION 10: REPUTATION & BLACKLIST
        # =====================================================================
        data['ip_reputation'] = safe_fetch(
            "SELECT * FROM ip_reputation WHERE target_id=? ORDER BY threat_score DESC", (tid,)
        )
        data['dnsbl_results'] = safe_fetch(
            "SELECT blacklist_source, listed, response FROM dnsbl_results WHERE target_id=?", (tid,)
        )
        data['abuseipdb'] = safe_fetch_one(
            "SELECT ip_address, abuse_reports, threat_score, isp, usage_type FROM ip_reputation WHERE target_id=? AND abuse_reports > 0", (tid,)
        )

        # =====================================================================
        # SECTION 11: BGP & ASN
        # =====================================================================
        data['bgp_info'] = safe_fetch("SELECT * FROM bgp_info WHERE target_id=?", (tid,))

        # =====================================================================
        # SECTION 12: ACTIVE PROTOCOL ENUMERATION
        # =====================================================================
        data['snmp_info'] = safe_fetch("SELECT * FROM snmp_info WHERE target_id=?", (tid,))
        data['smb_shares'] = safe_fetch("SELECT * FROM smb_shares WHERE target_id=?", (tid,))
        data['ldap_info'] = safe_fetch("SELECT * FROM ldap_info WHERE target_id=?", (tid,))
        data['ntp_info'] = safe_fetch("SELECT * FROM ntp_info WHERE target_id=?", (tid,))
        data['smtp_enum'] = safe_fetch("SELECT server, username, found, method FROM smtp_enum WHERE target_id=?", (tid,))

        # =====================================================================
        # SECTION 13: INTELLIGENCE (EMAILS, BREACHES, SEARCH)
        # =====================================================================
        data['emails'] = safe_fetch(
            "SELECT DISTINCT email, source_url FROM emails WHERE target_id=?", (tid,)
        )
        data['breaches'] = safe_fetch("SELECT * FROM breach_data WHERE target_id=?", (tid,))
        data['search_results'] = safe_fetch(
            "SELECT source, title, snippet, risk_level FROM search_results WHERE target_id=? GROUP BY snippet", (tid,)
        )
        data['social_profiles'] = safe_fetch(
            "SELECT platform, username, profile_url, status FROM social_profiles WHERE target_id=?", (tid,)
        )

        # =====================================================================
        # SECTION 14: HISTORICAL INTEL
        # =====================================================================
        data['historical_data'] = safe_fetch(
            "SELECT DISTINCT source, snapshot_count, first_seen, last_seen, status FROM historical_data WHERE target_id=? ORDER BY snapshot_date DESC", (tid,)
        )

        # =====================================================================
        # SECTION 15: METADATA & OTHER
        # =====================================================================
        data['metadata'] = safe_fetch(
            "SELECT file_url, file_type, author, software, creation_date FROM metadata WHERE target_id=?", (tid,)
        )

        conn.close()
        return data

    def generate_html(self, output_path=None):
        """Generate HTML report with all enhanced data sections"""
        data = self._fetch_data()
        template = self.jinja_env.get_template('report_v2.html')
        
        has_logo = os.path.exists(self.logo_path)
        logo_uri = f"file:///{self.logo_path.replace(os.sep, '/')}" if has_logo else None
        
        html_content = template.render(
            data=data, 
            date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            logo_path=logo_uri 
        )
        
        if not output_path:
            sanitized_target = re.sub(r'[^\w\-_.]', '_', self.target)
            filename = f"report_{sanitized_target}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            output_path = os.path.join(self.report_dir, filename)
            
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        return output_path

    def generate_pdf(self, output_path=None):
        """Generate PDF report from the same rich template"""
        data = self._fetch_data()
        template = self.jinja_env.get_template('report_v2.html')
        
        has_logo = os.path.exists(self.logo_path)
        logo_path_pdf = self.logo_path if has_logo else None

        html_content = template.render(
            data=data, 
            date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            logo_path=logo_path_pdf
        )

        if not output_path:
            sanitized_target = re.sub(r'[^\w\-_.]', '_', self.target)
            filename = f"report_{sanitized_target}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            output_path = os.path.join(self.report_dir, filename)

        with open(output_path, "wb") as pdf_file:
            pisa_status = pisa.CreatePDF(html_content, dest=pdf_file)
            
        if pisa_status.err:
            print(f"    [!] PDF generation error: {pisa_status.err}")
            return None
            
        return output_path
