"""
Reporting Module
Generates professional HTML and PDF reports for Argus OSINT Framework findings.
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

from jinja2 import Template
from xhtml2pdf import pisa
from config import config

class ReportGenerator:
    def __init__(self, target, target_id):
        self.target = target
        self.target_id = target_id
        self.report_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../reporter/reports'))
        self.logo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../reporter/static/img/logo.jpg'))
        
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)

    def _fetch_data(self):
        """Fetch all scan data from database with deduplication"""
        data = {}
        conn = sqlite3.connect(config.DB_PATH, timeout=30.0)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Target Info
        cursor.execute("SELECT * FROM targets WHERE id=?", (self.target_id,))
        data['target'] = dict(cursor.fetchone())

        # Domain Info
        cursor.execute("SELECT * FROM domain_info WHERE target_id=?", (self.target_id,))
        row = cursor.fetchone()
        data['domain_info'] = dict(row) if row else {}

        # Geo Info
        try:
            cursor.execute("SELECT * FROM geolocation WHERE target_id=?", (self.target_id,))
            row = cursor.fetchone()
            data['geolocation'] = dict(row) if row else {}
        except: data['geolocation'] = {}

        # Emails (Unique)
        cursor.execute("SELECT DISTINCT email, source_url FROM emails WHERE target_id=?", (self.target_id,))
        data['emails'] = [dict(row) for row in cursor.fetchall()]

        # Ports (Grouped by Port to remove duplicates)
        cursor.execute("""
            SELECT port, protocol, service, version, state 
            FROM ports 
            WHERE target_id=? 
            GROUP BY port 
            ORDER BY port ASC
        """, (self.target_id,))
        data['ports'] = [dict(row) for row in cursor.fetchall()]

        # Tech (Grouped by Name)
        cursor.execute("SELECT DISTINCT name, version, category FROM technologies WHERE target_id=?", (self.target_id,))
        data['technologies'] = [dict(row) for row in cursor.fetchall()]

        # Directories (New)
        cursor.execute("SELECT DISTINCT path, status_code FROM directories WHERE target_id=? ORDER BY status_code", (self.target_id,))
        data['directories'] = [dict(row) for row in cursor.fetchall()]

        # Security Findings - Deduplicated by Title
        cursor.execute("SELECT title, severity, description, url FROM findings WHERE target_id=? GROUP BY title", (self.target_id,))
        all_findings = [dict(row) for row in cursor.fetchall()]
        
        # Separate Web Analysis findings from other findings by title prefix
        data['findings'] = [f for f in all_findings if not f.get('title', '').startswith('[Web Analysis]')]
        data['web_analysis'] = [f for f in all_findings if f.get('title', '').startswith('[Web Analysis]')]

        # Threat Intel (Enhanced & Deduplicated)
        try:
            # Fetch all columns including additional_data JSON
            cursor.execute("""
                SELECT * FROM threat_intel 
                WHERE target_id=? 
                ORDER BY id DESC
            """, (self.target_id,))
            rows = cursor.fetchall()
            
            threat_intel = []
            seen_fingerprints = set()
            
            for row in rows:
                item = dict(row)
                # Parse JSON data if available
                try:
                    import json
                    if item.get('additional_data'):
                        item['details'] = json.loads(item['additional_data'])
                    else:
                        item['details'] = {}
                except:
                    item['details'] = {}
                
                # Content-Based Deduplication Fingerprint
                # Create a unique signature based on the FINDINGS, not the IP
                # Fields: Source, Open Ports (sorted), Vulns (sorted), ISP, ASN, Threat Score
                
                details = item.get('details', {})
                
                # Handle lists which can be unhashable
                ports = tuple(sorted(details.get('ports', []))) if isinstance(details.get('ports'), list) else ()
                vulns = tuple(sorted(details.get('vulns', []))) if isinstance(details.get('vulns'), list) else ()
                tags = tuple(sorted(details.get('tags', []))) if isinstance(details.get('tags'), list) else ()
                
                fingerprint = (
                    item.get('source'),
                    item.get('threat_score'),
                    ports,
                    vulns,
                    details.get('isp'),
                    details.get('asn'),
                    tags
                )
                
                # If we haven't seen this exact set of findings before, add it
                if fingerprint not in seen_fingerprints:
                    seen_fingerprints.add(fingerprint)
                    threat_intel.append(item)
                
            data['threat_intel'] = threat_intel
        except: data['threat_intel'] = []

        # Breach Data
        try:
            cursor.execute("SELECT * FROM breach_data WHERE target_id=?", (self.target_id,))
            data['breaches'] = [dict(row) for row in cursor.fetchall()]
        except: data['breaches'] = []
        
        # Search Results (Deduplicated)
        try:
            # Group by Snippet to avoid duplicate pastes with same content
            cursor.execute("SELECT source, title, snippet, risk_level FROM search_results WHERE target_id=? GROUP BY snippet", (self.target_id,))
            data['search_results'] = [dict(row) for row in cursor.fetchall()]
        except: data['search_results'] = []

        # Subdomains (Unique)
        try:
            cursor.execute("SELECT DISTINCT subdomain, ip_address FROM subdomains WHERE target_id=?", (self.target_id,))
            data['subdomains'] = [dict(row) for row in cursor.fetchall()]
        except: data['subdomains'] = []

        conn.close()
        return data

    def _get_html_template(self):
        """Define the HTML template"""
        return """
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: 'Helvetica', sans-serif; color: #333; line-height: 1.6; }
        .container { width: 100%; max-width: 800px; margin: 0 auto; }
        .header { text-align: center; background-color: #0d1117; color: #00ff9d; padding: 20px; border-bottom: 3px solid #00ff9d; }
        /* xhtml2pdf specific fix: ensure image has display block and doesn't float/collapse */
        .header img { 
            height: 80px; 
            width: 80px; 
            margin-bottom: 10px; 
            border-radius: 50%; 
            border: 2px solid #00ff9d; 
            display: inline-block;
            vertical-align: middle;
        }
        .header h1 { margin: 10px 0 5px 0; font-size: 28px; text-transform: uppercase; letter-spacing: 2px; }
        .header p { margin: 0; font-size: 14px; color: #888; }
        .section { margin-bottom: 30px; border: 1px solid #ddd; padding: 15px; border-radius: 5px; page-break-inside: avoid; }
        .section-title { font-size: 18px; font-weight: bold; border-bottom: 2px solid #00ff9d; padding-bottom: 5px; margin-bottom: 15px; color: #0d1117; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; font-size: 12px; }
        th { background-color: #f2f2f2; }
        .badge { display: inline-block; padding: 2px 5px; border-radius: 3px; font-size: 10px; color: white; }
        .badge-high { background-color: #d9534f; }
        .badge-med { background-color: #f0ad4e; }
        .badge-low { background-color: #5bc0de; }
        .badge-info { background-color: #5cb85c; }
        .footer { text-align: center; font-size: 10px; color: #777; margin-top: 50px; border-top: 1px solid #ddd; padding-top: 10px; }
        
        /* New Threat Intel Styles */
        .ti-card { background: #f9f9f9; border-left: 4px solid #00ff9d; padding: 10px; margin-bottom: 10px; }
        .ti-source { font-weight: bold; color: #333; font-size: 14px; margin-bottom: 5px; }
        .ti-stats { font-size: 11px; color: #666; margin-bottom: 5px; }
        .ti-details { font-size: 11px; background: #fff; border: 1px solid #eee; padding: 5px; margin-top: 5px; }
        .ti-tags span { background: #e1e4e8; color: #333; padding: 1px 4px; border-radius: 3px; font-size: 9px; margin-right: 3px; }
        .vuln-list { max-height: 100px; overflow-y: auto; font-size: 10px; margin-top: 5px; }
        .vuln-item { color: #d9534f; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            {% if logo_path %}
            <img src="{{ logo_path }}" alt="Logo">
            {% endif %}
            <h1>Argus OSINT Report</h1>
            <p>Confidential Intelligence Summary</p>
        </div>

        <div class="section">
            <div class="section-title">Target Overview</div>
            <p><strong>Target:</strong> {{ data.target.domain }}</p>
            <p><strong>Scan Date:</strong> {{ date }}</p>
            <p><strong>Risk Score:</strong> {{ data.target.risk_score|default(0) }}/100</p>
            {% if data.geolocation %}
            <p><strong>Location:</strong> {{ data.geolocation.city }}, {{ data.geolocation.country }} ({{ data.geolocation.isp }})</p>
            {% endif %}
        </div>

        {% if data.threat_intel %}
        <div class="section">
            <div class="section-title">Threat Intelligence</div>
            
            {% for item in data.threat_intel %}
            <div class="ti-card">
                <div class="ti-source">
                    {{ item.source }} 
                    <span class="badge {% if item.threat_score > 50 %}badge-high{% elif item.threat_score > 20 %}badge-med{% else %}badge-info{% endif %}" style="float:right">
                        Score: {{ item.threat_score }}
                    </span>
                </div>
                
                <div class="ti-stats">
                    <strong>Type:</strong> {{ item.indicator_type }} | <strong>Value:</strong> {{ item.indicator_value }}
                </div>

                <!-- VirusTotal Specific -->
                {% if item.source == 'VirusTotal' %}
                <div class="ti-details">
                    <div>
                        <span style="color:#d9534f">Malicious: {{ item.malicious_count }}</span> | 
                        <span style="color:#f0ad4e">Suspicious: {{ item.suspicious_count }}</span> | 
                        <span style="color:#5cb85c">Harmless: {{ item.harmless_count }}</span>
                    </div>
                     {% if item.details.categories %}
                    <div style="margin-top:5px; font-style:italic;">
                        Categories: 
                        {% for cat in item.details.categories.values() | unique | list %}
                            {{ cat }}{% if not loop.last %}, {% endif %}
                        {% endfor %}
                    </div>
                    {% endif %}
                </div>
                {% endif %}

                <!-- Shodan Specific -->
                {% if item.source == 'Shodan' %}
                <div class="ti-details">
                    <div><strong>OS:</strong> {{ item.details.os|default('N/A') }}</div>
                    <div><strong>ISP:</strong> {{ item.details.isp|default('N/A') }} (ASN: {{ item.details.asn|default('N/A') }})</div>
                    <div><strong>Open Ports:</strong> {{ item.details.ports|join(', ') }}</div>
                    
                    {% if item.details.hostnames %}
                    <div><strong>Hostnames:</strong> {{ item.details.hostnames|join(', ') }}</div>
                    {% endif %}

                    {% if item.details.vulns %}
                    <div style="margin-top:5px;"><strong>Vulnerabilities ({{ item.details.vulns|length }}):</strong></div>
                    <div class="vuln-list">
                        {% for vuln in item.details.vulns %}
                        <div class="vuln-item">{{ vuln }}</div>
                        {% endfor %}
                    </div>
                    {% else %}
                    <div style="color:#5cb85c; margin-top:5px;">No known vulnerabilities found.</div>
                    {% endif %}
                </div>
                {% endif %}
                
                <!-- OTX Specific -->
                {% if item.source == 'AlienVault OTX' %}
                <div class="ti-details">
                    <div><strong>Pulse Count:</strong> {{ item.details.pulse_count|default(0) }}</div>
                    <div><strong>Reputation:</strong> {{ item.details.reputation|default(0) }}</div>
                    {% if item.details.validation %}
                    <div style="margin-top:5px;"><strong>Validation:</strong></div>
                    <ul>
                    {% for v in item.details.validation %}
                        <li>{{ v.source }}: {{ v.message }}</li>
                    {% endfor %}
                    </ul>
                    {% endif %}
                </div>
                {% endif %}

                <!-- Censys Specific -->
                {% if item.source == 'Censys' %}
                <div class="ti-details">
                    {% if item.indicator_type == 'ip' %}
                    <div><strong>Exposed Services:</strong> {{ item.details.services_count|default(0) }}</div>
                    <div><strong>Open Ports:</strong> {{ item.details.ports|join(', ') }}</div>
                    {% if item.details.location %}
                    <div><strong>Location:</strong> {{ item.details.location.city }}, {{ item.details.location.country }}</div>
                    {% endif %}
                    {% if item.details.autonomous_system %}
                    <div><strong>ASN:</strong> {{ item.details.autonomous_system.asn }} ({{ item.details.autonomous_system.name }})</div>
                    {% endif %}
                    {% else %}
                    <div><strong>Related Hosts:</strong> {{ item.details.hit_count|default(0) }}</div>
                    <div><strong>Summary:</strong> {{ item.details.summary }}</div>
                    {% endif %}
                </div>
                {% endif %}

            </div>
            {% endfor %}
            
        </div>
        {% endif %}

        {% if data.findings %}
        <div class="section">
            <div class="section-title">Security Issues & Vulnerabilities</div>
            <table>
                <tr>
                    <th>Issue</th>
                    <th>Severity</th>
                    <th>Description</th>
                </tr>
                {% for item in data.findings %}
                <tr>
                    <td>{{ item.title }}</td>
                    <td>
                        <span class="badge {% if item.severity == 'High' or item.severity == 'Critical' %}badge-high{% elif item.severity == 'Medium' %}badge-med{% else %}badge-low{% endif %}">
                            {{ item.severity }}
                        </span>
                    </td>
                    <td>{{ item.description }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% endif %}

        {% if data.web_analysis %}
        <div class="section">
            <div class="section-title">Web Analysis Findings</div>
            <table>
                <tr>
                    <th>Finding</th>
                    <th>Severity</th>
                    <th>Details</th>
                </tr>
                {% for item in data.web_analysis %}
                <tr>
                    <td>{{ item.title }}</td>
                    <td>
                        <span class="badge {% if item.severity == 'High' or item.severity == 'Critical' %}badge-high{% elif item.severity == 'Medium' %}badge-med{% else %}badge-info{% endif %}">
                            {{ item.severity }}
                        </span>
                    </td>
                    <td>{{ item.description }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% endif %}

        {% if data.breaches %}
        <div class="section">
            <div class="section-title">Breached Identities</div>
            <table>
                <tr>
                    <th>Email</th>
                    <th>Breach Count</th>
                    <th>Latest Breach</th>
                </tr>
                {% for item in data.breaches %}
                <tr>
                    <td>{{ item.email }}</td>
                    <td><span class="badge badge-high">{{ item.breach_count }}</span></td>
                    <td>{{ item.most_recent_breach }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% endif %}

        {% if data.technologies %}
        <div class="section">
            <div class="section-title">Web Technologies</div>
            <table>
                <tr>
                    <th>Name</th>
                    <th>Category</th>
                    <th>Version</th>
                </tr>
                {% for item in data.technologies %}
                <tr>
                    <td>{{ item.name }}</td>
                    <td>{{ item.category }}</td>
                    <td>{{ item.version }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% endif %}

        {% if data.subdomains %}
        <div class="section">
            <div class="section-title">Attack Surface (Subdomains)</div>
            <table>
                <tr>
                    <th>Subdomain</th>
                    <th>IP Address</th>
                </tr>
                {% for sub in data.subdomains %}
                <tr>
                    <td>{{ sub.subdomain }}</td>
                    <td>{{ sub.ip_address }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% endif %}
        
        {% if data.ports %}
        <div class="section">
            <div class="section-title">Open Port Exposure</div>
            <table>
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Version</th>
                </tr>
                {% for port in data.ports %}
                <tr>
                    <td>{{ port.port }}/{{ port.protocol }}</td>
                    <td>{{ port.service }}</td>
                    <td>{{ port.version }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% endif %}

        {% if data.directories %}
        <div class="section">
            <div class="section-title">Directory Enumeration</div>
            <table>
                <tr>
                    <th>Path</th>
                    <th>Status</th>
                </tr>
                {% for item in data.directories %}
                <tr>
                    <td>{{ item.path }}</td>
                    <td>
                        <span class="badge {% if item.status_code == 200 %}badge-info{% else %}badge-med{% endif %}">
                            {{ item.status_code }}
                        </span>
                    </td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% endif %}
        
        {% if data.search_results %}
        <div class="section">
            <div class="section-title">Search Intelligence Findings</div>
            <table>
                <tr>
                    <th>Risk</th>
                    <th>Source</th>
                    <th>Title/Snippet</th>
                </tr>
                {% for item in data.search_results %}
                <tr>
                    <td>
                         <span class="badge {% if item.risk_level == 'High' or item.risk_level == 'Critical' %}badge-high{% elif item.risk_level == 'Medium' %}badge-med{% else %}badge-low{% endif %}">
                            {{ item.risk_level }}
                        </span>
                    </td>
                    <td>{{ item.source }}</td>
                    <td>{{ item.title }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% endif %}

        {% if data.emails %}
        <div class="section">
            <div class="section-title">Contact Intelligence</div>
            <ul>
                {% for item in data.emails %}
                <li>{{ item.email }} <span style="font-size:10px; color:#999">({{ item.source_url }})</span></li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}

        <div class="footer">
            <p>Generated by Argus OSINT Framework | Date: {{ date }}</p>
            <p>CONFIDENTIAL - AUTHORIZED EYES ONLY</p>
        </div>
    </div>
</body>
</html>
"""

    def generate_html(self, output_path=None):
        """Generate HTML report"""
        data = self._fetch_data()
        template = Template(self._get_html_template())
        
        # Check if logo exists
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
        """Generate PDF report"""
        data = self._fetch_data()
        template = Template(self._get_html_template())
        
        has_logo = os.path.exists(self.logo_path)
        # xhtml2pdf usually works better with absolute local paths
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
