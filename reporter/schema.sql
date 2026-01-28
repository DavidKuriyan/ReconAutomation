-- schema.sql

-- 1. Core Targets
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE NOT NULL,
    risk_score INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Domain Intelligence (WHOIS)
CREATE TABLE IF NOT EXISTS domain_info (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    registrar TEXT,
    creation_date TEXT,
    expiration_date TEXT,
    registrant_name TEXT,
    registrant_email TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 3. DNS Map
CREATE TABLE IF NOT EXISTS dns_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    record_type TEXT NOT NULL,
    value TEXT NOT NULL,
    ttl INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 4. SSL Analysis
CREATE TABLE IF NOT EXISTS ssl_info (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    issuer TEXT,
    subject TEXT,
    valid_from TEXT,
    valid_to TEXT,
    has_expired BOOLEAN,
    sans TEXT, -- Subject Alternative Names (comma separated)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 5. Attack Surface (Subdomains & IPs)
CREATE TABLE IF NOT EXISTS subdomains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    subdomain TEXT UNIQUE NOT NULL,
    ip_address TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 6. Network (Ports)
CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    subdomain_id INTEGER REFERENCES subdomains(id),
    port INTEGER NOT NULL,
    protocol TEXT DEFAULT 'tcp',
    service TEXT,
    version TEXT,
    state TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 7. Web Recon (Technologies & Directories)
CREATE TABLE IF NOT EXISTS technologies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    subdomain_id INTEGER REFERENCES subdomains(id),
    name TEXT NOT NULL,
    version TEXT,
    category TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS directories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    subdomain_id INTEGER REFERENCES subdomains(id),
    path TEXT NOT NULL,
    status_code INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 8. Intelligence (Emails)
CREATE TABLE IF NOT EXISTS emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    email TEXT UNIQUE NOT NULL,
    source_url TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 9. Findings (Vulnerabilities)
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    subdomain_id INTEGER REFERENCES subdomains(id),
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT,
    remediation TEXT,
    url TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 10. Event Queue (IPC)
CREATE TABLE IF NOT EXISTS event_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel TEXT NOT NULL,
    message TEXT NOT NULL,
    processed BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 11. Geolocation Intelligence (IP-based)
CREATE TABLE IF NOT EXISTS geolocation (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    ip_address TEXT NOT NULL,
    country TEXT,
    region TEXT,
    city TEXT,
    latitude REAL,
    longitude REAL,
    isp TEXT,
    organization TEXT,
    asn TEXT,
    asn_org TEXT,
    timezone TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 12. Social Media Intelligence (SOCMINT)
CREATE TABLE IF NOT EXISTS social_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    platform TEXT NOT NULL,
    username TEXT NOT NULL,
    profile_url TEXT,
    email TEXT,
    status TEXT, -- 'Found', 'Not Found', 'Error'
    additional_info TEXT, -- JSON data
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 13. Breach Intelligence
CREATE TABLE IF NOT EXISTS breach_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    email TEXT NOT NULL,
    breach_count INTEGER DEFAULT 0,
    breach_names TEXT, -- Comma-separated breach names
    paste_count INTEGER DEFAULT 0,
    most_recent_breach TEXT,
    is_sensitive BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 14. Threat Intelligence
CREATE TABLE IF NOT EXISTS threat_intel (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    source TEXT NOT NULL, -- 'VirusTotal', 'Shodan', 'OTX', 'Censys'
    indicator_type TEXT, -- 'domain', 'ip', 'url', 'hash'
    indicator_value TEXT NOT NULL,
    threat_score INTEGER DEFAULT 0, -- 0-100
    malicious_count INTEGER DEFAULT 0,
    suspicious_count INTEGER DEFAULT 0,
    harmless_count INTEGER DEFAULT 0,
    tags TEXT, -- Comma-separated tags
    threat_categories TEXT, -- Malware, Phishing, etc.
    last_analysis_date TEXT,
    cve_list TEXT, -- CVEs found (from Shodan)
    additional_data TEXT, -- JSON for raw data
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 15. Metadata Extraction
CREATE TABLE IF NOT EXISTS metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    file_url TEXT NOT NULL,
    file_type TEXT, -- 'image', 'pdf', 'document'
    file_name TEXT,
    author TEXT,
    creator TEXT,
    producer TEXT,
    creation_date TEXT,
    modification_date TEXT,
    gps_latitude REAL,
    gps_longitude REAL,
    camera_make TEXT,
    camera_model TEXT,
    software TEXT,
    raw_metadata TEXT, -- JSON for all metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 16. Historical Intelligence
CREATE TABLE IF NOT EXISTS historical_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    source TEXT NOT NULL, -- 'WaybackMachine', 'Archive.today'
    snapshot_url TEXT,
    snapshot_date TEXT,
    snapshot_count INTEGER,
    first_seen TEXT,
    last_seen TEXT,
    status TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 17. Search Intelligence (Dorks, GitHub, Pastebin)
CREATE TABLE IF NOT EXISTS search_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    source TEXT NOT NULL, -- 'Google', 'GitHub', 'Pastebin'
    search_type TEXT, -- 'dork', 'code', 'paste'
    query TEXT,
    result_url TEXT,
    title TEXT,
    snippet TEXT,
    risk_level TEXT, -- 'Critical', 'High', 'Medium', 'Low'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 18. Audit Log (Ethical Tracking)
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    action TEXT NOT NULL, -- 'scan_started', 'consent_given', 'module_executed'
    module_name TEXT,
    user_ip TEXT,
    consent_given BOOLEAN DEFAULT 0,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    notes TEXT
);
