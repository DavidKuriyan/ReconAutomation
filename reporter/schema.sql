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
CREATE UNIQUE INDEX IF NOT EXISTS idx_ports_unique 
    ON ports(target_id, port, protocol);

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

-- =============================================================================
-- NEW TABLES FOR ENHANCED RECONNAISSANCE MODULES
-- =============================================================================

-- 19. HTTP Methods (Method Enumeration)
CREATE TABLE IF NOT EXISTS http_methods (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    url TEXT NOT NULL,
    method TEXT NOT NULL,
    status_code INTEGER,
    allowed BOOLEAN DEFAULT 0,
    response_body_preview TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 20. DNS Zone Transfer
CREATE TABLE IF NOT EXISTS dns_zone_info (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    nameserver TEXT NOT NULL,
    zone_transfer_allowed BOOLEAN DEFAULT 0,
    record_count INTEGER DEFAULT 0,
    records_snippet TEXT,
    error TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 21. SSL/TLS Configuration
CREATE TABLE IF NOT EXISTS ssl_config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    host TEXT NOT NULL,
    port INTEGER DEFAULT 443,
    supports_ssl_v2 BOOLEAN DEFAULT 0,
    supports_ssl_v3 BOOLEAN DEFAULT 0,
    supports_tls_v1 BOOLEAN DEFAULT 0,
    supports_tls_v11 BOOLEAN DEFAULT 0,
    supports_tls_v12 BOOLEAN DEFAULT 0,
    supports_tls_v13 BOOLEAN DEFAULT 0,
    weak_ciphers TEXT,
    strong_ciphers TEXT,
    certificate_expiry_days INTEGER,
    self_signed BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 22. Traceroute
CREATE TABLE IF NOT EXISTS traceroute (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    target_host TEXT NOT NULL,
    hop_count INTEGER DEFAULT 0,
    hops_json TEXT,
    avg_rtt_ms REAL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 23. IP Reputation / Blacklist
CREATE TABLE IF NOT EXISTS ip_reputation (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    ip_address TEXT NOT NULL,
    blacklisted BOOLEAN DEFAULT 0,
    blacklist_sources TEXT,
    abuse_reports INTEGER DEFAULT 0,
    threat_score INTEGER DEFAULT 0,
    last_reported TEXT,
    isp TEXT,
    usage_type TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 24. SMTP User Enumeration
CREATE TABLE IF NOT EXISTS smtp_enum (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    server TEXT NOT NULL,
    username TEXT NOT NULL,
    found BOOLEAN DEFAULT 0,
    method TEXT,
    response TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 25. NTP Information
CREATE TABLE IF NOT EXISTS ntp_info (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    server TEXT NOT NULL,
    stratum INTEGER,
    reachability INTEGER,
    delay REAL,
    offset_sec REAL,
    peers_found INTEGER DEFAULT 0,
    clients_found INTEGER DEFAULT 0,
    monlist_enabled BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 26. SNMP Information
CREATE TABLE IF NOT EXISTS snmp_info (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    host TEXT NOT NULL,
    community_string TEXT DEFAULT 'public',
    accessible BOOLEAN DEFAULT 0,
    system_description TEXT,
    system_contact TEXT,
    system_location TEXT,
    system_name TEXT,
    uptime TEXT,
    services TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 27. SMB Shares
CREATE TABLE IF NOT EXISTS smb_shares (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    host TEXT NOT NULL,
    share_name TEXT NOT NULL,
    share_type TEXT,
    comment TEXT,
    accessible BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 28. LDAP Information
CREATE TABLE IF NOT EXISTS ldap_info (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    server TEXT NOT NULL,
    port INTEGER DEFAULT 389,
    accessible BOOLEAN DEFAULT 0,
    base_dn TEXT,
    naming_contexts TEXT,
    attribute_count INTEGER DEFAULT 0,
    attributes TEXT,
    ssl_supported BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 29. Historical WHOIS
CREATE TABLE IF NOT EXISTS whois_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    domain TEXT NOT NULL,
    snapshot_date TEXT,
    registrar TEXT,
    registrant_name TEXT,
    registrant_email TEXT,
    raw_data TEXT,
    source TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 30. BGP Information
CREATE TABLE IF NOT EXISTS bgp_info (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    ip_address TEXT NOT NULL,
    asn INTEGER,
    asn_name TEXT,
    asn_country TEXT,
    asn_routes TEXT,
    upstream_asns TEXT,
    peer_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 31. Malware Analysis Reports
CREATE TABLE IF NOT EXISTS malware_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    indicator TEXT NOT NULL,
    indicator_type TEXT,
    source TEXT,
    report_url TEXT,
    threat_score INTEGER DEFAULT 0,
    malware_family TEXT,
    first_seen TEXT,
    last_seen TEXT,
    tags TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 32. Web Forms
CREATE TABLE IF NOT EXISTS web_forms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    page_url TEXT NOT NULL,
    form_action TEXT,
    form_method TEXT DEFAULT 'GET',
    input_fields TEXT,
    has_password_field BOOLEAN DEFAULT 0,
    has_email_field BOOLEAN DEFAULT 0,
    has_file_upload BOOLEAN DEFAULT 0,
    form_type TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 33. Auth Pages
CREATE TABLE IF NOT EXISTS auth_pages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    page_url TEXT NOT NULL,
    auth_type TEXT,
    status_code INTEGER,
    has_login_form BOOLEAN DEFAULT 0,
    has_password_reset BOOLEAN DEFAULT 0,
    has_registration BOOLEAN DEFAULT 0,
    has_mfa_field BOOLEAN DEFAULT 0,
    detected_keywords TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 34. Job Postings
CREATE TABLE IF NOT EXISTS job_postings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    source TEXT,
    job_title TEXT,
    company TEXT,
    technologies TEXT,
    posting_url TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 35. Security Reports / Disclosures
CREATE TABLE IF NOT EXISTS security_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    source TEXT,
    title TEXT,
    report_url TEXT,
    severity TEXT,
    cve_id TEXT,
    published_date TEXT,
    summary TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 36. Cached Pages / Search Engine Cache
CREATE TABLE IF NOT EXISTS cached_pages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    page_url TEXT,
    cache_source TEXT,
    cache_date TEXT,
    content_snippet TEXT,
    found_keywords TEXT,
    is_available BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 37. Business Directory Info
CREATE TABLE IF NOT EXISTS business_info (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    source TEXT,
    company_name TEXT,
    description TEXT,
    industry TEXT,
    founded_year TEXT,
    employees TEXT,
    headquarters TEXT,
    revenue TEXT,
    social_links TEXT,
    raw_data TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 38. Cookie Security Audit
CREATE TABLE IF NOT EXISTS cookie_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    cookie_name TEXT NOT NULL,
    domain TEXT,
    path TEXT,
    secure_flag BOOLEAN DEFAULT 0,
    httponly BOOLEAN DEFAULT 0,
    samesite TEXT,
    expiry TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 39. DNSBL / Blacklist Check Results
CREATE TABLE IF NOT EXISTS dnsbl_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    blacklist_source TEXT NOT NULL,
    listed BOOLEAN DEFAULT 0,
    response TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 40. Response Code Map
CREATE TABLE IF NOT EXISTS response_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    url TEXT NOT NULL,
    status_code INTEGER,
    content_length INTEGER,
    content_type TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 41. RIR WHOIS Records
CREATE TABLE IF NOT EXISTS rir_whois (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    rir_name TEXT,
    whois_server TEXT,
    net_handle TEXT,
    net_range TEXT,
    organization TEXT,
    raw_data TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
