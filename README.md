# 🔎 Argus OSINT Framework v2.0
### 📡 Discover • Analyze • Report — Ethically

Argus is a **professional-grade, ethical OSINT and reconnaissance framework** designed for security research, blue team analysis, and authorized penetration testing. It emphasizes modularity, safety, auditability, and integration with real-world threat intelligence sources — all backed by a **config-driven, defensive-by-design** architecture.

> [!WARNING]
> **Authorized use only.** This framework is intended strictly for ethical security testing and research with proper permission.

---

## 🧠 Core Capabilities

### 🔍 Passive Intelligence Gathering (Stealth)
- **WHOIS & Domain Identity** — Native socket WHOIS + WhoisXML API backfill for registrar, creation/expiry dates, registrant details
- **DNS Enumeration** — A, NS, MX, TXT, SOA records with TTL
- **SSL/TLS Analysis** — Certificate issuer, subject, validity, expiry check
- **Subdomain Discovery** — 25+ free sources + API-based (VirusTotal, SecurityTrails, Shodan, etc.)
- **Email Harvesting** — theHarvester integration + homepage scraping
- **SMTP Analysis** — MX banner grabbing & server fingerprinting
- **Historical WHOIS** — WhoisXML API + domaintools.com fallback
- **Reverse WHOIS** — Find related domains by registrant/email
- **BGP/ASN Analysis** — ipapi.co + HackerTarget ASN lookups
- **DNSBL Reputation Check** — Spamhaus, SpamCop, Barracuda, Sorbs & more
- **AbuseIPDB** — IP abuse score & threat reporting
- **Search Engine IP** — DuckDuckGo threat references

### ⚙️ Active Reconnaissance (Optional & Controlled)
- **Ping Sweep** — ICMP host discovery
- **TCP/UDP Port Scanning** — 200+ ports with Nmap or native socket fallback
- **Service Fingerprinting** — Banner grabbing with protocol-specific probes (HTTP, HTTPS, SSH, FTP, SMTP, MySQL, RDP, POP3, IMAP)
- **OS Fingerprinting** — TTL analysis + Nmap -O fallback
- **Directory Busting** — 30+ common paths with status code mapping
- **DNS Zone Transfer** — AXFR attempt from authoritative nameservers
- **Security Header Analysis** — HSTS, CSP, X-Frame-Options, etc.
- **SNMP / SMB / LDAP / NTP Enumeration** — Protocol-level probes
- **Enhanced SMTP Enumeration** — VRFY, EXPN, EHLO capabilities
- **Tech Detection** — 125+ signatures via TechDetector + TechChecker.io API
- **Web Robots/Security.txt/Sitemap Discovery**

### 🛡️ Threat Intelligence
- **VirusTotal** — Domain/IP reputation & resolution history
- **Shodan** — Infrastructure intelligence, ports, services, CVEs
- **AlienVault OTX** — Threat pulses & indicators of compromise
- **Censys** — Certificate transparency & exposure mapping
- **AbuseIPDB** — IP abuse confidence scoring
- **DNSBL** — Real-time blacklist status (8 DNSBLs)

### 🔎 Search Intelligence
- **GitHub Reconnaissance** for exposed secrets, hardcoded credentials, config leaks, sensitive references
- **Google Dorking integration**
- **DuckDuckGo passive search**

### 🌐 Web Analysis
- **Live Server Probing** — HTTP/HTTPS on all configured ports (httpx or Python)
- **CMS Detection** — 7 CMS signatures (WordPress, Drupal, Joomla, Magento, Shopify, Ghost, Laravel)
- **Virtual Host Fuzzing** — 15 vhost prefixes per base domain
- **URL Extraction** — katana crawling + Python fallback
- **JavaScript Analysis** — Secret scanning (AWS keys, API keys, JWT, passwords, emails, internal URLs)
- **Source Map Extraction** — Exposed .map file discovery
- **Favicon Analysis** — Hash calculation for Shodan search
- **GraphQL Detection** — Endpoint discovery + introspection probe
- **Parameter Discovery** — arjun + common parameter wordlist
- **WebSocket Auditing** — Origin bypass & upgrade handshake validation
- **gRPC Reflection** — grpcurl probe + port scanning
- **IIS Shortname Scanning** — 8.3 filename disclosure detection
- **HTTP Method Enumeration** — PUT, DELETE, TRACE, CONNECT detection
- **Form Enumeration** — Login, upload, search, registration form discovery
- **Authentication Page Identification** — Admin, MFA, password reset pages
- **SSL/TLS Configuration Testing** — Protocol version detection & weak cipher check
- **Cookie Security Audit** — Secure, HttpOnly, SameSite validation
- **Response Code Mapping** — 30+ paths across status codes
- **Password Dictionary Generation** — Context-aware password candidates

### 📊 Reporting
- **Interactive HTML Dashboard** — v2 template with all scan sections
- **Executive-ready PDF Reports** — xhtml2pdf generation
- **Structured SQLite Storage** — `argus.db` with 30+ tables
- **Risk Scoring** — Automated 0–100 scoring based on findings

### 🛑 Safety, Ethics & Compliance
- ✅ **Explicit consent confirmation before scans**
- ✅ **Full audit logging**
- ✅ **Configurable rate limits per API**
- ✅ **Module-level enable/disable**
- ❌ **No exploitation modules**
- ❌ **No credential brute-forcing**
- ❌ **No bypass or evasion techniques**

**This tool collects intelligence — it does not attack.**

---

## 🏗️ Architecture Overview

```text
┌──────────────────┐
│   User CLI/Args  │
│  run_scan.bat /  │
│  orchestrator.py │
└──────┬───────────┘
       │
┌──────▼────────────────────────────────┐
│ Orchestrator Engine (ReconEngine)     │
│ ├─ Consent Check + Audit Logging      │
│ ├─ Phase Mgmt (passive/active/search) │
│ ├─ Execution Wrapper (error isolation)│
│ └─ Risk Score Calculator              │
└──────┬────────────────────────────────┘
       │
┌──────▼──────────────────────────────────────┐
│ Intelligence Modules (20+)                  │
│                                             │
│ ┌─ Passive Recon ───────────────────────┐   │
│ │ WHOIS / DNS / SSL / Subdomains / BGP  │   │
│ │ Email / SMTP / DNSBL / AbuseIPDB      │   │
│ │ Historical WHOIS / Reverse WHOIS      │   │
│ └───────────────────────────────────────┘   │
│ ┌─ Active Recon ───────────────────────┐   │
│ │ Port Scan / Dir Bust / Tech Detect   │   │
│ │ SNMP / SMB / LDAP / NTP / SMTP enum  │   │
│ │ OS Fingerprint / DNS Zone Transfer   │   │
│ └───────────────────────────────────────┘   │
│ ┌─ Web Analysis ───────────────────────┐   │
│ │ Web Probing / CMS / VHOST / JS Sec   │   │
│ │ GraphQL / WebSocket / gRPC / Fuzzing │   │
│ │ SSL Test / Cookie Audit / Form Enum  │   │
│ └───────────────────────────────────────┘   │
│ ┌─ Threat Intel / Search / Geo / Meta ─┐   │
│ │ VT / Shodan / OTX / Censys / GitHub   │   │
│ │ Geolocation / Metadata Extraction    │   │
│ └───────────────────────────────────────┘   │
└──────┬──────────────────────────────────────┘
       │
┌──────▼──────────────────────┐
│ Database (argus.db / SQLite)│
│ 30+ tables                  │
└──────┬──────────────────────┘
       │
┌──────▼──────────────────────┐
│ Reporting Engine            │
│ ├─ HTML (Jinja2 + v2 theme)│
│ └─ PDF (xhtml2pdf)          │
└─────────────────────────────┘
```

---

## 🚀 Quick Start

### 📦 Requirements
- **Python 3.8+**
- **Git**
- Internet connection (for threat APIs)
- Optional: `nmap`, `httpx`, `katana`, `theHarvester`, `subfinder`, etc.

### 📥 Installation

**Windows (PowerShell)**
```powershell
git clone https://github.com/DavidKuriyan/ReconAutomation.git
cd ReconAutomation
pip install -r requirements.txt
```

**Linux / macOS**
```bash
git clone https://github.com/DavidKuriyan/ReconAutomation.git
cd ReconAutomation
pip3 install -r requirements.txt
```

**Create local config for API keys:**
```bash
# Edit .env.local with your API keys (see Supported APIs section)
# Only WhoisXML API key is minimally required for WHOIS backfill
```

### ▶️ Usage

**Interactive Mode (Recommended)**
```powershell
.\run_scan.bat
```
Then follow the prompts to enter a target and select scan mode.

**Direct CLI Mode**
```bash
# Full scan (passive + active + web analysis)
python orchestrator/orchestrator.py example.com --mode full

# Passive-only (stealth, no intrusive probes)
python orchestrator/orchestrator.py example.com --mode passive

# Active-only (ports, dir busting, tech detection)
python orchestrator/orchestrator.py example.com --mode active

# Skip consent prompt (only if authorized)
python orchestrator/orchestrator.py example.com --mode full --consent-given
```

### 📋 Scan Phases
| Phase | Mode | Description |
| :--- | :--- | :--- |
| 1. Passive Recon | `passive` | WHOIS, DNS, SSL, subdomains, emails, DNSBL, BGP, historical WHOIS |
| 2. Active Recon | `active` | Ping, ports, dir busting, tech detect, SNMP/SMB/LDAP/NTP/SMTP enum |
| 3. Search Intel | `search` | GitHub dorking, search engine intelligence |
| 4. Web Analysis | `web` | Probing, CMS, JS analysis, GraphQL, WS, gRPC, SSL test, cookie audit |
| 5. Reporting | — | Interactive HTML + PDF generation with risk scoring |

---

## 🔐 API Configuration

Create a `.env.local` file in the project root (already `.gitignored`):

```bash
# .env.local — Add only the APIs you have keys for
WHOISXML_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
GITHUB_TOKEN=your_token_here
OTX_API_KEY=your_key_here
CENSYS_API_ID=your_id_here
CENSYS_API_SECRET=your_secret_here
HIBP_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
IPINFO_API_KEY=your_key_here
TECHCHECKER_API_KEY=your_key_here
```

> [!CAUTION]
> **Never commit `.env.local`** — it's `.gitignored` by default.

### Supported APIs

| Service | Purpose | Free Tier | Used In |
| :--- | :--- | :--- | :--- |
| **WhoisXML** | Historical WHOIS, Reverse WHOIS, WHOIS backfill | 500/month | `passive_recon.py` |
| **VirusTotal** | Domain/IP reputation, resolutions | 500 req/day | `threat_intel.py` |
| **Shodan** | Ports, services, CVEs, infrastructure | Limited | `threat_intel.py` |
| **AlienVault OTX** | Threat pulses & IoCs | Unlimited | `threat_intel.py` |
| **Censys** | Certificate transparency, exposure | Limited | `threat_intel.py` |
| **GitHub** | Secret scanning, code intelligence | 5000 req/hr | `search_intel.py` |
| **HIBP** | Breached account detection | ❌ Paid | `breach_intel.py` |
| **AbuseIPDB** | IP abuse scoring & reports | 1000 req/day | `passive_recon.py` |
| **IPinfo** | IP geolocation & ASN data | 50k req/month | `geo_intelligence.py` |
| **TechChecker** | Tech stack detection | Free | `tech_detector.py` |
| **SecurityTrails** | DNS & subdomain history | Limited | `passive_sources.py` |
| **URLScan.io** | Website screenshot & analysis | 100/month | `passive_sources.py` |
| **Chaos (ProjectDiscovery)** | Subdomain datasets | Free | `passive_sources.py` |
| **Brave Search** | Search intelligence | 2000 req/month | `passive_sources.py` |
| **Hunter.io** | Email finding | 25 req/month | `passive_sources.py` |

The framework **degrades gracefully** — missing API keys simply skip their respective features without crashing.

---

## ⚙️ Configuration

All settings are managed from a single file: `orchestrator/config.py`

### What You Can Configure

| Category | Settings |
| :--- | :--- |
| **API Keys** | 20+ API keys loaded from environment |
| **Rate Limits** | Per-API request throttling (seconds between requests) |
| **Module Toggles** | Enable/disable each module independently |
| **Timeouts** | HTTP, DNS, and command execution timeouts |
| **Threading** | Max workers for ports, directories, subdomains, general tasks |
| **Port Scanning** | Custom TCP/UDP port lists, HTTP/HTTPS port sets |
| **Web Probing** | Web port list, vhost prefixes, GraphQL endpoints, gRPC ports |
| **Safety** | Consent requirement toggle, audit logging toggle |
| **Tool Paths** | Override paths for external tools (httpx, nuclei, katana, ffuf, etc.) |

Environment variables override all defaults — making it easy to customize per-deployment.

---

## 📁 Project Structure

```text
Argus-OSINT/
├── orchestrator/
│   ├── orchestrator.py          # Main engine — scan orchestration, consent, reporting
│   ├── config.py                # All configuration (API keys, timeouts, ports, modules)
│   ├── utils.py                 # Shared utilities (USER_AGENTS, headers, check_tool, run_command)
│   └── modules/
│       ├── __init__.py          # Module exports
│       ├── passive_recon.py     # WHOIS, DNS, SSL, subdomains, DNSBL, BGP, historical WHOIS
│       ├── active_recon.py      # Port scan, dir busting, tech detect, SNMP/SMB/LDAP/NTP/SMTP
│       ├── web_analysis.py      # Web probing, CMS, JS analysis, GraphQL, WS, gRPC, SSL test
│       ├── passive_sources.py   # Subdomain discovery from 25+ free + API sources
│       ├── external_tools.py    # Wrappers for theHarvester, Amass, etc.
│       ├── threat_intel.py      # VirusTotal, Shodan, OTX, Censys integrations
│       ├── search_intel.py      # GitHub dorking, search engine queries
│       ├── breach_intel.py      # Have I Been Pwned breach checks
│       ├── geo_intelligence.py  # Geolocation, IPinfo, IP geocoding
│       ├── socmint.py           # Social media intelligence
│       ├── historical_intel.py  # Wayback Machine & historical endpoint discovery
│       ├── metadata_extractor.py# Document metadata analysis
│       ├── tech_detector.py     # 125+ technology signature detector
│       ├── tech_signatures.py   # Signatures database for tech_detector
│       └── reporting.py         # HTML + PDF report generator (Jinja2 + xhtml2pdf)
├── reporter/
│   ├── reporter.py              # Standalone report viewer
│   ├── argus.db                 # SQLite database (auto-generated)
│   ├── schema.sql               # Database schema definition
│   ├── init_db.py               # Database initializer
│   ├── templates/
│   │   ├── report.html          # Original report template
│   │   └── report_v2.html       # Enhanced report template with all sections
│   └── reports/                 # Generated reports (HTML + PDF)
├── tests/
│   └── test_utils.py            # Unit tests for shared utilities
├── .env.local                   # Local API keys (gitignored — create this!)
├── .gitignore
├── requirements.txt             # Python dependencies
├── run_scan.bat                 # Windows quick-launch script
├── test_full_scan.py            # Integration test script
├── test_report_generation.py    # Report generation test
├── verify_fixes.py              # Verification script
├── verify_integration.py        # Integration verification
├── upgrade.md                   # Upgrade notes
├── README.md                    # ← You are here
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
└── ETHICAL_GUIDELINES.md
```

---

## 🔬 Advanced Features

### Config-Driven Port Scanning
Edit `orchestrator/config.py` or set environment variables:
```bash
COMMON_TCP_PORTS="21,22,23,25,53,80,443,8080,8443"
COMMON_UDP_PORTS="53,67,68,69,123,161,162,500"
HTTP_TIMEOUT_FAST=3
MAX_WORKERS_GENERAL=25
```

### Scan Modes
| Flag | Behavior |
| :--- | :--- |
| `--mode full` | Everything (recommended for deep analysis) |
| `--mode passive` | Stealth only — no direct connection to target |
| `--mode active` | Intrusive probes (ports, directories, tech) |
| `--consent-given` | Skip consent prompt (for automated pipelines) |

### Ethical Safeguards
- **Consent gate** blocks execution without explicit authorization
- **Audit logging** records every action per target
- **Rate limiting** prevents aggressive scanning
- **Configurable timeouts** prevent resource exhaustion
- **Module isolation** — one module failure never crashes the entire scan

---

## 🤝 Contributing

Contributions are welcome!

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Follow coding & ethics guidelines
4. Run tests: `python -m pytest tests/ -v`
5. Submit a Pull Request

Please read:
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- [ETHICAL_GUIDELINES.md](ETHICAL_GUIDELINES.md)

---

## ⚖️ License & Legal Disclaimer

**MIT License**

> [!IMPORTANT]
> This framework is provided for **educational and authorized security testing only**.
> The developers assume no liability for misuse.

**By using Argus OSINT Framework, you agree to operate within legal and ethical boundaries.**
