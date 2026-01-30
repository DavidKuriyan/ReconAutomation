# Argus OSINT Framework v2.0
 
A **professional-grade, ethical OSINT framework** with advanced intelligence gathering capabilities.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🌟 Enhanced Capabilities

### **1. Geolocation Intelligence (GEOINT)**
- ✅ IP address resolution and geolocation (MaxMind/ipapi)
- ✅ ISP, ASN, and organization lookup
- ✅ Reverse DNS enumeration
- ✅ Geographic coordinates and timezone
- ✅ Google Maps integration in reports

### **2. Interactive Recon Mode**
- ✅ **New CLI Menu system** (`run_scan.bat`)
- ✅ Passive, Active, Full, and Custom scan profiles
- ✅ Real-time feedback and progress tracking
- ✅ Post-scan report generation prompt

### **2. Social Media Intelligence (SOCMINT)**
- ✅ Username enumeration across 300+ platforms (Sherlock)
- ✅ Email-to-profile mapping
- ✅ GitHub, Twitter, LinkedIn, Instagram, Facebook discovery
- ✅ Automated profile aggregation

### **3. Breach Intelligence**
- ✅ Have I Been Pwned integration
- ✅ Email breach database checks
- ✅ Paste site monitoring
- ✅ Breach severity assessment

### **4. Threat Intelligence**
- ✅ **VirusTotal**: Domain/IP reputation scanning
- ✅ **Shodan**: CVE detection and service enumeration
- ✅ **AlienVault OTX**: Threat pulse correlation
- ✅ Threat scoring (0-100 risk assessment)

### **5. Metadata Extraction**
- ✅ Image EXIF data (GPS, camera info, timestamps)
- ✅ PDF metadata (author, creation date, software)
- ✅ Document fingerprinting
- ✅ Geolocation from embedded coordinates

### **6. Historical Intelligence**
- ✅ Wayback Machine snapshot discovery
- ✅ Archive.today lookups
- ✅ First/last seen timeline tracking
- ✅ Historical domain analysis

### **7. Search Engine Intelligence**
- ✅ Google Dorks (sensitive file discovery)
- ✅ GitHub code/secret search
- ✅ Pastebin monitoring
- ✅ Risk-level assessment (High/Medium/Low)

### **8. Classic OSINT (Original Features)**
- ✅ WHOIS lookups
- ✅ DNS enumeration (A, NS, MX, TXT, SOA)
- ✅ SSL/TLS certificate analysis
- ✅ Subdomain discovery (subfinder + crt.sh)
- ✅ Email harvesting
- ✅ SMTP server analysis
- ✅ Port scanning (Nmap or native socket)
- ✅ Banner grabbing
- ✅ Technology fingerprinting
- ✅ Directory enumeration
- ✅ Security header auditing

### **9. Ethical Safeguards**
- ✅ Legal disclaimer and consent verification
- ✅ Comprehensive audit logging
- ✅ Automatic rate limiting (API protection)
- ✅ GDPR/CCPA compliance features

---

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.8+
- Git

### 2. Installation

```powershell
# Navigate to repository
cd "d:\Cyber security Projects\Reconnaissance"

# Install dependencies
cd reporter
pip install -r requirements.txt
```

### 3. Optional: Configure API Keys

**All API keys are OPTIONAL**. The framework works without them but with reduced capabilities.

Create `.env` file from template:
```powershell
copy .env.example .env
```

> **⚠️ SECURITY WARNING:** Never commit your `.env` file to version control. It is already added to `.gitignore` to prevent accidental uploads. If you fork this repository, ensure your secrets remain local.

Edit `.env` and add your API keys:

| API | Purpose | Free Tier | Get Key |
|-----|---------|-----------|---------|
| **HIBP** | Breach checking | Yes (with key) | [Get Key](https://haveibeenpwned.com/API/Key) |
| **VirusTotal** | Malware scanning | 500/day | [Get Key](https://www.virustotal.com/gui/my-apikey) |
| **Shodan** | CVE detection | 100/month | [Get Key](https://account.shodan.io/) |
| **GitHub** | Code search | 5000/hour | [Get Token](https://github.com/settings/tokens) |
| **OTX** | Threat intel | Unlimited | [Get Key](https://otx.alienvault.com/api) |

### 4. Initialize Database

```powershell
cd d:\Cyber security Projects\Reconnaissance\reporter
python init_db.py
```

### 5. Start Dashboard

```powershell
python reporter.py
```

Dashboard available at: **http://localhost:5000**

### 6. Run Reconnaissance (Recommended)
Simply double-click `run_scan.bat` or run:
```powershell
.\run_scan.bat
```
This launches the **Interactive Menu** where you can choose:
1.  **Passive Scan** (Safe)
2.  **Active Scan** (Intrusive)
3.  **Full Scan** (Comprehensive)
4.  **Custom Scan**

### Manual Execution (Advanced)
```powershell
cd orchestrator
python orchestrator.py target.com --consent-given
```

---

## 📁 Project Structure

```
Reconnaissance/
├── orchestrator/
│   ├── orchestrator.py       # Main scan engine
│   ├── config.py              # Configuration management
│   └── modules/               # OSINT modules
│       ├── geo_intelligence.py
│       ├── socmint.py
│       ├── breach_intel.py
│       ├── threat_intel.py
│       ├── metadata_extractor.py
│       ├── historical_intel.py
│       └── search_intel.py
├── reporter/
│   ├── aether.db              # SQLite database
│   ├── reporter.py            # Flask dashboard
│   ├── schema.sql             # Database schema
│   └── requirements.txt       # Python dependencies
├── .env.example               # API key template
├── ETHICAL_GUIDELINES.md      # Legal & ethical policies
└── README.md                  # This file
```

---

## ⚙️ Configuration

### Environment Variables (.env)

```env
# API Keys (all optional)
HIBP_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
GITHUB_TOKEN=your_token_here

# Module Toggles
ENABLE_GEOLOCATION=true
ENABLE_SOCMINT=true
ENABLE_BREACH_INTEL=true
ENABLE_THREAT_INTEL=true
ENABLE_METADATA=true
ENABLE_HISTORICAL=true
ENABLE_SEARCH_INTEL=true

# Ethical Settings
REQUIRE_CONSENT=true
AUDIT_LOGGING=true
```

---

## 🔒 Ethical Usage

**⚠️ CRITICAL: Read ETHICAL_GUIDELINES.md before using this tool**

### Legal Requirements
- ✅ **Obtain explicit authorization** before scanning any target
- ✅ **Your own domains**: Always permitted
- ✅ **Bug bounty programs**: Follow program rules
- ❌ **Unauthorized targets**: ILLEGAL and PROHIBITED

### Responsible Use
1. Always get written permission
2. Respect rate limits and API terms
3. Handle personal data responsibly
4. Follow responsible disclosure practices
5. Comply with local laws (CFAA, GDPR, Computer Misuse Act)

**Consent Prompt**: The framework displays a legal disclaimer before each scan.

---

## 🎯 Usage Examples

### Basic Scan
```powershell
python orchestrator.py target.com
```

### With API Keys Configured
```powershell
# Ensure .env file has API keys, then run:
python orchestrator.py target.com

# Features enabled:
# ✓ Breach checking (HIBP)
# ✓ Threat intel (VirusTotal, Shodan, OTX)
# ✓ GitHub code search
```

### Automated/CI Pipeline
```powershell
# Skip interactive consent (use only if authorized)
python orchestrator.py target.com --consent-given
```

---

## 📊 Output

### Database
All findings stored in: `d:\Cyber security Projects\Reconnaissance\reporter\aether.db`

### Dashboard
Real-time web dashboard: **http://localhost:5000**
- Network topology visualization
- Breach intelligence summary
- Threat assessment scores
- Historical timeline
- Security findings

### Console Output
- Phase-based execution (Passive → Active → Search)
- Real-time status updates
- Color-coded risk levels 🔴🟡🟢
- Module execution tracking

---

## 🛠 Troubleshooting

### Database Locked
```powershell
# Reinitialize database with WAL mode
python init_db.py
```

### Missing Dependencies
```powershell
pip install -r requirements.txt --upgrade
```

### API Rate Limits
- Framework auto-throttles requests
- Free tiers have limits (see Configuration table)
- Upgrade to paid tiers for high-volume scanning

### Sherlock Not Found
```powershell
# Optional: Install Sherlock for enhanced SOCMINT
pip install sherlock-project
# OR fallback to manual platform checks (automatic)
```

### Module Not Working
- Check `.env` for required API keys
- Enable/disable modules in `.env`:
  ```env
  ENABLE_BREACH_INTEL=false  # Disable specific module
  ```

---

## 🎓 Module Details

| Module | Data Collected | API Required? |
|--------|---------------|--------------|
| **Geolocation** | IP, Country, ISP, ASN | No (ipapi.co) |
| **SOCMINT** | Social profiles, usernames | No (Sherlock optional) |
| **Breach Intel** | Email breaches, pastes | **Yes** (HIBP) |
| **Threat Intel (VT)** | Malware detections, reputation | **Yes** (VirusTotal) |
| **Threat Intel (Shodan)** | CVEs, exposed services | **Yes** (Shodan) |
| **Threat Intel (OTX)** | Threat pulses | No (limited access) |
| **Metadata** | EXIF, GPS, authors | No |
| **Historical** | Archive snapshots | No (Wayback API) |
| **Search Intel** | Dorks, GitHub leaks | GitHub Token optional |

---

## 📝 License & Disclaimer

**MIT License** - See LICENSE file

**Legal Disclaimer**: This tool is for authorized security testing only. The developers are NOT liable for misuse. Users are responsible for obtaining proper authorization and complying with applicable laws.

**By using Aether-Recon, you agree to use it ethically and legally.**

---

## 🤝 Contributing

Contributions welcome! Please:
1. Follow ethical guidelines
2. Add tests for new modules
3. Update documentation
4. Respect rate limits in code

---

## 📧 Support

- **Issues**: File a GitHub issue
- **Documentation**: Read `ETHICAL_GUIDELINES.md`
- **Updates**: Check for new versions regularly

**Version**: 2.0.0  
**Last Updated**: January 2026
