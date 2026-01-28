# Ethical Guidelines for Argus OSINT Framework

## Legal Disclaimer

**IMPORTANT: READ BEFORE USE**

This framework is designed for **ethical and legal** Open Source Intelligence (OSINT) gathering only. By using this tool, you agree to the following terms:

### Authorized Use Only

- ✅ **Legal Purposes**: Security assessments, vulnerability research, threat intelligence gathering
- ✅ **With Permission**: You have explicit written authorization to scan the target
- ✅ **Your Own Assets**: Testing your own domains, infrastructure, and applications
- ✅ **Bug Bounty Programs**: Targets explicitly listed in bug bounty programs
- ✅ **Research**: Academic research with proper ethical approval

### Prohibited Use

- ❌ **Unauthorized Scanning**: Scanning targets without explicit permission
- ❌ **Malicious Intent**: Using gathered intelligence for illegal activities
- ❌ **Harassment**: Stalking, doxxing, or harassing individuals
- ❌ **Corporate Espionage**: Gathering competitive intelligence illegally
- ❌ **Identity Theft**: Using personal information for fraudulent purposes

## Scope of Authorized Intelligence Gathering

### Passive Reconnaissance (Generally Legal)
- Public WHOIS data
- DNS records
- SSL/TLS certificate information
- Historical website archives (Wayback Machine)
- Public social media profiles
- Published breach data (Have I Been Pwned)
- Search engine results

### Active Reconnaissance (Requires Authorization)
- Port scanning
- Directory enumeration
- Banner grabbing
- Vulnerability scanning
- Service fingerprinting

## Responsible Disclosure

If you discover vulnerabilities during your reconnaissance:

1. **Document Findings**: Record all details professionally
2. **Contact Target**: Reach out via security@ or published security contact
3. **Allow Time**: Give reasonable time (30-90 days) for remediation
4. **No Public Disclosure**: Do not publish vulnerabilities until fixed
5. **Follow Programs**: Adhere to bug bounty program rules if applicable

## Data Retention and Privacy

### Data Handling
- Store reconnaissance data securely
- Encrypt sensitive findings
- Limit access to authorized personnel only
- Delete data when no longer needed

### Personal Information
- Treat personal information (emails, names, addresses) with respect
- Do not share or publish personal information
- Comply with GDPR, CCPA, and other privacy regulations
- Obtain consent before using personal data beyond OSINT

## Rate Limiting and Resource Respect

### API Usage
- Respect API rate limits (automatically enforced by framework)
- Use free tiers responsibly
- Do not attempt to bypass rate limiting
- Obtain paid tiers for high-volume scanning

### Target Resources
- Avoid aggressive scanning that could cause denial of service
- Use reasonable thread limits (configured by default)
- Scan during off-peak hours when possible
- Stop scanning if requested by target

## Ethical Research Principles

1. **Transparency**: Be honest about your intentions
2. **Minimize Harm**: Avoid actions that could harm individuals or organizations
3. **Respect Privacy**: Value people's right to privacy
4. **Accountability**: Take responsibility for your actions
5. **Legal Compliance**: Follow all applicable laws and regulations

## Country-Specific Laws

### United States
- Computer Fraud and Abuse Act (CFAA)
- Electronic Communications Privacy Act (ECPA)
- Stored Communications Act (SCA)

### European Union
- General Data Protection Regulation (GDPR)
- Network and Information Security Directive (NIS2)

### United Kingdom
- Computer Misuse Act 1990
- Data Protection Act 2018

### International
- Budapest Convention on Cybercrime
- Various national cybercrime laws

**Consult with legal counsel in your jurisdiction before conducting reconnaissance.**

## Certification and Audit

This framework implements:

- ✓ Consent verification before active scanning
- ✓ Audit logging of all reconnaissance activities
- ✓ Automatic rate limiting to prevent abuse
- ✓ Graceful degradation when API keys unavailable
- ✓ Data retention tracking

## Reporting Concerns

If you witness misuse of this framework:

1. **Document** the misuse with evidence
2. **Report** to appropriate authorities
3. **Contact** the framework maintainers

## Updates and Compliance

This document may be updated to reflect:
- Changes in laws and regulations
- New ethical guidelines from security community
- Feedback from users and stakeholders

**Last Updated**: January 2026

---

## Your Responsibility

**By using Argus OSINT Framework, you acknowledge that:**

1. You are responsible for ensuring your use complies with all applicable laws
2. You will obtain proper authorization before scanning any target
3. You will use the framework ethically and responsibly
4. The developers are not liable for misuse of this tool

**When in doubt, don't scan. Get explicit permission first.**
