# Vulnerability Assessment Report: Corporate Network Segment

Date: 14/11/2025 
Scanner: Nessus  
Target: Simulated Corporate Network (192.168.1.0/24)

Executive Summary
Conducted comprehensive vulnerability assessment identifying 23 vulnerabilities across 15 hosts. Three critical vulnerabilities were identified requiring immediate remediation.

Critical Findings
| Severity | Vulnerability | CVE | CVSS | Affected Host | Recommendation |
|----------|---------------|-----|------|---------------|----------------|
| Critical | SMB Remote Code Execution | CVE-2017-0143 | 9.8 | 192.168.1.15 | Apply MS17-010 patch immediately |
| Critical | Apache Path Traversal | CVE-2021-41773 | 9.1 | 192.168.1.20 | Upgrade to Apache 2.4.51+ |
| High | WordPress SQL Injection | CVE-2022-21661 | 8.1 | 192.168.1.25 | Update WordPress to 5.8.3+ |

Risk Analysis
The SMB vulnerability (CVE-2017-0143) poses the highest risk as it's wormable and allows remote code execution without authentication. This could lead to complete domain compromise.

Remediation Timeline
- Critical: Patch within 24 hours
- High: Remediate within 72 hours  
- Medium: Address within 2 weeks

Skills Demonstrated
- Vulnerability Scanning & Analysis
- Risk Prioritization using CVSS

SOC Analysis: Brute Force Attack Detection
Incident ID: SOC-2024-001  
Date: 14/11/2025 
SIEM:Splunk  
Severity:Medium

Executive Summary
Detected and analyzed brute force attack against web application login portal. Incident contained and remediated within 45 minutes.

Detection
Splunk Query:
-- spl
index=web_logs sourcetype=access_ (status=401 OR status=404) 
stats count by client_ip, method, uri 
where count > 15
sort - count

Investigation Timeline
- 14:05: First 401 errors detected from IP 203.0.113.45
- 14:10: Correlation with firewall logs confirmed attack pattern  
- 14:15: 152 login attempts recorded within 10 minutes
- 14:20: IP blocked at firewall level
- 14:35: Incident documented and tickets closed
- Remediation Planning & Reporting

Indicators of Compromise (IOCs)
Attacker IP: 203.0.113.45
Target URL: /wp-admin/wp-login.php
Technique: Password Spraying
Volume: 152 attempts in 10 minutes

Recommendations
Implement account lockout policy (5 attempts = 30min lock)
Deploy CAPTCHA on login pages
Create automated SIEM alert for similar patterns

Skills Demonstrated
SIEM Query Development
Incident Response Procedures
Threat Hunting & Analysis
Security Documentation

File 3: Network Analysis
Path: network-analysis/ftp-credential-capture.md`
markdown
Network Analysis: Cleartext Credential Capture

Date: 14/11/2025  
Tool:Wireshark  
Protocol:FTP

Objective
Demonstrate security risks of unencrypted protocols by capturing and analyzing FTP authentication traffic.
Methodology
1. Captured network traffic during FTP session establishment
2. Applied Wireshark filter: `ftp`
3. Followed TCP stream to reconstruct session
4. Identified authentication mechanism
Findings
Captured FTP Session:
220 (vsFTPd 3.0.3)
USER admin
331 Please specify the password.
PASS Company123!
230 Login successful.

Security Implications
- Credentials transmitted in cleartext
- Susceptible to network sniffing
- Violates security best practices

Business Impact
- Potential unauthorized access to file server
- Data exfiltration risk
- Compliance violations (PCI DSS, GDPR)

Recommendations
1. Immediate: Replace FTP with SFTP/FTPS
2. Network: Segment legacy systems
3. Monitoring: Implement IDS rules for cleartext protocols

Skills Demonstrated
- Network Protocol Analysis
- Wireshark Proficiency  
- Security Risk Assessment
- Secure Configuration Guidance

Cybersecurity Portfolio

Junior Cybersecurity Specialist | SOC Analyst | (ISC)² CC Certified
Hands-on experience in vulnerability assessment, SOC operations, and network security analysis. This repository contains detailed lab reports and security analyses demonstrating practical cybersecurity skills.

Projects
[Vulnerability Management](vulnerability-assessment)
- Nessus Scan Analysis: Comprehensive vulnerability assessment with risk prioritization and remediation planning
- CVSS scoring and business impact analysis

[SOC Operations](siem-monitoring)
- Brute Force Detection: SIEM-based threat detection and incident response
- Splunk query development and security monitoring

[Network Security](network-analysis/)
- Protocol Analysis: Security assessment of network protocols and traffic inspection
- Wireshark analysis and cleartext credential capture

Technical Skills
- Security Tools: Nessus, Nmap, Wireshark, Burp Suite, Splunk, Metasploit
- Certifications: (ISC)² Certified in Cybersecurity, Cisco Cybersecurity, Palo Alto Networks
- Methods: Vulnerability Assessment, SIEM Monitoring, Incident Response, Network Analysis

Contact
- Email: abdouabon10@gmail.com
- LinkedIn: [www.linkedin.com/in/abdou-ahidjo]
- Location: Dubai, UAE | Available Immediately for Cybersecurity Roles

> This portfolio demonstrates analytical thinking, security documentation skills, and practical understanding of cybersecurity fundamentals.
