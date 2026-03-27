# Week 2 — Master Lab Notes
**CYART SOC Training | Practical Application**

---

## Lab 1 — Advanced Log Analysis

### Tools
- Elastic Security (Kibana + Elasticsearch)
- Security Onion
- Google Sheets (documentation)

### Key Concepts
- **Log Correlation**: Linking related events across different sources using timestamps, IPs, or user accounts
- **Anomaly Detection**: Creating threshold-based rules to flag unusual activity
- **Log Enrichment**: Adding context (e.g., GeoIP, hostname resolution) to raw logs

### Important Event IDs (Windows)
| Event ID | Description |
|---|---|
| 4625 | Failed logon attempt |
| 4624 | Successful logon |
| 4648 | Logon with explicit credentials |
| 4720 | User account created |
| 4728 | Member added to security group |
| 4776 | Credential validation |

### Elastic KQL Quick Reference
```kql
# Filter failed logins
event.code: "4625"

# Failed logins from specific IP
event.code: "4625" AND source.ip: "192.168.1.100"

# High data transfer
network.bytes > 1048576

# Combine: failed login + outbound traffic
event.code: "4625" AND destination.ip: "8.8.8.8"
```

### Sample Log Correlation Table
| Timestamp | Event ID | Source IP | Destination IP | Notes |
|---|---|---|---|---|
| 2025-08-18 12:00:00 | 4625 | 192.168.1.100 | 8.8.8.8 | Suspicious DNS request |
| 2025-08-18 12:01:00 | 4625 | 192.168.1.100 | 8.8.8.8 | 2nd failed login |
| 2025-08-18 12:02:00 | 4625 | 192.168.1.100 | 8.8.8.8 | Brute force pattern |

---

## Lab 2 — Threat Intelligence Integration

### Tools
- Wazuh (SIEM/EDR)
- AlienVault OTX (Threat feeds)
- TheHive (Case management)

### IOC Types
- **IP addresses** (malicious C2 servers)
- **Domain names** (phishing/malware domains)
- **File hashes** (MD5, SHA1, SHA256)
- **URLs** (malicious links)
- **Email addresses** (phishing sources)

### MITRE ATT&CK: T1078 — Valid Accounts
- Adversaries may use compromised credentials to access systems
- Detection: Monitor for unusual login times, locations, or access patterns
- Wazuh query: `user.name != "system" AND event.code: "4624"`

### Alert Enrichment Template
| Alert ID | IP | Reputation | OTX Pulses | Notes |
|---|---|---|---|---|
| 003 | 192.168.1.100 | Malicious (OTX) | 3 pulses | Linked to C2 server |

---

## Lab 3 — Incident Escalation Practice

### Tools
- TheHive (Case + ticket management)
- Google Docs (SITREP writing)
- Splunk Phantom / SOAR (automation)

### Escalation Decision Matrix
| Severity | Priority | Action | SLA |
|---|---|---|---|
| Critical | P1 | Immediate escalation | 15 min |
| High | P2 | Escalate to Tier 2 | 1 hour |
| Medium | P3 | Investigate + monitor | 4 hours |
| Low | P4 | Log and queue | 24 hours |

### SITREP Structure
```
Title: [Incident Name]
Date/Time: [Detection timestamp]
Analyst: [Name]
Summary: [1-2 sentences describing the incident]
Affected Systems: [Hostname/IP]
MITRE Technique: [TXxxx]
Actions Taken: [What was done]
Status: [Open/Contained/Resolved]
Next Steps: [Recommended actions]
```

---

## Lab 4 — Alert Triage with Threat Intelligence

### Tools
- Wazuh, VirusTotal, AlienVault OTX

### Triage Priority Assessment
| Factor | High | Medium | Low |
|---|---|---|---|
| Data sensitivity | PII/Critical | Internal | Public |
| Affected systems | Server/DC | Workstation | Test |
| IOC confirmed | Yes | Partial | No |
| MITRE technique | Active | Passive | Unknown |

### PowerShell Execution Red Flags
- Execution Policy bypass: `-ExecutionPolicy Bypass`
- Encoded commands: `-EncodedCommand`
- Download cradle: `IEX (New-Object Net.WebClient).DownloadString`
- AMSI bypass attempts
- Process injection patterns

---

## Lab 5 — Evidence Preservation

### Tools
- Velociraptor (remote forensics)
- FTK Imager (disk/memory imaging)

### Chain of Custody Principles
1. Document who collected evidence and when
2. Hash all evidence immediately after collection
3. Store in write-protected containers
4. Maintain logs of all access

### Hash Verification
```bash
# Linux
sha256sum memory_dump.raw

# Windows PowerShell
Get-FileHash -Algorithm SHA256 memory_dump.raw

# Compare hashes
echo "ORIGINAL_HASH  memory_dump.raw" | sha256sum --check
```

### Evidence Collection Template
| Item | Description | Collected By | Date | SHA256 Hash |
|---|---|---|---|---|
| Memory Dump | Server-Y RAM dump | SOC Analyst | 2025-08-18 | [hash] |
| Disk Image | Server-Y C:\ drive | SOC Analyst | 2025-08-18 | [hash] |
| Network Log | Netstat capture | SOC Analyst | 2025-08-18 | [hash] |

---

## Lab 6 — Capstone

### Attack Chain (MITRE ATT&CK)
```
Initial Access → Execution → Persistence → Privilege Escalation → Exfiltration
T1190           T1059       T1053         T1068               T1048
```

### Samba Exploit Reference
- **CVE:** CVE-2007-2447
- **Module:** `exploit/multi/samba/usermap_script`
- **Port:** 445 (SMB)
- **MITRE:** T1210 (Exploitation of Remote Services)

### Report Template (SANS Format)
```
1. Executive Summary (2-3 sentences, non-technical)
2. Incident Timeline
3. Technical Analysis
4. Impact Assessment
5. Containment Actions
6. Recommendations
7. Appendices (logs, hashes, screenshots)
```
