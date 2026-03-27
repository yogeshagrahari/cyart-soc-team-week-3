# Lab 4 — Alert Triage with Threat Intelligence
## Complete Step-by-Step Workflow

**Tools:** Wazuh, VirusTotal, AlienVault OTX  
**Objectives:** Triage alerts and validate IOCs using threat intelligence  
**MITRE:** T1059.001 (PowerShell)

---

## Pre-Lab Setup

### Verify Tools
```bash
# Wazuh Manager running
sudo systemctl status wazuh-manager

# Ensure Sysmon is installed on Windows agent (for PowerShell detection)
# On Windows (as Admin):
# Download: https://download.sysinternals.com/files/Sysmon.zip
# Install: Sysmon64.exe -accepteula -i sysmonconfig.xml

# Verify Sysmon logs in Wazuh:
# Dashboard - Security Events - filter: data.win.system.channel: Microsoft-Windows-Sysmon/Operational
```

### Get API Keys
```
VirusTotal: https://www.virustotal.com/gui/join-us
- Free account - My API Key - Copy key

AlienVault OTX: https://otx.alienvault.com
- Settings - API Integration - Copy key
```

---

## Task 1: Alert Triage Simulation

### Step 1 — Generate Mock PowerShell Alert

On Windows VM (run as Admin in PowerShell):
```powershell
# This generates a suspicious PowerShell event for detection
# (Safe test — no actual malware)

# Test 1: Encoded command (common malware technique)
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Host 'SOC Lab Test'"))
powershell.exe -EncodedCommand $encoded

# Test 2: Download cradle pattern (simulated, no actual download)
# powershell.exe -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri http://test.local"

# Test 3: AMSI bypass attempt signature
$a = 'AMSI'
Write-Host "Testing $a bypass detection"
```

### Step 2 — Verify Alert Appears in Wazuh
```
Wazuh Dashboard → Security Events
→ Filter: rule.groups = sysmon
→ Look for rule.description containing "PowerShell"
→ Or filter: data.win.eventdata.image = *powershell*

Alternative manual check:
```
```bash
# Check Wazuh alerts.log on server
sudo grep -i "powershell" /var/ossec/logs/alerts/alerts.json | tail -20 | python3 -m json.tool
```

### Step 3 — Document Alert in Triage Table
```
| Alert ID | Description              | Source IP      | Hostname  | User       | Priority | Status |
|----------|--------------------------|----------------|-----------|------------|----------|--------|
| 004      | PowerShell Execution     | 10.0.2.20  | WS-101    | jdoe       | High     | Open   |
| 005      | Encoded PowerShell Cmd   | 10.0.2.20  | WS-101    | jdoe       | Critical | Open   |
| 006      | Exec Policy Bypass       | 10.0.2.20    | WS-101    | jdoe       | High     | Open   |

Save as: Lab4_TriageTable.csv
```

### Step 4 — Assess Alert Priority
```
Priority Decision Framework:
+-----------------------+----------+
| Factor                | Weight   |
+-----------------------+----------+
| Encoded command used  | +Critical|
| Execution policy bypass | +High  |
| Download/IEX pattern  | +Critical|
| Admin/privileged user | +High    |
| Production system     | +High    |
| Off-hours execution   | +Medium  |
| IOC match in OTX/VT   | +Critical|
+-----------------------+----------+

For Alert 005 (Encoded Command):
 Encoded command = Critical
 Admin user = High
 Production WS = High
 Final: CRITICAL — immediate triage required
```

---

## Task 2: IOC Validation

### Step 2a — VirusTotal IP Lookup (API)

```python
# Save as: /opt/soc/vt_lookup.py
import requests
import json
import sys

VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"

def vt_ip_lookup(ip_address):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": VT_API_KEY}
    
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        attrs = data["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        
        print(f"\n=== VirusTotal Report: {ip_address} ===")
        print(f"Malicious: {stats.get('malicious', 0)}")
        print(f"Suspicious: {stats.get('suspicious', 0)}")
        print(f"Clean: {stats.get('harmless', 0)}")
        print(f"Country: {attrs.get('country', 'Unknown')}")
        print(f"ASN: {attrs.get('asn', 'Unknown')}")
        print(f"Network: {attrs.get('network', 'Unknown')}")
        print(f"VT URL: https://www.virustotal.com/gui/ip-address/{ip_address}")
        return stats
    else:
        print(f"Error: {response.status_code} — {response.text}")
        return None

def vt_hash_lookup(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        attrs = data["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        
        print(f"\n=== VirusTotal File Report: {file_hash} ===")
        print(f"Malicious: {stats.get('malicious', 0)}")
        print(f"Name: {attrs.get('meaningful_name', 'Unknown')}")
        print(f"Type: {attrs.get('type_description', 'Unknown')}")
        print(f"Size: {attrs.get('size', 0)} bytes")
        print(f"VT URL: https://www.virustotal.com/gui/file/{file_hash}")
        return stats
    else:
        print(f"Error: {response.status_code}")
        return None

if __name__ == "__main__":
    # Test with alert IOCs
    test_ip = "192.168.1.101"
    test_hash = "44d88612fea8a8f36de82e1278abb02f"  # EICAR test hash
    
    vt_ip_lookup(test_ip)
    vt_hash_lookup(test_hash)
```

```bash
python3 /opt/soc/vt_lookup.py
```

### Step 2b — OTX IP Lookup (API)

```python
# Save as: /opt/soc/otx_lookup.py
import requests
import json

OTX_API_KEY = "YOUR_OTX_API_KEY"

def otx_ip_lookup(ip_address):
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    
    endpoints = {
        "general": f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general",
        "reputation": f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/reputation",
        "malware": f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/malware"
    }
    
    for name, url in endpoints.items():
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            data = r.json()
            if name == "general":
                pulses = data.get("pulse_info", {}).get("count", 0)
                print(f"\n=== OTX Report: {ip_address} ===")
                print(f"Pulse count: {pulses}")
                print(f"Reputation: {'Malicious' if pulses > 0 else 'Clean'}")
                print(f"OTX URL: https://otx.alienvault.com/indicator/ip/{ip_address}")

if __name__ == "__main__":
    otx_ip_lookup("192.168.1.101")
    otx_ip_lookup("8.8.8.8")
```

```bash
python3 /opt/soc/otx_lookup.py
```

### Step 2c — Manual VirusTotal Check (GUI)
```
1. Go to: https://www.virustotal.com
2. Click: Search tab
3. Enter IP: 192.168.1.101
4. Review: Detection engines, Community score, WHOIS, Relations
5. Screenshot the results

For file hash:
1. Click: Search tab
2. Paste SHA256 hash from suspicious PowerShell script
3. Review: Detection names (malware family), first seen date
```

### Step 3 — Summarize IOC Validation Findings (50 words)
```
Example:
"IOC validation for 192.168.1.101 yielded 4 VirusTotal detections (Malicious: 4, 
Suspicious: 1) and 2 OTX pulses linked to Cobalt Strike C2 infrastructure. 
The PowerShell script hash matched Emotet dropper signatures across 18/70 AV engines. 
Alert reclassified from High to Critical pending containment."
```

### Step 4 — Update Triage Table
```
| Alert ID | IP            | VT Detections | OTX Pulses | Final Priority | Status     |
|----------|---------------|---------------|------------|----------------|------------|
| 004      | 10.0.2.25     | 0/90          | 0          | Medium         | Monitoring |
| 005      | 10.0.2.25     | 4/90          | 2          | Critical       | Escalated  |
| 006      | 10.0.2.25     | 0/90          | 0          | High           | Open       |
```

---

## Complete Triage Decision Flow

```
Alert Received
      |
      
Is it a false positive? - YES - Close, document reason - Done
      |
      NO
      
Severity assessment (High/Critical/Medium)
      |
      
IOC extraction (IP, hash, domain)
      |
      
VirusTotal lookup → malicious? - YES - escalate
      |                              - NO - continue
OTX lookup - pulses > 0? → YES - raise priority
      |                       - NO - continue
      
Document findings in triage table
      |
      
Critical/High - Create TheHive case - Escalate
Medium/Low - Monitor - Document - Close if resolved
```

---

## Deliverables Checklist
- [ ] PowerShell test alert generated on Windows VM
- [ ] Alert appeared in Wazuh dashboard
- [ ] Triage table documented (4+ alerts)
- [ ] VirusTotal API script ran successfully
- [ ] OTX API script ran successfully
- [ ] 50-word IOC validation summary written
- [ ] Updated triage table with VT/OTX data
- [ ] Screenshots taken (see Screenshot Guide)
