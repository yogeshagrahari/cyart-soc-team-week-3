# Lab 2 — Threat Intelligence Integration
## Complete Step-by-Step Workflow

**Tools:** Wazuh, AlienVault OTX, TheHive  
**Objectives:** Import threat feeds, enrich alerts, hunt for threats  
**MITRE:** T1078 (Valid Accounts)

---

## Pre-Lab Setup

### Verify Services
```bash
# Check Wazuh Manager
sudo systemctl status wazuh-manager

# Check Wazuh Dashboard
sudo systemctl status wazuh-dashboard

# Confirm Wazuh API responds
curl -k -u admin:SecretPassword https://localhost:55000/
# Expected: {"data":{"title":"Wazuh API REST","api_version":"4.x.x"...}}

# Confirm at least one agent connected
sudo /var/ossec/bin/manage_agents -l
```

---

## Task 1: Threat Feed Import (AlienVault OTX → Wazuh)

### Step 1 — Register on AlienVault OTX
```
1. Go to: https://otx.alienvault.com
2. Click: Sign Up (free account)
3. Complete email verification
4. Log in → click your username (top right) → Settings
5. Click: API Integration tab
6. Copy your OTX API Key (save it securely)
```

### Step 2 — Install Python OTX Library on Wazuh Server
```bash
sudo apt update
sudo apt install python3-pip python3-requests -y
pip3 install OTXv2 requests --break-system-packages
```

### Step 3 — Create OTX Integration Script
```bash
sudo nano /var/ossec/integrations/custom-otx.py
```

Paste the following:
```python
#!/usr/bin/env python3
"""
Wazuh + AlienVault OTX Integration
Enriches Wazuh alerts with OTX IOC reputation data
"""
import sys
import os
import json
import requests

# Config
OTX_API_KEY = "YOUR_OTX_API_KEY_HERE"
OTX_BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

def query_otx_ip(ip_address):
    """Query OTX for IP reputation."""
    url = f"{OTX_BASE_URL}/IPv4/{ip_address}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            return {
                "ip": ip_address,
                "pulse_count": pulse_count,
                "reputation": "Malicious" if pulse_count > 0 else "Clean",
                "otx_url": f"https://otx.alienvault.com/indicator/ip/{ip_address}"
            }
    except Exception as e:
        return {"error": str(e)}
    return {"reputation": "Unknown"}

def send_enriched_alert(alert_data, enrichment):
    """Send enriched alert to Wazuh via active response."""
    print(json.dumps({
        "original_alert": alert_data,
        "otx_enrichment": enrichment
    }))

if __name__ == "__main__":
    # Read alert from stdin (Wazuh passes alert as JSON)
    alert_file = sys.argv[1]
    with open(alert_file) as f:
        alert = json.load(f)
    
    # Extract source IP from alert
    src_ip = alert.get("data", {}).get("srcip", 
             alert.get("data", {}).get("src_ip", ""))
    
    if src_ip and not src_ip.startswith("192.168") and not src_ip.startswith("10."):
        enrichment = query_otx_ip(src_ip)
        send_enriched_alert(alert, enrichment)
    else:
        print(json.dumps({"message": "Private IP — skipping OTX lookup"}))
```

```bash
# Set permissions
sudo chmod 750 /var/ossec/integrations/custom-otx.py
sudo chown root:wazuh /var/ossec/integrations/custom-otx.py
```

### Step 4 — Configure Integration in ossec.conf
```bash
sudo nano /var/ossec/etc/ossec.conf
```

Add inside `<ossec_config>`:
```xml
<integration>
  <name>custom-otx</name>
  <api_key>YOUR_OTX_API_KEY_HERE</api_key>
  <level>5</level>
  <alert_format>json</alert_format>
</integration>
```

### Step 5 — Restart Wazuh and Verify
```bash
sudo systemctl restart wazuh-manager
sudo tail -f /var/ossec/logs/ossec.log | grep -i "otx\|integrat"
```

### Step 6 — Test with Mock Malicious IP
```bash
# Simulate alert from IP 203.0.113.42 (TEST-NET, OTX usually has entries)
# Or use a known bad IP from OTX pulse

# Manual test of the script:
echo '{"data":{"srcip":"185.220.101.1"},"rule":{"id":"5710","level":5}}' > /tmp/test_alert.json
sudo python3 /var/ossec/integrations/custom-otx.py /tmp/test_alert.json
```

---

## Task 2: Alert Enrichment

### Step 1 — Generate Test Alert
```bash
# Attempt SSH from monitored agent to trigger authentication alert
# From a Linux machine:
ssh invalid_user@<WAZUH_AGENT_IP>
# Enter wrong password 3 times

# Check alert in Wazuh dashboard:
# Dashboard → Security Events → filter: rule.id: 5710
```

### Step 2 — View Enriched Alert in Dashboard
```
Wazuh Dashboard → Security Events
→ Find alert with rule.id = 5710 or rule.groups = authentication_failed
→ Click event to expand
→ Look for: data.otx_enrichment field (added by integration)
```

### Step 3 — Document Alert Enrichment Table
```
| Alert ID | IP            | Reputation        | OTX Pulses | Notes                 |
|----------|---------------|-------------------|------------|-----------------------|
| 003      | 192.168.1.100 | Malicious (OTX)   | 3          | Linked to C2 server   |
| 004      | 185.220.101.1 | Malicious (OTX)   | 12         | Known Tor exit node   |
| 005      | 10.0.0.5      | Private IP        | N/A        | Internal — skip OTX   |
```

Save as: `Lab2_AlertEnrichment.csv`

---

## Task 3: Threat Hunting — T1078 Valid Accounts

### Step 1 — Understand T1078
```
MITRE T1078 - Valid Accounts:
Adversaries may obtain and use valid credentials (stolen/default)
to gain initial/persistent access, bypass access controls, or 
evade defenses using trusted accounts.

Detection focus:
- Logins outside business hours
- Logins from unusual geolocations
- Logins using accounts that rarely log in
- Multiple concurrent logins from same user
```

### Step 2 — Create Hunt Query in Wazuh Dashboard
```
Wazuh Dashboard → Security Events
→ Add filter:
  Field: rule.groups
  Operator: is
  Value: authentication_success

→ Add filter:
  Field: data.win.system.eventID
  Operator: is not
  Value: (leave empty)

→ In KQL search:
  NOT data.win.eventdata.targetUserName: ("system" OR "LOCAL SERVICE" OR "NETWORK SERVICE" OR "ANONYMOUS LOGON")
```

### Step 3 — Use Wazuh API for Hunting
```bash
# Get auth token
TOKEN=$(curl -su admin:SecretPassword -k -X GET \
  "https://localhost:55000/security/user/authenticate?raw=true")

echo "Token: $TOKEN"

# Hunt for non-system logins (T1078)
curl -k -X GET "https://localhost:55000/security/events?q=rule.groups=authentication_success" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" | python3 -m json.tool

# Look for after-hours logins (adjust time to your timezone)
curl -k -X GET "https://localhost:55000/security/events?q=rule.groups=authentication_success;timestamp>2025-08-18T19:00:00" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

### Step 4 — Cross-Reference with OTX Pulses
```
1. Note suspicious usernames or source IPs from hunt results
2. Go to: https://otx.alienvault.com
3. Search → type: IP Address → enter suspicious IP
4. Review: Pulse count, Tags, Related malware families
5. Check: https://otx.alienvault.com/indicator/ip/<IP>
```

### Step 5 — Document Threat Hunt Summary (50 words)
```
Example:
"Threat hunt for T1078 identified 2 suspicious logins from user 'svc_backup' 
at 02:15 and 03:40 UTC (off-hours). Source IP 203.0.113.50 matched 5 OTX pulses 
linked to credential-stuffing campaigns. Account has been flagged for review and 
temporary suspension pending investigation."
```

### Step 6 — Create TheHive Case for Findings
```
TheHive → New Case
Title: T1078 — Suspected Valid Account Abuse
Severity: High
Tags: T1078, lateral-movement, credential-abuse
TLP: Amber
Description: [paste hunt summary]
Observable: Add IP and username as observables
Assign to: Tier 2 analyst
```

---

## Deliverables Checklist
- [ ] OTX API key obtained and integrated
- [ ] custom-otx.py script deployed and tested
- [ ] Alert enrichment table documented (CSV)
- [ ] Threat hunt query executed in Wazuh
- [ ] 50-word threat hunt summary written
- [ ] TheHive case created for suspicious logins
- [ ] Screenshots taken (see Screenshot Guide)
