# Lab 3 — Incident Escalation Practice
## Complete Step-by-Step Workflow

**Tools:** TheHive, Google Docs, Splunk Phantom/SOAR  
**Objectives:** Simulate escalation, draft SITREPs, automate alert workflows  
**MITRE:** T1078 (Valid Accounts)

---

## Pre-Lab Setup

### Install TheHive (Docker — Recommended)
```bash
# Install Docker
sudo apt install docker.io docker-compose -y
sudo systemctl enable --now docker

# Create TheHive docker-compose file
mkdir -p ~/thehive && cd ~/thehive
nano docker-compose.yml
```

Paste:
```yaml
version: "3"
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.9
    environment:
      - discovery.type=single-node
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    ports:
      - "9200:9200"
    volumes:
      - es_data:/usr/share/elasticsearch/data

  thehive:
    image: thehiveproject/thehive4:latest
    depends_on:
      - elasticsearch
    ports:
      - "9000:9000"
    command:
      - --es-uri
      - http://elasticsearch:9200

volumes:
  es_data:
```

```bash
# Start TheHive
docker-compose up -d

# Access at:
# http://localhost:9000
# Default credentials: admin@thehive.local / secret
```

---

## Task 1: Escalation Simulation

### Step 1 — Login to TheHive
```
1. Open browser: http://localhost:9000
2. Login: admin@thehive.local / secret
3. Change default password immediately:
    Click admin (top right) - Change Password
```

### Step 2 — Create Organizations
```
TheHive - Admin - Organizations
 -Click: Add Organization
  Name: SOC-Team
  Description: CYART SOC Operations
- Save

- Create Users:
  Click: Admin - Users - Add User
  - Login: tier1@cyart.soc | Role: Analyst | Org: SOC-Team
  - Login: tier2@cyart.soc | Role: Analyst | Org: SOC-Team
  - Login: soc_manager@cyart.soc | Role: Org-Admin | Org: SOC-Team
```

### Step 3 — Create New High-Priority Case
```
TheHive - New Case
- Fill fields:
  Title: Unauthorized Access — Server-Y
  Severity: High (3 stars)
  TLP: Amber 
  PAP: Amber
  Tags: unauthorized-access, T1078, Server-Y, Week2-Lab3
  Description:
    "At 2026-03-25 13:00 UTC, an unauthorized access attempt was detected 
    on Server-Y (10.0.2.20). Event ID 4625 triggered 14 times in 2 minutes 
    followed by a successful Event ID 4624 from the same IP. The account 
    'svc_maintenance' was used — this account has no business justification 
    for accessing Server-Y. Wazuh Rule 100001 (T1078) triggered."

- Click: Create Case
- Note the Case ID (e.g., #5)
```

### Step 4 — Add Observables (IOCs) to Case
```
Inside the case - Observables tab - Add Observable
  Type: IP    Value: 10.0.2.25    Tags: server, victim
  Type: IP    Value: 10.0.2.26   Tags: source, suspicious
  Type: hostname   Value: Server-Y    Tags: affected-system
  Type: username   Value: svc_maintenance   Tags: compromised-account
```

### Step 5 — Add Tasks
```
Inside case - Tasks tab - Add Task
  Task 1: Isolate Server-Y from network
  Task 2: Reset svc_maintenance password
  Task 3: Review VPN/AD logs for account usage
  Task 4: Escalate to Tier 2 analyst
  Task 5: Write SITREP and notify management
```

### Step 6 — Escalate Case to Tier 2
```
Inside case - Assignee: Change from tier1 to tier2@cyart.soc
- Add case comment:
  "Escalating to Tier 2. Case involves T1078 pattern — account used outside 
  normal hours from IP not in approved list. Server-Y has been isolated. 
  14 failed logins followed by 1 success at 13:00 UTC. OTX shows IP linked 
  to 3 pulses. Recommend immediate AD audit and forensic acquisition 
  of Server-Y memory. SITREP attached."
- Save
```

### Step 7 — Write 100-Word Escalation Summary
```
At 2026-03-25 13:00 UTC, Wazuh detected 14 failed logins (Event ID 4625) 
followed by a successful authentication (Event ID 4624) to Server-Y 
(10.0.2.25) using account 'svc_maintenance' from IP 10.0.2.26. 
MITRE T1078 (Valid Accounts) applies. OTX reports source IP linked to 
3 threat pulses associated with credential-stuffing campaigns. Server-Y 
has been network-isolated. svc_maintenance password has been reset. 
Escalating to Tier 2 for forensic analysis, AD account review, and 
determination of lateral movement. Immediate memory acquisition of 
Server-Y recommended before further investigation.
```

---

## Task 2: SITREP Draft

### Open Google Docs (or create as .md file)

```markdown
---
SITUATION REPORT (SITREP)
CYART Security Operations Center
---

Title:     Unauthorized Access — Server-Y
Report #:  SITREP-2026-0818-001
Date/Time: 2026-03-25 14:00 UTC
Analyst:   [Your Name], Tier 1 SOC
Status:    ACTIVE — Escalated to Tier 2

---

1. SUMMARY
Unauthorized access to Server-Y (10.0.2.25) was detected at 2026-03-25
13:00 UTC. The account 'svc_maintenance' was used from IP 10.0.2.26
following 14 failed login attempts. This matches MITRE ATT&CK T1078 
(Valid Accounts).

2. TIMELINE
| Time (UTC)   | Event                                            |
|--------------|--------------------------------------------------|
| 12:58:00     | First failed login — svc_maintenance — Server-Y  |
| 12:58:00–    | 13 additional failed logins over 2 minutes       |
| 13:00:42     | Successful login — svc_maintenance — Server-Y    |
| 13:05:00     | Wazuh alert triggered — Rule 100001 (T1078)      |
| 13:08:00     | Tier 1 analyst acknowledged alert                |
| 13:15:00     | Server-Y isolated from network                   |
| 13:20:00     | svc_maintenance password reset                   |
| 14:00:00     | Escalated to Tier 2 — SITREP created             |

3. AFFECTED SYSTEMS
- Server-Y (10.0.2.25) — Windows Server 2019
- Account: svc_maintenance (service account)

4. INDICATORS OF COMPROMISE
- Source IP: 192.168.1.100 (OTX: 3 pulses, credential-stuffing)
- Account: svc_maintenance (unusual usage pattern)
- Event IDs: 4625 (×14), 4624 (×1)

5. MITRE ATT&CK MAPPING
- Tactic: Initial Access / Persistence
- Technique: T1078 — Valid Accounts

6. ACTIONS TAKEN
 Server-Y isolated from network segment
 svc_maintenance password reset and account locked
 Wazuh alert acknowledged and documented
 Case #5 created in TheHive
Escalated to Tier 2 analyst

7. RECOMMENDED NEXT STEPS
 Forensic memory acquisition of Server-Y
 Full AD audit for svc_maintenance recent activity
 Review all systems svc_maintenance had access to
 Check for persistence mechanisms (scheduled tasks, registry)
 Notify Server-Y system owner

8. CURRENT STATUS
Contained — pending Tier 2 forensic investigation

---
Prepared by: [Analyst Name] | Tier 1 SOC | CYART
Reviewed by: [Supervisor Name]
```

---

## Task 3: Workflow Automation (Splunk Phantom / SOAR)

### Option A — TheHive Cortex Responder (Built-in)

```
1. In TheHive - Admin - Cortex Settings
2. Enter Cortex URL: http://localhost:9001
3. Add Cortex API key
4. Enable responders for automatic triage
```

### Option B — Simple Python SOAR Script

```bash
nano /opt/soc/auto_escalate.py
```

```python
#!/usr/bin/env python3
"""
Simple SOAR: Auto-escalate High-priority Wazuh alerts to TheHive Tier 2
"""
import requests
import json
from datetime import datetime

# Config
THEHIVE_URL = "http://localhost:9000"
THEHIVE_API_KEY = "YOUR_THEHIVE_API_KEY"
TIER2_USER = "tier2@cyart.soc"

def create_thehive_case(alert_data):
    """Create a case in TheHive and assign to Tier 2."""
    headers = {
        "Authorization": f"Bearer {THEHIVE_API_KEY}",
        "Content-Type": "application/json"
    }
    
    case_payload = {
        "title": f"AUTO-ESCALATED: {alert_data.get('rule_description', 'Security Alert')}",
        "severity": 3,  # High
        "tlp": 2,       # Amber
        "tags": ["auto-escalated", "high-priority", alert_data.get("mitre", "")],
        "description": f"""
Auto-escalated by SOAR at {datetime.utcnow().isoformat()} UTC

Alert Details:
- Rule ID: {alert_data.get('rule_id')}
- Source IP: {alert_data.get('src_ip')}
- Description: {alert_data.get('rule_description')}
- MITRE: {alert_data.get('mitre')}

This case has been automatically assigned to Tier 2 for investigation.
        """,
        "assignee": TIER2_USER
    }
    
    response = requests.post(
        f"{THEHIVE_URL}/api/case",
        headers=headers,
        json=case_payload,
        verify=False
    )
    
    if response.status_code == 201:
        case = response.json()
        print(f"[+] Case created: #{case['caseId']} — {case['title']}")
        return case
    else:
        print(f"[-] Failed: {response.status_code} {response.text}")
        return None

# Test with mock high-priority alert
if __name__ == "__main__":
    mock_alert = {
        "rule_id": "100001",
        "rule_description": "T1078: Valid Accounts — Successful login detected",
        "src_ip": "192.168.1.100",
        "mitre": "T1078",
        "priority": "High"
    }
    create_thehive_case(mock_alert)
```

```bash
# Test the script
python3 /opt/soc/auto_escalate.py

# Expected output:
# [+] Case created: #6 — AUTO-ESCALATED: T1078: Valid Accounts...
```

---

## Deliverables Checklist
- [ ] TheHive deployed and accessible
- [ ] Case created: Unauthorized Access — Server-Y
- [ ] Observables added (IPs, hostname, username)
- [ ] Case escalated to Tier 2 with 100-word summary
- [ ] SITREP drafted with timeline and recommendations
- [ ] Automation script tested (auto_escalate.py)
- [ ] Screenshots taken (see Screenshot Guide)
