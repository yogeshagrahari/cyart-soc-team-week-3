# Lab 1 — Advanced Log Analysis
## Complete Step-by-Step Workflow

**Tools:** Elastic Security, Security Onion, Google Sheets  
**Objectives:** Log Correlation, Anomaly Detection, Log Enrichment  
**MITRE:** T1048 (Exfiltration), T1110 (Brute Force)

---

## Pre-Lab Setup

### Verify Elastic Stack is Running
```bash
sudo systemctl status elasticsearch
sudo systemctl status kibana
sudo systemctl status logstash

# Confirm Elasticsearch responds
curl -X GET "localhost:9200/_cluster/health?pretty"
# Expected: "status" : "green" or "yellow"

# Confirm Kibana is running
curl -I http://localhost:5601
# Expected: HTTP 200 or 302
```

### Confirm Filebeat Collecting Windows Logs
```bash
# On Linux server, check Filebeat status
sudo systemctl status filebeat

# Test Filebeat configuration
sudo filebeat test config
sudo filebeat test output

# On Windows endpoint, confirm Winlogbeat is running
# PowerShell:
Get-Service -Name "winlogbeat"
```

---

## Task 1: Log Correlation

### Step 1 — Open Kibana and Navigate to Security
```
1. Open browser: http://localhost:5601
2. Click: Security (left sidebar)
3. Click: Explore → Events
4. Time range: Last 24 hours (top right)
```

### Step 2 — Ingest Boss of the SOC (BOTS) Sample Data
```bash
# Download BOTS v3 sample dataset
cd /tmp
wget https://s3.amazonaws.com/botsdataset/botsv3/botsv3_data_set.tgz
tar -xzf botsv3_data_set.tgz

# Or use Elastic's built-in sample security data:
# Kibana Home → Add sample data → Sample security data → Add data
```

### Step 3 — Filter Failed Logins (Event ID 4625)
```
In Kibana Discover:
1. Select index: winlogbeat-* or logs-*
2. Search bar (KQL):
   event.code: "4625"
3. Add columns:
   - @timestamp
   - event.code
   - source.ip
   - destination.ip
   - user.name
   - winlog.event_data.FailureReason
4. Click: Refresh
5. Take screenshot
```

### Step 4 — Correlate Failed Logins with Outbound Traffic
```
KQL query:
(event.code: "4625" AND source.ip: "10.0.2.20") OR
(network.direction: "outbound" AND source.ip: "10.0.2.20")

Sort by: @timestamp ascending
Look for: failed login → immediately followed by outbound connection
```

### Step 5 — Document Findings in Table
```
Create Google Sheet with columns:
| Timestamp | Event ID | Source IP | Destination IP | Notes |

Fill from Kibana results:
| 2025-08-18 12:00:00 | 4625 | 10.0.2.20 | 8.8.8.8 | Suspicious DNS request |
| 2025-08-18 12:01:30 | 4625 | 10.0.2.20 | 8.8.8.8 | 2nd failed login |
| 2025-08-18 12:03:00 | 4625 | 10.0.2.20 | 8.8.8.8 | Brute force pattern |

Export as CSV: File → Download → .csv
```

---

## Task 2: Anomaly Detection Rule

### Step 1 — Navigate to Detection Rules
```
Kibana → Security → Rules → Detection Rules (SIEM)
→ Click: Create New Rule
→ Select type: Threshold
```

### Step 2 — Configure Rule
```
Rule Type: Threshold
Index patterns: logs-*, winlogbeat-*, filebeat-*

Query (KQL):
network.direction: "outbound"

Threshold:
  Field: source.ip
  Threshold value: 1
  Cardinality: (leave empty)

Group by: source.ip
Time window: 1 minute
```

### Step 3 — Add Filter for Data Size
```
Click: + Add filter
Field: network.bytes
Operator: is greater than
Value: 1048576
```

### Step 4 — Set Severity and Metadata
```
Name: High Volume Outbound Data Transfer — Possible Exfiltration
Description: Detects outbound data transfer exceeding 1MB in 1 minute window
Severity: High
Risk Score: 73
MITRE ATT&CK:
  Tactic: Exfiltration (TA0010)
  Technique: T1048 - Exfiltration Over Alternative Protocol
```

### Step 5 — Save and Enable Rule
```
Click: Continue → Continue → Create & Enable Rule
Verify rule appears in Rules list with Status: Active
```

### Step 6 — Test with Mock File Transfer
```bash
# On Linux machine, simulate large file transfer
dd if=/dev/urandom bs=1M count=5 | nc -w 5 <TARGET_IP> 9999

# Or use iperf3
sudo apt install iperf3 -y
# Server side:
iperf3 -s -p 9999
# Client side:
iperf3 -c <TARGET_IP> -p 9999 -n 10M

# Wait ~2 minutes, then check:
# Kibana → Security → Alerts
# New alert should appear for rule
```

---

## Task 3: Log Enrichment with GeoIP

### Step 1 — Install GeoIP Database
```bash
# Install MaxMind GeoLite2 database
sudo apt install libmaxminddb0 libmaxminddb-dev -y

# Create account at: https://www.maxmind.com/en/geolite2/signup
# Download GeoLite2-City.mmdb

# Copy to Logstash
sudo mkdir -p /usr/share/logstash/vendor/bundle/jruby/2.6.0/gems/
sudo cp GeoLite2-City.mmdb /etc/logstash/
```

### Step 2 — Configure Logstash GeoIP Filter
```bash
sudo nano /etc/logstash/conf.d/02-geoip.conf
```

Paste:
```ruby
filter {
  if [source][ip] and [source][ip] !~ /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/ {
    geoip {
      source => "[source][ip]"
      target => "[source][geo]"
      database => "/etc/logstash/GeoLite2-City.mmdb"
      fields => ["city_name", "country_name", "country_code2", "location", "region_name"]
    }
  }
  if [destination][ip] and [destination][ip] !~ /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/ {
    geoip {
      source => "[destination][ip]"
      target => "[destination][geo]"
      database => "/etc/logstash/GeoLite2-City.mmdb"
    }
  }
}
```

### Step 3 — Restart Logstash and Verify
```bash
sudo systemctl restart logstash
sudo tail -f /var/log/logstash/logstash-plain.log
# Wait for: Successfully started Logstash
```

### Step 4 — View GeoIP Data in Kibana
```
1. Kibana → Discover
2. Search: source.ip: "8.8.8.8" (or any external IP)
3. Expand document
4. Look for fields: source.geo.country_name, source.geo.city_name
5. Kibana → Maps → Create layer from index pattern
6. Select geo field: source.geo.location
7. View IP locations on world map
```

### Step 5 — Summarize GeoIP Findings (50 words)
```
Example Summary:
"GeoIP enrichment added geolocation context to 847 log entries. 
External IPs resolved to United States (42%), China (18%), Russia (12%), 
and Netherlands (8%). One IP (185.220.101.x) matched a known Tor exit node 
in Germany, previously correlating with 3 failed login attempts on Server-Y."
```

---

## Deliverables Checklist
- [ ] Log correlation table exported to CSV
- [ ] Threshold detection rule created and enabled
- [ ] Mock transfer test triggered an alert
- [ ] GeoIP pipeline configured in Logstash
- [ ] 50-word GeoIP summary written
- [ ] Screenshots taken (see Screenshot Guide)
