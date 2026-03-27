# Elastic Security Cheat Sheet
**CYART SOC Team | Week 2**

---

## Installation (Ubuntu/Debian)

```bash
# 1. Import GPG Key
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

# 2. Add Elastic Repository
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

# 3. Install Elasticsearch
sudo apt-get update && sudo apt-get install elasticsearch -y

# 4. Install Kibana
sudo apt-get install kibana -y

# 5. Install Logstash
sudo apt-get install logstash -y

# 6. Enable and Start Services
sudo systemctl enable elasticsearch kibana logstash
sudo systemctl start elasticsearch kibana logstash

# 7. Check Status
sudo systemctl status elasticsearch
```

---

## Kibana Access
- URL: `http://localhost:5601`
- Default port: `5601`
- Elastic API: `http://localhost:9200`

---

## KQL (Kibana Query Language)

### Basic Syntax
```kql
# Match a field value
field: "value"

# Wildcard
field: "val*"

# Range
field >= 100 AND field <= 200

# NOT
NOT field: "value"

# Combine
field1: "val1" AND field2: "val2"
field1: "val1" OR field2: "val2"
```

### Security-Specific Queries

```kql
# Failed Windows Logons (Event ID 4625)
event.code: "4625"

# Successful Logons
event.code: "4624"

# PowerShell Execution
process.name: "powershell.exe"

# Encoded PowerShell (suspicious)
process.command_line: "*EncodedCommand*"

# Large outbound transfer (>1MB)
network.bytes > 1048576 AND network.direction: "outbound"

# DNS queries to 8.8.8.8
destination.ip: "8.8.8.8" AND dns.type: "query"

# Correlate failed login + outbound traffic
event.code: "4625" AND source.ip: "192.168.1.100"

# Detect T1078 - Valid Accounts abuse
event.code: "4624" AND NOT user.name: ("system" OR "LOCAL SERVICE" OR "NETWORK SERVICE")
```

---

## Detection Rule Creation (Threshold Rule)

```json
{
  "name": "High Volume Data Transfer",
  "description": "Detects data exfiltration - bytes_out > 1MB in 1 minute",
  "type": "threshold",
  "query": "network.direction: outbound",
  "threshold": {
    "field": "source.ip",
    "value": 1,
    "cardinality": []
  },
  "filters": [
    {
      "range": {
        "network.bytes": {
          "gt": 1048576
        }
      }
    }
  ],
  "interval": "1m",
  "severity": "high",
  "risk_score": 73
}
```

Steps in Kibana UI:
```
Security → Rules → Create New Rule → Threshold
→ Set query: network.direction: outbound
→ Set threshold: network.bytes > 1048576
→ Group by: source.ip
→ Time window: 1 minute
→ Severity: High
→ Risk Score: 73
→ Save and Enable
```

---

## GeoIP Enrichment in Logstash

```ruby
# /etc/logstash/conf.d/geoip.conf
filter {
  if [source][ip] {
    geoip {
      source => "[source][ip]"
      target => "[source][geo]"
      fields => ["city_name", "country_name", "location", "region_name"]
    }
  }
  if [destination][ip] {
    geoip {
      source => "[destination][ip]"
      target => "[destination][geo]"
    }
  }
}
```

Restart Logstash after changes:
```bash
sudo systemctl restart logstash
sudo journalctl -fu logstash  # Monitor logs
```

---

## Elasticsearch Index Management

```bash
# List all indices
curl -X GET "localhost:9200/_cat/indices?v"

# Create index
curl -X PUT "localhost:9200/soc-logs-2025"

# Delete index
curl -X DELETE "localhost:9200/soc-logs-2025"

# Check cluster health
curl -X GET "localhost:9200/_cluster/health?pretty"

# Search all documents in index
curl -X GET "localhost:9200/soc-logs-2025/_search?pretty"
```

---

## Ingest Sample BOTS (Boss of the SOC) Logs

```bash
# Download BOTS v3 dataset (sample)
wget https://github.com/splunk/botsv3/archive/refs/heads/master.zip
unzip master.zip

# Or use Elastic's sample data
# In Kibana: Home → Add sample data → Sample web logs / Security logs

# Custom ingest via Filebeat
sudo apt install filebeat -y
sudo filebeat modules enable system
sudo filebeat setup
sudo systemctl start filebeat
```

---

## Useful Elastic Stack Commands

```bash
# Elasticsearch
sudo systemctl start|stop|restart|status elasticsearch

# Kibana
sudo systemctl start|stop|restart|status kibana

# Logstash
sudo systemctl start|stop|restart|status logstash

# Filebeat
sudo systemctl start|stop|restart|status filebeat

# View logs
sudo journalctl -fu elasticsearch
sudo journalctl -fu kibana
tail -f /var/log/logstash/logstash-plain.log
```
