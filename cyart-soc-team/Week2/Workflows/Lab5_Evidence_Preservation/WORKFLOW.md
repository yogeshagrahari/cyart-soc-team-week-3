# Lab 5 — Evidence Preservation and Analysis
## Complete Step-by-Step Workflow

**Tools:** Velociraptor, FTK Imager  
**Objectives:** Collect volatile data, acquire memory, maintain chain-of-custody  
**Legal Note:** Only collect evidence from systems you own or have written authorization to examine

---

## Pre-Lab Setup

### Install Velociraptor Server
```bash
# Download latest Velociraptor
cd /opt
sudo wget https://github.com/Velocidex/velociraptor/releases/download/v0.72/velociraptor-v0.72.0-linux-amd64 -O velociraptor
sudo chmod +x velociraptor

# Generate self-signed config
sudo ./velociraptor config generate -i
# Prompts:
#   Deployment type: Self Signed SSL
#   Public DNS Name: <YOUR_SERVER_IP>
#   Frontend bind port: 8000
#   GUI bind port: 8889
#   Datastore path: /opt/velociraptor/datastore
# → Accept defaults for remaining prompts

# Add admin user
sudo ./velociraptor --config server.config.yaml user add admin --role administrator
# Enter password when prompted

# Start the server
sudo ./velociraptor --config server.config.yaml frontend -v &

echo "Velociraptor GUI: https://<YOUR_IP>:8889"
```

### Deploy Velociraptor Agent on Windows VM

On Windows VM (as Administrator in CMD):
```cmd
REM Download the Windows client from Velociraptor GUI:
REM Clients → Add New Client → Windows → Download MSI

REM Install silently
msiexec /i velociraptor_client_amd64.msi /quiet /norestart

REM Verify service running
sc query velociraptor
net start velociraptor
```

---

## Task 1: Volatile Data Collection

### Step 1 — Login to Velociraptor GUI
```
Browser: https://<SERVER_IP>:8889
Username: admin
Password: <set during setup>
```

### Step 2 — Find Your Windows Agent
```
Velociraptor GUI → Clients (left sidebar)
→ Search for your Windows VM hostname or IP
→ Click on the client name to open it
→ Verify: Last Seen — should be recent
```

### Step 3 — Run Network Connections Query (netstat)
```
In client view → Collected → New Collection
→ Search artifact: "Windows.Network.Netstat"
→ Click: Windows.Network.Netstat
→ Click: Launch
→ Wait for collection to complete (green checkmark)
→ Click results → View in browser
```

VQL equivalent (in Notebooks):
```sql
SELECT Laddr as LocalAddress,
       Raddr as RemoteAddress,
       Status,
       Pid,
       Name as ProcessName
FROM netstat()
WHERE Status = "ESTABLISHED" OR Status = "LISTEN"
```

### Step 4 — Save Netstat Results to CSV
```
Collection results → Download Results
→ Select: CSV Format
→ Save as: Lab5_netstat_output.csv

Or from VQL notebook:
```
```sql
SELECT Laddr, Raddr, Status, Pid, Name
FROM netstat()
| write_csv(filename="C:\\Evidence\\netstat_20250818.csv")
```

### Step 5 — Collect Additional Volatile Data

Running processes:
```sql
SELECT Pid, Ppid, Name, Exe, CommandLine, Username, CreateTime
FROM pslist()
ORDER BY Pid
```

DNS cache:
```sql
SELECT Name AS DomainName,
       IPAddress,
       TTL,
       TimeToLive
FROM dns_cache()
```

Logged-in users:
```sql
SELECT Name, Type, LogonTime
FROM logged_in_users()
```

Autorun persistence (registry):
```
Artifact: Windows.Persistence.PersistenceSniper
→ New Collection → Search: PersistenceSniper
→ Launch → Review results for suspicious entries
```

---

## Task 2: Memory Acquisition and Hashing

### Step 1 — Run Memory Acquisition in Velociraptor
```
Client view → New Collection
→ Search artifact: "Windows.Memory.Acquisition"
→ Click: Artifact.Windows.Memory.Acquisition
→ Parameters:
    OutputPath: C:\Evidence\memory_dump.raw
    (or leave default — stored in Velociraptor datastore)
→ Click: Launch

Note: Memory acquisition can take 5–20 minutes depending on RAM size
```

VQL equivalent:
```sql
SELECT *
FROM Artifact.Windows.Memory.Acquisition(
  outputPath="C:\\Evidence\\memory_dump.raw"
)
```

### Step 2 — Monitor Collection Progress
```
Velociraptor GUI → Collections → Find your collection
→ Status: Running → wait for Finished
→ Click: Results tab
→ Note: file path of memory dump
```

### Step 3 — Download Memory Dump
```
Collection results → Download → Raw Files
→ Save the .raw file to analyst workstation
→ Rename: ServerY_memory_20250818_1400.raw
```

### Step 4 — Hash the Memory Dump

On Linux analyst workstation:
```bash
# Navigate to downloaded file
cd ~/Evidence/

# Generate SHA256 hash
sha256sum ServerY_memory_20250818_1400.raw

# Example output:
# a3f5d2b1c4e9f7a8b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5  ServerY_memory_20250818_1400.raw

# Save hash to file
sha256sum ServerY_memory_20250818_1400.raw > ServerY_memory_20250818_1400.raw.sha256

# Display hash
cat ServerY_memory_20250818_1400.raw.sha256
```

On Windows (PowerShell):
```powershell
# Generate SHA256 hash
$hash = Get-FileHash -Path "C:\Evidence\ServerY_memory_20250818_1400.raw" -Algorithm SHA256
$hash | Format-List

# Save to file
$hash | Export-Csv -Path "C:\Evidence\hash_record.csv" -NoTypeInformation

# Output:
# Algorithm : SHA256
# Hash      : A3F5D2B1C4E9F7A8B2C3D4E5F6A7B8C9...
# Path      : C:\Evidence\ServerY_memory_20250818_1400.raw
```

### Step 5 — Verify Hash Integrity
```bash
# After copying to another location, re-verify
sha256sum -c ServerY_memory_20250818_1400.raw.sha256
# Expected: ServerY_memory_20250818_1400.raw: OK
# If tampered: FAILED open or read
```

### Step 6 — Document in Chain of Custody Table
```
| Item #  | Item              | Description            | Collected By | Date/Time (UTC)      | Tool                   | SHA256 Hash                                                      |
|---------|-------------------|------------------------|--------------|----------------------|------------------------|------------------------------------------------------------------|
| ITEM-001 | Memory Dump       | Server-Y physical RAM  | [Your Name]  | 2026-03-26  13:50| Velociraptor v0.72.0   | [paste actual hash here]                                         |
| ITEM-002 | Netstat CSV       | Active connections     | [Your Name]  | 2026-03-26 13:55 |   Vociraptor v0.72.0   | [hash]                                                           |
| ITEM-003 | Process List      | Running processes      | [Your Name]  | 2026-03-26 13:56  | Velociraptor v0.72.0   | [hash]                                                           |
| ITEM-004 | DNS Cache         | DNS resolver cache     | [Your Name]  | 2026-03-26 13:57  |Velociraptor v0.72.0   | [hash]                                                           |
```

---

## FTK Imager — Memory Capture (Alternative Method)

```
1. Download FTK Imager: https://www.exterro.com/ftk-imager
2. Install on Windows target (or run portable version)
3. Run as Administrator
4. Menu: File → Capture Memory
5. Set:
   Destination folder: C:\Evidence\
   Filename: ServerY_FTK_memory.mem
    Include pagefile.sys
6. Click: Capture Memory
7. Wait for completion (progress bar)
8. Review summary — note size in bytes
9. Hash verification:
   PowerShell: Get-FileHash "C:\Evidence\ServerY_FTK_memory.mem" -Algorithm SHA256
10. Document in chain of custody
```

---

## Evidence Storage Best Practices

```
1. Write-protect evidence media immediately after collection
2. Store copies in at least 2 locations (primary + backup)
3. Use encrypted containers (e.g., VeraCrypt) for storage
4. Label evidence bags/drives clearly with case number
5. Log every person who accesses evidence files
6. Never work on original — always work on forensic copy

Evidence folder structure:
/Evidence/
  SOC-2025-0818-001/
    ├── original/          (read-only, never modify)
    │   ├── memory.raw
    │   ├── memory.raw.sha256
    │   └── netstat.csv
    ├── working_copy/      (analysis workspace)
    │   └── (copies of files)
    └── chain_of_custody.csv
```

---

## Deliverables Checklist
- [ ] Velociraptor server installed and accessible
- [ ] Windows agent connected to Velociraptor
- [ ] Netstat collection run — results saved to CSV
- [ ] Memory dump collected via Velociraptor
- [ ] SHA256 hash generated and saved
- [ ] Hash integrity verified successfully
- [ ] Chain of custody table filled out completely
- [ ] Screenshots taken (see Screenshot Guide)
