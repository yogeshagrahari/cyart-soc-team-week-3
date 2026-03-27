# Velociraptor Forensics Cheat Sheet
**CYART SOC Team | Week 2**

---

## Installation (Server)

```bash
# 1. Download latest Velociraptor binary
wget https://github.com/Velocidex/velociraptor/releases/download/v0.72/velociraptor-v0.72.0-linux-amd64
chmod +x velociraptor-v0.72.0-linux-amd64
sudo mv velociraptor-v0.72.0-linux-amd64 /usr/local/bin/velociraptor

# 2. Generate server configuration
velociraptor config generate -i
# Follow prompts: deployment type = self-signed SSL, bind address = 0.0.0.0

# 3. Create admin user
velociraptor --config server.config.yaml user add admin --role administrator

# 4. Start server
velociraptor --config server.config.yaml frontend -v

# 5. Access GUI
# https://<SERVER_IP>:8889
```

---

## Agent Deployment (Windows)

```powershell
# 1. Download Windows MSI from Velociraptor releases
# or build client config from server:
# GUI → Clients → Add New Client → Download Installer

# 2. Install silently
msiexec /i velociraptor_client.msi /quiet

# 3. Service starts automatically
Get-Service -Name "Velociraptor"
```

---

## Key VQL (Velociraptor Query Language) Commands

### Volatile Data Collection

```sql
-- Active network connections
SELECT Laddr, Raddr, Status, Pid, Name
FROM netstat()

-- Running processes
SELECT Pid, Ppid, Name, Exe, CommandLine, CreateTime
FROM pslist()

-- DNS cache
SELECT Entry, Addresses, TTL
FROM dns_cache()

-- Logged-in users
SELECT Name, Type, LogonTime
FROM logged_in_users()

-- Open file handles
SELECT Pid, Name, Path
FROM handles()
WHERE Type = "File"

-- Loaded DLLs for a specific PID
SELECT Pid, Name, Base, Size, Path
FROM modules()
WHERE Pid = 1234
```

### Memory Acquisition

```sql
-- Memory dump collection
SELECT *
FROM Artifact.Windows.Memory.Acquisition(
  outputPath="C:\\Evidence\\memory_dump.raw"
)

-- Physical memory info
SELECT *
FROM info()
```

### Filesystem Forensics

```sql
-- Recent file modifications (last 24h)
SELECT FullPath, Size, Mtime, Atime, Ctime
FROM glob(globs="C:\\Users\\**\\*")
WHERE Mtime > now() - 86400

-- Prefetch files
SELECT *
FROM Artifact.Windows.Forensics.Prefetch()

-- Browser history
SELECT *
FROM Artifact.Windows.Applications.Chrome.History()

-- Windows event logs
SELECT *
FROM Artifact.Windows.EventLogs.EvtxHunter(
  EvtxGlob="C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
  IdRegex="4625"
)
```

### Persistence Mechanisms

```sql
-- Registry run keys (persistence)
SELECT Key, Value, Data
FROM Artifact.Windows.Persistence.PersistenceSniper()

-- Scheduled tasks
SELECT Name, Action, Triggers, Status
FROM Artifact.Windows.System.ScheduledTasks()

-- Services
SELECT Name, DisplayName, StartMode, PathName, State
FROM Artifact.Windows.System.Services()
WHERE StartMode = "Auto"
```

---

## Save Results to CSV

```sql
-- Export netstat to CSV
LET results = SELECT Laddr, Raddr, Status, Pid
FROM netstat()

SELECT * FROM results
```
Then in GUI: Results → Download CSV

Or via VQL notebook:
```sql
SELECT * FROM netstat()
| write_csv(filename="C:\\Evidence\\netstat_output.csv")
```

---

## Hash Evidence Files

```bash
# Linux — hash a collected file
sha256sum /path/to/memory_dump.raw

# Linux — hash and save to file
sha256sum memory_dump.raw > memory_dump.raw.sha256

# Windows PowerShell
Get-FileHash -Path "C:\Evidence\memory_dump.raw" -Algorithm SHA256 | Format-List

# Verify integrity
sha256sum -c memory_dump.raw.sha256
```

---

## Chain of Custody Documentation

```markdown
## Chain of Custody Record

| Field          | Value                            |
|----------------|----------------------------------|
| Case Number    | SOC-2025-0818-001                |
| Item Number    | ITEM-001                         |
| Description    | Memory dump — Server-Y           |
| Collected By   | [Analyst Name]                   |
| Collection Date| 2025-08-18 14:30:00 UTC          |
| Collection Tool| Velociraptor v0.72.0             |
| Storage Location| /evidence/SOC-2025-0818-001/   |
| SHA256 Hash    | [hash value]                     |
| Verified By    | [Supervisor Name]                |
| Verification Date | 2025-08-18 14:45:00 UTC       |
```

---

## FTK Imager — Quick Reference

```
1. Launch FTK Imager as Administrator
2. File → Create Disk Image
3. Source: Physical Drive or Logical Drive
4. Image Type: E01 (Expert Witness) or RAW/DD
5. Set destination path
6. ✅ Check: Verify images after they are created
7. ✅ Check: Create directory listings
8. Click Start → wait for completion
9. Verify hash shown in summary matches source hash
10. Document in chain of custody
```

Memory capture with FTK Imager:
```
File → Capture Memory
→ Set destination folder
→ Check: Include pagefile
→ Click Capture Memory
→ SHA256 of output file: Get-FileHash memory.mem
```
