# Threat Hunting Playbooks

**Author:** Brandon Imperati | CySA+ | PenTest+ | SSCP  
**Tools:** Splunk · KQL (Sentinel) · Bash · Python · MITRE ATT&CK Navigator  
**Focus:** Proactive Threat Hunting · APT TTP Detection · Lateral Movement · Persistence

---

## Overview

A structured library of threat hunting playbooks combining Splunk SPL queries, Microsoft Sentinel KQL, and Bash/Python automation scripts. Each playbook targets a specific adversary TTP mapped to the MITRE ATT&CK framework — enabling proactive hunting beyond reactive alert-based detection.

Built from operational experience hunting APTs and lateral movement in enterprise MSP environments.

---

## Repository Structure

```
threat-hunting-playbooks/
├── playbooks/
│   ├── hunt_lateral_movement.md      # PsExec, WMI, SMB, Pass-the-Hash
│   ├── hunt_persistence.md           # Registry, scheduled tasks, services, WMI subs
│   ├── hunt_credential_access.md     # LSASS dumping, Kerberoasting, DCSync
│   ├── hunt_c2_beaconing.md          # Periodic outbound, DNS tunneling, HTTP C2
│   └── hunt_data_exfiltration.md     # Staging, compression, exfil channels
├── splunk-queries/
│   ├── lateral_movement.spl
│   ├── persistence_hunting.spl
│   ├── credential_access.spl
│   └── c2_beaconing.spl
├── sentinel-queries/
│   ├── lateral_movement.kql
│   └── persistence_hunting.kql
├── scripts/
│   ├── baseline_network_traffic.py   # Build normal traffic baseline for anomaly hunting
│   ├── hunt_rare_processes.sh        # Find statistically rare processes across fleet
│   └── extract_iocs_from_logs.py    # Pull structured IOCs from raw log files
└── docs/
    ├── hunting_methodology.md
    └── mitre_coverage_map.md
```

---

## Hunting Methodology

Each playbook follows a structured 5-phase approach:

```
1. HYPOTHESIS    → What adversary behavior are we hunting?
2. DATA SOURCES  → Which logs/telemetry do we need?
3. HUNT QUERIES  → SPL/KQL queries to surface anomalies
4. TRIAGE        → How to distinguish true positives from noise
5. RESPONSE      → If confirmed, what's the IR action?
```

---

## Playbook Index (MITRE ATT&CK Mapped)

| Playbook | MITRE Tactic | Techniques Covered |
|----------|-------------|-------------------|
| Lateral Movement | Lateral Movement | T1570, T1021.002, T1550.002 |
| Persistence | Persistence | T1053, T1547, T1543, T1546 |
| Credential Access | Credential Access | T1003.001, T1558.003, T1557 |
| C2 Beaconing | Command & Control | T1071, T1048, T1095 |
| Data Exfiltration | Exfiltration | T1560, T1041, T1048 |

---

## Sample Query — C2 Beaconing Detection (Splunk)

```splunk
| tstats count AS connection_count, 
         avg(duration) AS avg_duration,
         stdev(duration) AS stdev_duration
  WHERE index=network_traffic 
  BY src_ip, dest_ip, dest_port, _time span=1h
| eval jitter_ratio = stdev_duration / avg_duration
| where connection_count > 10 
  AND jitter_ratio < 0.15         
  AND avg_duration BETWEEN 25 AND 3600
| eval hunt_finding = "Suspected C2 Beaconing — Low Jitter Periodic Callback"
| eval mitre = "T1071 / T1095"
| sort - connection_count
```

*Hunts for low-jitter, periodic outbound connections — the signature of automated C2 beaconing vs. human-driven traffic.*

---

## Sample Query — LSASS Credential Dumping (KQL / Sentinel)

```kql
DeviceProcessEvents
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("wininit.exe", "csrss.exe", "services.exe")
| where InitiatingProcessCommandLine has_any ("minidump", "sekurlsa", "procdump", "-ma lsass")
| extend RiskScore = case(
    InitiatingProcessFileName =~ "mimikatz.exe", 100,
    InitiatingProcessCommandLine has "procdump", 85,
    true, 60)
| where RiskScore >= 60
| project TimeGenerated, DeviceName, InitiatingProcessFileName, 
          InitiatingProcessCommandLine, AccountName, RiskScore
| sort by RiskScore desc
```

---

## Quick Start

```bash
# Import Splunk queries
# Copy .spl files into Splunk → Settings → Searches, Reports & Alerts → Import

# Run process rarity hunter
chmod +x scripts/hunt_rare_processes.sh
./scripts/hunt_rare_processes.sh --host CORP-WKS-047 --days 7

# Build network baseline
python scripts/baseline_network_traffic.py \
  --input network_logs.csv \
  --baseline-days 14 \
  --output baseline_profile.json
```
