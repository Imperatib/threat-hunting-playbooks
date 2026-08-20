# Threat Hunting Playbooks

**Author:** Brandon Imperati | CySA+ | PenTest+ | SSCP
**Tools:** Splunk SPL · Microsoft Sentinel KQL · Bash
**Focus:** Proactive Threat Hunting · APT TTP Detection

---

## Overview

A structured library of threat hunting playbooks combining Splunk SPL queries, Microsoft Sentinel KQL, and a Bash rarity-analysis script. Each playbook targets a specific adversary TTP mapped to MITRE ATT&CK, written from operational experience hunting lateral movement and credential access patterns in enterprise MSP environments.

---

## Repository Structure

```
threat-hunting-playbooks/
├── playbooks/
│   ├── hunt_lateral_movement.md      # PsExec, WMI, SMB, Pass-the-Hash
│   ├── hunt_persistence.md           # Registry, scheduled tasks, services
│   ├── hunt_credential_access.md     # LSASS dumping, Kerberoasting
│   ├── hunt_c2_beaconing.md          # Low-jitter periodic callback detection
│   └── hunt_data_exfiltration.md     # DNS tunneling, large outbound transfers
├── splunk-queries/
│   ├── lateral_movement.spl
│   ├── persistence_hunting.spl
│   └── credential_access.spl
├── sentinel-queries/
│   ├── lateral_movement.kql
│   ├── persistence_hunting.kql
│   └── lsass_credential_dumping.kql
└── scripts/
    └── hunt_rare_processes.sh        # Finds statistically rare processes across a fleet
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

| Playbook          | MITRE Tactic       | Techniques Covered              |
| ------------------ | ------------------ | -------------------------------- |
| Lateral Movement   | Lateral Movement   | T1570, T1021.002, T1550.002     |
| Persistence        | Persistence        | T1053.005, T1547.001, T1543.003 |
| Credential Access  | Credential Access  | T1003.001, T1558.003            |
| C2 Beaconing       | Command and Control | T1071, T1095, T1573            |
| Data Exfiltration  | Exfiltration        | T1048, T1041, T1567             |

---

## Usage

```bash
# Rare-process hunt across an exported fleet process list (host,process_name CSV)
chmod +x scripts/hunt_rare_processes.sh
./scripts/hunt_rare_processes.sh --input process_export.csv --threshold 2
```

Splunk `.spl` and Sentinel `.kql` files are meant to be copied directly into their respective query editors (Splunk Search & Reporting / Sentinel Logs blade) — see each playbook's `.md` file for the triage and response steps that go with each query.

---

## Roadmap

- [ ] Add tested `.spl` / `.kql` query files for the C2 beaconing and data exfiltration playbooks (currently embedded inline in their `.md` files)
- [ ] Add a MITRE ATT&CK coverage map (visual)
- [ ] Add a network-traffic baseline builder script
