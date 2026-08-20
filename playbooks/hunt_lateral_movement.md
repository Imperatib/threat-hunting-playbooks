# Hunt Playbook: Lateral Movement

**MITRE ATT&CK:** T1570 (Lateral Tool Transfer), T1021.002 (SMB/Windows Admin Shares), T1550.002 (Pass the Hash)

## 1. Hypothesis
An adversary who has compromised a single host is attempting to move to additional hosts using stolen credentials or built-in Windows admin tooling (PsExec, WMI, SMB admin shares).

## 2. Data Sources
- Windows Security Event Logs (4624, 4625, 4648, 4672, 4776)
- Sysmon (Event ID 1 process creation, Event ID 3 network connection)
- EDR process/network telemetry
- SMB/admin share access logs

## 3. Hunt Queries
See `../splunk-queries/lateral_movement.spl` and `../sentinel-queries/lateral_movement.kql`.

Core signal: a single source host authenticating (Type 3 logon) to multiple destination hosts in a short window, especially paired with admin-share access (`ADMIN$`, `C$`) or remote service creation.

## 4. Triage
- **Likely benign:** known IT admin accounts, patch management tools (SCCM, Ansible), backup software service accounts — cross-reference against an allowlist.
- **Suspicious:** a user account (not a service account) authenticating to 3+ hosts within 10 minutes, especially outside business hours or from an unusual source host.
- **Escalate immediately if:** followed by new process creation on the destination host from an unusual parent process (e.g., `services.exe` spawning `cmd.exe`), or use of PsExec/WMIC from a non-admin workstation.

## 5. Response
- Isolate the source host pending investigation.
- Disable the account used, force credential reset.
- Pivot to the destination host(s) — check for persistence mechanisms installed post-authentication.
- Preserve process and network logs for the affected hosts before remediation.
