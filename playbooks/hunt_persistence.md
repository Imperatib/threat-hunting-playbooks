# Hunt Playbook: Persistence

**MITRE ATT&CK:** T1053 (Scheduled Task/Job), T1547 (Boot or Logon Autostart Execution), T1543 (Create or Modify System Process), T1546 (Event-Triggered Execution)

## 1. Hypothesis
An adversary with initial access is establishing a mechanism to survive reboot or logoff — a scheduled task, a new service, a registry Run key, or a WMI event subscription.

## 2. Data Sources
- Windows Security/System Event Logs (4698 scheduled task created, 7045 service installed, 4657 registry value modified)
- Sysmon Event ID 13 (registry value set)
- WMI-Activity operational log (WMI event subscription creation)

## 3. Hunt Queries
See `../splunk-queries/persistence_hunting.spl` and `../sentinel-queries/persistence_hunting.kql`.

Core signal: new scheduled task, service, or Run-key entry created outside a known change window, especially referencing an executable in a user-writable path (`%TEMP%`, `%APPDATA%`, `C:\Users\Public`).

## 4. Triage
- **Likely benign:** software installers and updaters creating expected scheduled tasks — cross-reference against known application inventory.
- **Suspicious:** task/service binary path points to an unsigned executable, a script interpreter (`powershell.exe`, `wscript.exe`) with obfuscated arguments, or a path outside `Program Files`/`Windows`.
- **Escalate immediately if:** persistence mechanism was created shortly after a known initial-access event (phishing click, exploit alert) on the same host.

## 5. Response
- Disable/remove the persistence mechanism (task, service, Run key, WMI subscription).
- Identify and quarantine the referenced binary/script.
- Check for additional persistence — adversaries frequently layer multiple mechanisms.
- Document the full chain for the incident report.
