# Hunt Playbook: Credential Access

**MITRE ATT&CK:** T1003.001 (LSASS Memory), T1558.003 (Kerberoasting), T1557 (Adversary-in-the-Middle)

## 1. Hypothesis
An adversary is attempting to dump credentials from memory (LSASS), request crackable Kerberos service tickets (Kerberoasting), or intercept credentials in transit.

## 2. Data Sources
- EDR process telemetry (process access to `lsass.exe`)
- Windows Security Event Logs (4769 Kerberos service ticket requested)
- Sysmon Event ID 10 (process access)

## 3. Hunt Queries
See `../sentinel-queries/lsass_credential_dumping.kql` for the LSASS-access detection and the credential-access section of `../splunk-queries/credential_access.spl` for Kerberoasting indicators (abnormal volume of RC4 [23] service ticket requests per account).

## 4. Triage
- **Likely benign:** legitimate security tooling (EDR agents, backup software) accessing LSASS with expected access rights — cross-reference against your EDR's own process.
- **Suspicious:** a non-security process (browser, Office app, unsigned binary) requesting `PROCESS_VM_READ`/`PROCESS_QUERY_INFORMATION` access to `lsass.exe`, or command lines referencing `sekurlsa`, `minidump`, or `procdump -ma lsass`.
- **Escalate immediately if:** confirmed LSASS access from an unsigned or renamed binary, or an account requesting an unusually high number of Kerberos service tickets in a short window (Kerberoasting).

## 5. Response
- Isolate the host, preserve memory if feasible for forensics.
- Force credential reset for any accounts with sessions on the affected host at the time of access.
- Review for lateral movement using any credentials that may have been exposed.
