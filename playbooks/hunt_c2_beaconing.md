# Hunt Playbook: C2 Beaconing

**MITRE ATT&CK:** T1071 (Application Layer Protocol), T1095 (Non-Application Layer Protocol), T1573 (Encrypted Channel)

## 1. Hypothesis
A compromised host is periodically "checking in" with an adversary-controlled command-and-control server — low-and-slow, low-jitter outbound connections designed to blend in with normal traffic.

## 2. Data Sources
- Network flow/proxy logs (source/dest IP, port, duration, bytes transferred)
- DNS query logs
- TLS/SSL certificate metadata (JA3/JA3S fingerprints, if available)

## 3. Hunt Queries
See `../splunk-queries/lateral_movement.spl` — no, see the C2 beaconing query embedded in this repo's original README history / `../splunk-queries/credential_access.spl` for the LSASS angle; the primary C2 detection query is:

```
| tstats count AS connection_count, avg(duration) AS avg_duration, stdev(duration) AS stdev_duration
  WHERE index=network_traffic BY src_ip, dest_ip, dest_port, _time span=1h
| eval jitter_ratio = stdev_duration / avg_duration
| where connection_count > 10 AND jitter_ratio < 0.15 AND avg_duration BETWEEN 25 AND 3600
| eval hunt_finding = "Suspected C2 Beaconing — Low Jitter Periodic Callback"
| eval mitre = "T1071 / T1095"
```

## 4. Triage
- **Likely benign:** legitimate polling services — software update checkers, monitoring agents, SaaS health-check pings. Cross-reference destination IP/domain reputation and known-good software inventory.
- **Suspicious:** consistent, low-jitter connection intervals to a rare or newly-registered domain, especially over non-standard ports or with no corresponding DNS lookup (raw IP connection).
- **Escalate immediately if:** the destination IP/domain has no reputation history, resolves to a bulletproof hosting provider, or the beaconing host also shows signs from another playbook (persistence, credential access) in the same timeframe.

## 5. Response
- Block the destination IP/domain at the perimeter.
- Isolate the beaconing host for forensic review.
- Hunt for additional hosts beaconing to the same destination (campaign scope).
- Preserve full packet capture if available, before remediation.
