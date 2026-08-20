# Hunt Playbook: Data Exfiltration

**MITRE ATT&CK:** T1048 (Exfiltration Over Alternative Protocol), T1041 (Exfiltration Over C2 Channel), T1567 (Exfiltration Over Web Service)

## 1. Hypothesis
An adversary (or malicious insider) is moving sensitive data out of the environment — via DNS tunneling, an unsanctioned cloud storage service, or unusually large outbound transfers.

## 2. Data Sources
- DNS query logs (query length, frequency, unique subdomain count per domain)
- Proxy/firewall logs (bytes transferred outbound, destination category)
- Cloud access security broker (CASB) logs, if available

## 3. Hunt Queries

```
``` DNS tunneling indicator: abnormally high query volume / unique subdomain count per domain ```
index=dns_logs
| bin _time span=1h
| stats count AS query_count, dc(query) AS unique_subdomains BY domain, _time
| where query_count > 200 AND unique_subdomains > 150
| eval hunt_finding = "Suspected DNS Tunneling / Exfiltration"
| eval mitre = "T1048.003"

``` Large outbound transfer to an uncategorized or newly-seen destination ```
index=proxy_logs
| stats sum(bytes_out) AS total_bytes_out BY src_ip, dest_domain, category
| where total_bytes_out > 500000000 AND category IN ("uncategorized", "newly-registered")
| eval hunt_finding = "Suspected Large Outbound Data Transfer"
| eval mitre = "T1567"
```

## 4. Triage
- **Likely benign:** scheduled backup jobs to approved cloud storage, large legitimate file transfers to known business partners — cross-reference against a change calendar and approved-destination allowlist.
- **Suspicious:** high-volume transfer or high DNS query volume to a domain with no business justification, especially outside business hours or from a host that also shows signs of compromise from another hunt.
- **Escalate immediately if:** destination is a personal cloud storage account, a newly registered domain, or transfer volume/timing doesn't match any known business process.

## 5. Response
- Block the destination at the perimeter (proxy/firewall/DNS).
- Isolate the source host and preserve logs.
- Identify what data was accessed/transferred — scope the exposure for breach notification requirements.
- Review DLP/CASB policies for gaps that allowed the transfer.
