# Zeek Telemetry to MITRE ATT&CK Behavioral Mapping Database Documentation

## 1. Zeek Telemetry Coverage Overview

The Zeek monitoring infrastructure provides network-level visibility across multiple attack phases including reconnaissance, initial access, discovery, lateral movement, command and control, collection, and exfiltration.

Zeek logs are not treated as standalone detections. Instead, they are converted into normalized telemetry events and mapped probabilistically to MITRE ATT&CK techniques. Behavioral techniques require correlation across multiple events, while direct mappings rely on explicit protocol indicators or signatures.

The mapping database provides:

- ATT&CK technique identification
- Associated Zeek telemetry source
- Required fields
- Detection type
- Confidence score
- Behavioral correlation requirements
- False positive considerations
- Required enrichment sources


---

# 2. Zeek Log to MITRE ATT&CK Technique Mapping


| Technique ID | Technique Name | Tactic | Mapping Type | Confidence | Zeek Log(s) |
|-------------|----------------|--------|--------------|------------|-------------|
| T1046 | Network Service Scanning | Reconnaissance | Behavioral | 0.80-0.85 | conn.log |
| T1595.001 | Active Scanning: Scanning IP Blocks | Reconnaissance | Behavioral | 0.82 | conn.log |
| T1595.002 | Active Scanning: Vulnerability Scanning | Reconnaissance | Behavioral | 0.88 | http.log |
| T1590.001 | Gather Victim Network Information: Domain Properties | Reconnaissance | Direct | 0.75 | dns.log |
| T1590.002 | Gather Victim Network Information: DNS | Reconnaissance | Behavioral | 0.78 | dns.log |
| T1592 | Gather Victim Host Information | Reconnaissance | Behavioral | 0.70 | conn.log |
| T1083 | File and Directory Discovery | Discovery | Behavioral | 0.82 | http.log |
| T1018 | Remote System Discovery | Discovery | Behavioral | 0.75 | conn.log |
| T1016 | System Network Configuration Discovery | Discovery | Direct | 0.65 | dns.log |
| T1049 | System Network Connections Discovery | Discovery | Behavioral | 0.70 | conn.log |
| T1190 | Exploit Public-Facing Application | Initial Access | Direct/Behavioral | 0.78-0.92 | notice.log, http.log, weird.log |
| T1133 | External Remote Services | Initial Access | Direct | 0.70 | conn.log |
| T1078 | Valid Accounts | Initial Access | Direct | 0.65-0.68 | ssh.log, conn.log |
| T1505.003 | Server Software Component: Web Shell | Persistence | Direct/Behavioral | 0.85-0.88 | http.log |
| T1059.001 | PowerShell | Execution | Direct | 0.75 | http.log |
| T1059.003 | Windows Command Shell | Execution | Direct | 0.70 | http.log |
| T1203 | Exploitation for Client Execution | Execution | Direct | 0.80 | files.log |
| T1204 | User Execution | Execution | Direct | 0.60 | http.log |
| T1110 | Brute Force | Credential Access | Behavioral | 0.82-0.88 | ssh.log, http.log |
| T1110.001 | Password Guessing | Credential Access | Behavioral | 0.85 | ssh.log |
| T1110.003 | Password Spraying | Credential Access | Behavioral | 0.80-0.86 | ssh.log, http.log |
| T1003 | OS Credential Dumping | Credential Access | Behavioral | 0.55 | conn.log |
| T1021.001 | Remote Desktop Protocol | Lateral Movement | Direct | 0.72 | conn.log |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement | Direct | 0.70 | conn.log |
| T1021.004 | SSH | Lateral Movement | Direct/Behavioral | 0.75-0.78 | ssh.log, conn.log |
| T1210 | Exploitation of Remote Services | Lateral Movement | Behavioral | 0.75 | conn.log |
| T1071.001 | Application Layer Protocol: Web Protocols | Command and Control | Behavioral | 0.80-0.82 | http.log, ssl.log |
| T1071.002 | Application Layer Protocol: File Transfer Protocols | Command and Control | Behavioral | 0.72 | ftp.log |
| T1071.004 | Application Layer Protocol: DNS | Command and Control | Behavioral | 0.85 | dns.log |
| T1572 | Protocol Tunneling | Command and Control | Behavioral | 0.88 | dns.log |
| T1571 | Non-Standard Port | Command and Control | Direct | 0.75 | conn.log |
| T1095 | Non-Application Layer Protocol | Command and Control | Behavioral | 0.78 | conn.log |
| T1105 | Ingress Tool Transfer | Command and Control | Direct | 0.85-0.88 | http.log, ftp.log |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | Behavioral | 0.82 | conn.log |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration | Behavioral | 0.75 | conn.log |
| T1048.003 | Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol | Exfiltration | Behavioral | 0.80-0.87 | http.log, dns.log |
| T1567 | Exfiltration Over Web Service | Exfiltration | Behavioral | 0.78 | http.log |
| T1039 | Data from Network Shared Drive | Collection | Behavioral | 0.60 | conn.log |
| T1213 | Data from Information Repositories | Collection | Behavioral | 0.65 | http.log |
| T1496 | Resource Hijacking | Impact | Behavioral | 0.75 | conn.log |
| T1497 | Virtualization/Sandbox Evasion | Defense Evasion | Behavioral | 0.55 | dns.log |


---

# 3. Zeek Log Visibility and Security Fields


| Zeek Log | Primary Visibility | ATT&CK Tactics Covered | Key Security-Relevant Fields |
|----------|--------------------|------------------------|------------------------------|
| conn.log | Network connection metadata and communication flows | Reconnaissance, Discovery, Lateral Movement, C2, Exfiltration | id.orig_h, id.resp_h, id.resp_p, proto, service, conn_state, duration, orig_bytes, resp_bytes, ts |
| dns.log | DNS queries and responses | Reconnaissance, Discovery, C2, Exfiltration | id.orig_h, query, qtype_name, answers, rcode, TTL, ts |
| http.log | HTTP request and response analysis | Initial Access, Execution, Persistence, C2, Collection, Exfiltration | id.orig_h, host, uri, method, status_code, user_agent, referrer, request_body_len, response_body_len, ts |
| ssl.log | TLS session metadata | C2 | id.orig_h, id.resp_h, server_name, version, cipher, subject, issuer, validation_status, ts |
| x509.log | Certificate information | C2, Defense Evasion | certificate.subject, issuer, serial, validity dates |
| files.log | File transfer and extraction metadata | Initial Access, Execution, C2 | filename, mime_type, md5, sha1, source, tx_hosts, rx_hosts, ts |
| notice.log | Zeek signature-based alerts | Initial Access, Reconnaissance | src, dst, note, msg, sub, ts |
| weird.log | Protocol anomalies | Initial Access, Lateral Movement | id.orig_h, id.resp_h, name, addl, ts |
| ssh.log | SSH authentication activity | Credential Access, Lateral Movement | id.orig_h, id.resp_h, auth_success, client, server, direction, ts |
| ftp.log | FTP command activity | C2, Exfiltration, Tool Transfer | id.orig_h, user, command, arg, reply_code, file_size, ts |






# 4. Techniques Requiring Correlation Instead of Direct Mapping

Zeek provides high-value network visibility, but many MITRE ATT&CK techniques cannot be reliably identified from a single network event.

A single DNS request, HTTP request, or TCP connection is usually legitimate activity. Detection requires behavioral analysis across multiple events, time windows, and contextual information.

The Behavioral Detection Engine aggregates Zeek events and calculates technique confidence based on:

- Event frequency
- Source and destination relationships
- Timing patterns
- Traffic volume
- Protocol behavior
- Host baseline deviation
- External threat intelligence enrichment


| Technique ID | Technique Name | Why Correlation Is Required | Key Correlation Parameters |
|-------------|----------------|-----------------------------|----------------------------|
| T1046 | Network Service Scanning | A single connection is normal; scanning requires broad targeting | GROUP BY orig_h, count unique resp_h > 10, count unique resp_p > 15, window 60s |
| T1595.001 | Active Scanning: Scanning IP Blocks | Internet background traffic can look similar; sequential targeting indicates reconnaissance | GROUP BY orig_h, sequential IP coverage, count destinations > 20, window 180s |
| T1595.002 | Active Scanning: Vulnerability Scanning | Single HTTP errors are normal; vulnerability scanners generate repeated patterns | GROUP BY orig_h, host, unique URI > 30, error ratio > 60%, window 60s |
| T1590.002 | Gather Victim Network Information: DNS | Single DNS queries are normal; enumeration requires systematic discovery | GROUP BY orig_h, unique queries > 20, NXDOMAIN ratio analysis, window 60s |
| T1083 | File and Directory Discovery | One missing file generates 404; enumeration requires many paths | GROUP BY orig_h, host, unique URI > 25, 404 ratio > 70%, window 60s |
| T1018 | Remote System Discovery | One connection does not indicate discovery; multiple hosts indicate scanning | GROUP BY orig_h, unique resp_h > 10, window 120s |
| T1049 | System Network Connections Discovery | Requires mapping of communication relationships | GROUP BY orig_h, unique resp_h > 8, unique ports > 5, low byte volume, window 180s |
| T1190 | Exploit Public-Facing Application | Suspicious requests require exploitation context | HTTP exploit pattern + server errors + weird.log correlation |
| T1505.003 | Web Shell | Single suspicious URI is weak evidence | GROUP BY host, uri, repeated access > 3, command parameters, no referrer, window 300s |
| T1110 | Brute Force | Failed authentication alone is common | GROUP BY orig_h, resp_h, failures > 10, failure ratio > 90%, window 60s |
| T1110.001 | Password Guessing | Requires repeated attempts against one account/service | GROUP BY orig_h, resp_h, attempts > 15, interval < 5s, window 120s |
| T1110.003 | Password Spraying | Requires low attempts against many accounts | GROUP BY orig_h, targets > 5, attempts per target <= 3, window 300-600s |
| T1003 | OS Credential Dumping | Network activity alone cannot prove credential dumping | SMB activity + lateral movement indicators + endpoint correlation |
| T1021.004 | SSH Lateral Movement | Legitimate SSH administration exists | GROUP BY orig_h, unique resp_h > 3, port 22, duration > 30s, window 300s |
| T1210 | Exploitation of Remote Services | Requires exploitation behavior after discovery | GROUP BY orig_h, service, targets > 5, unusual service behavior |
| T1071.001 | HTTP C2 | Single HTTP request is normal browsing | GROUP BY orig_h, host, repeated requests > 4, beacon CV < 0.3, no referrer |
| T1071.001 | HTTPS C2 | Requires encrypted beaconing indicators | GROUP BY orig_h, resp_h, repeated TLS sessions, certificate anomalies, CV < 0.3 |
| T1071.004 | DNS C2 | DNS is frequently used legitimately | GROUP BY orig_h, domain, unique subdomains > 10, beacon interval analysis |
| T1572 | DNS Tunneling | Single long DNS request is insufficient | GROUP BY orig_h, domain, queries > 50, avg length > 60, rate > 1/s |
| T1095 | Non-Application Layer Protocol C2 | Unknown protocols may be legitimate | GROUP BY orig_h, resp_h, resp_p, repeated sessions, duration > 300s |
| T1041 | Exfiltration Over C2 Channel | Requires confirmed C2 relationship | Prior C2 mapping + orig_bytes > 10MB, window 3600s |
| T1048.003 | HTTP Exfiltration | Large uploads may be backups | POST requests + volume > 5MB + no referrer + suspicious destination |
| T1048.003 | DNS Exfiltration | Requires encoded high-volume DNS traffic | Queries > 100, avg length > 70, rate > 1/s |
| T1567 | Exfiltration Over Web Service | Cloud uploads may be legitimate | Cloud destination + upload volume > 10MB + unusual account context |
| T1048 | Alternative Protocol Exfiltration | Requires unusual transfer behavior | orig_bytes > 50MB, unusual port, ratio > 50 |
| T1039 | Data From Network Shared Drive | SMB usage is common | Port 445 + large transfer + suspicious source host |
| T1213 | Data From Information Repositories | API usage alone is insufficient | Export patterns + large response volume |
| T1071.002 | FTP C2 | FTP may be legacy business traffic | Repeated sessions + beacon timing |
| T1496 | Resource Hijacking | Requires mining behavior | Persistent connections + known mining destinations |


---

# 5. Zeek Logging Improvements and Additional Fields


## 5.1 Zeek Script Enhancements for Increased ATT&CK Coverage


| Improvement | Target Techniques | Implementation |
|-------------|------------------|----------------|
| SMB file share parsing | T1021.002, T1039, T1003 | Enable smb_files.log and smb_mapping.log to capture ADMIN$, C$, IPC$ activity and file operations |
| SMB named pipe tracking | T1003.001 | Capture pipe names such as lsarpc, samr, and netlogon |
| HTTP file hashing | T1105, T1203 | Enable file extraction and calculate hashes through files.log |
| SSL certificate chain validation | T1071.001, T1573 | Correlate ssl.log with x509.log certificate information |
| SSH behavior analysis | T1021.004 | Add timing analysis for interactive SSH sessions |
| DNS TTL logging | T1071.004, T1572 | Record DNS TTL values for fast-flux and tunneling detection |
| HTTP header analysis | T1190, T1505.003 | Capture unusual headers and command injection indicators |
| RDP protocol logging | T1021.001 | Enable RDP analysis logs for session metadata |
| Kerberos logging | T1110, T1078 | Enable Kerberos events for authentication abuse detection |
| NTLM tracking | T1003, T1078 | Enable NTLM authentication monitoring for credential abuse |


---

# 6. Behavioral Detection Engine Enhancements


| Enhancement | Purpose |
|-------------|---------|
| Connection state transition tracking | Detect scanning progression from SYN attempts to service identification |
| Byte ratio analysis | Separate downloads, uploads, and exfiltration behavior |
| Beaconing jitter analysis | Detect malware periodic communication patterns |
| Domain entropy scoring | Identify DGA-generated domains |
| Threat intelligence enrichment | Identify malicious IPs, domains, and certificates |
| Host role profiling | Reduce false positives by understanding normal host behavior |
| Temporal baseline analysis | Detect deviations from normal network activity |


---

# 7. Multi-Source Correlation Recommendations


Zeek mappings should not operate independently. High-confidence ATT&CK detection requires correlation with endpoint and application telemetry.


| Data Source | Techniques Improved | Required Correlation |
|-------------|--------------------|---------------------|
| Windows Security Events | T1078, T1110 | Event IDs 4624 and 4625 for authentication analysis |
| Sysmon | T1059.001, T1105 | Event ID 1 process creation and command line analysis |
| Linux Auditd | T1021.004, T1003 | Authentication and syscall monitoring |
| Apache/Tomcat Logs | T1190, T1505.003 | Web exploitation and server-side anomalies |
| File Hash Intelligence | T1105, T1203 | Malware reputation verification |


---

# 8. Confidence Score Calibration


The confidence values represent the probability that observed telemetry corresponds to an ATT&CK technique.

The Behavioral Detection Engine should use confidence scoring rather than binary detection.


| Confidence Range | Meaning | Example |
|-----------------|---------|---------|
| 0.90 - 0.95 | Strong direct evidence | Confirmed exploit signatures, malware communication patterns |
| 0.75 - 0.88 | Strong behavioral evidence | DNS tunneling, brute force, C2 beaconing |
| 0.60 - 0.72 | Moderate evidence requiring context | Remote access, suspicious downloads |
| 0.40 - 0.55 | Weak indicators requiring multi-source validation | Credential dumping network indicators, sandbox evasion |


## Confidence Adjustment Logic


The engine should apply:


### Confidence Amplification

Increase confidence when:

- Multiple related ATT&CK techniques occur on the same host
- Events appear in a realistic attack sequence
- Endpoint telemetry confirms network behavior
- Threat intelligence matches observed indicators


Example:
T1105 Ingress Tool Transfer
+
T1059 Command Execution
+
T1071 DNS C2

Result:
Increase compromise confidence significantly



### Confidence Decay

Reduce confidence when:

- No supporting activity appears after detection
- Behavior matches normal host baseline
- Destination is verified legitimate
- Expected attack progression does not continue


This probabilistic approach prevents isolated network events from generating excessive false positives while allowing the engine to recognize multi-stage attacker behavior.