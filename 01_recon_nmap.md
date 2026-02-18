# Attack Scenario 01: Network Reconnaissance

## Attack Summary

| Field | Value |
|-------|-------|
| **Attack Name** | Network Reconnaissance via Nmap |
| **MITRE Tactic** | Reconnaissance (TA0043) |
| **MITRE Technique** | T1046 — Network Service Discovery |
| **Tool Used** | Nmap 7.94 |
| **Target** | 192.168.100.10 (ubuntu-victim) |
| **Attacker** | 192.168.50.5 (kali-attacker) |
| **Date Executed** | YYYY-MM-DD |

---

## Objective

Perform network reconnaissance to identify live hosts, open ports, running services, and potential vulnerabilities on the target network.

---

## Attack Steps

### Step 1: Ping Sweep (Host Discovery)

```bash
nmap -sn 192.168.100.0/24
```

**Output:**
```
Nmap scan report for 192.168.100.10
Host is up (0.00045s latency).
Nmap scan report for 192.168.100.20
Host is up (0.00052s latency).
```

### Step 2: Port Scan (Service Discovery)

```bash
nmap -sV 192.168.100.10
```

**Output:**
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu
80/tcp   open  http    Apache httpd 2.4.52
53/tcp   open  domain  ISC BIND 9.18.1
```

### Step 3: Aggressive Scan

```bash
nmap -A -T4 192.168.100.10
```

**Results:**
- Operating System: Ubuntu 22.04 LTS
- SSH Banner: OpenSSH 8.9p1
- HTTP Title: "Victim Web Server"
- DNS Server: BIND 9.18.1

### Step 4: Vulnerability Scan

```bash
nmap --script vuln 192.168.100.10
```

**Findings:**
- No critical vulnerabilities detected
- HTTP server allows directory listing
- SSH allows password authentication

---

## Wazuh Detection Analysis

### Was the Attack Detected?

**✅ YES** — Partially detected

### Wazuh Alerts Triggered

| Rule ID | Description | Severity | Count |
|---------|-------------|----------|-------|
| 5720 | Port scan detected | Medium (6) | 1 |
| - | Host scan alerts | - | 0 |

### Alert Details

**Rule 5720: Port Scan Detected**
```
Rule: 5720 - Port scan
Level: 6 (Medium)
Description: High amount of connections to same destination
Source: 192.168.50.5
Destination: 192.168.100.10
```

### Detection Gap Analysis

**What was missed:**
- Ping sweep (ICMP probes) — not logged by default
- Service version detection — not flagged as suspicious
- NSE vulnerability scripts — appeared as normal HTTP requests

**Why:**
- Wazuh default rules focus on authentication and file integrity
- Port scan detection requires correlation of netstat logs
- No IDS/IPS at network layer (only host-based agent)

---

## Packet Capture Analysis

**Wireshark Capture File:** `pcaps/01_nmap_recon.pcap`

**Key Observations:**
- 1,000+ TCP SYN packets sent to victim
- Sequential port scanning pattern visible
- DNS queries to reverse-lookup target
- HTTP GET requests to enumerate web server

**Filters Used:**
```
tcp.flags.syn == 1 && tcp.flags.ack == 0
http.request.method == "GET"
```

---

## Screenshots

1. Nmap scan output (`screenshots/01_nmap_output.png`)
2. Wazuh alert for port scan (`screenshots/01_wazuh_alert.png`)
3. Wireshark capture (`screenshots/01_wireshark.png`)

---

## Recommendations

### For Blue Team (Defense)

1. **Enable network-level IDS:**
   - Deploy Suricata or Snort alongside Wazuh
   - Create signature for rapid sequential connections

2. **Custom Wazuh Rule:**
   ```xml
   <rule id="100010" level="8">
     <if_group>netstat</if_group>
     <match>SYN_SENT</match>
     <frequency>50</frequency>
     <timeframe>10</timeframe>
     <description>Possible port scan - 50+ SYN packets in 10s</description>
   </rule>
   ```

3. **Log netstat output:**
   - Add netstat monitoring to Wazuh agent config
   - Enable iptables logging for new connections

### For Red Team (Offense)

1. **Evasion techniques:**
   - Use slower scan timing (`-T2` instead of `-T4`)
   - Randomize port scan order
   - Fragment packets to evade signature detection

---

## Lessons Learned

- **For SOC Analyst Resume:**
  - Demonstrates understanding of reconnaissance TTPs
  - Shows ability to correlate alerts with attack behavior
  - Identifies detection gaps and proposes solutions

- **For Interview Talking Points:**
  - "Simulated Nmap reconnaissance and analyzed Wazuh detection coverage"
  - "Identified that default rules miss slow scans — wrote custom correlation rule"
  - "Used Wireshark to validate attack traffic matched expected behavior"

---

## References

- MITRE ATT&CK T1046: https://attack.mitre.org/techniques/T1046/
- Wazuh Rule 5720 Documentation
- Nmap Official Documentation: https://nmap.org/book/
