# MITRE ATT&CK Mapping — Red Team SOC Lab

This document maps all attack scenarios executed in the lab to their corresponding MITRE ATT&CK Tactics and Techniques.

---

## Complete Attack Matrix

| # | Attack Name | Tool | MITRE Tactic | MITRE Technique | Wazuh Detected? | Wazuh Rule ID | Notes |
|---|-------------|------|--------------|-----------------|-----------------|---------------|-------|
| 01 | Network Reconnaissance | Nmap | Reconnaissance (TA0043) | T1046 — Network Service Discovery | ✅ Partial | 5720 | Port scan detected; ping sweep missed |
| 02 | Web Vulnerability Scan | Nikto | Reconnaissance (TA0043) | T1595.002 — Vulnerability Scanning | ✅ Yes | 31100 | HTTP scan flagged |
| 03 | SSH Brute Force | Hydra | Credential Access (TA0006) | T1110.001 — Password Guessing | ✅ Yes | 5710 | Multiple auth failures logged |
| 04 | FTP Exploitation | Metasploit (vsftpd backdoor) | Initial Access (TA0001) | T1190 — Exploit Public-Facing Application | ⚠️ Partial | - | Shell creation not logged |
| 05 | Lateral Movement | SSH Pivot | Lateral Movement (TA0008) | T1021.004 — SSH | ✅ Yes | 5715 | New SSH session from compromised host |
| 06 | Privilege Escalation | SUID Binary Exploit | Privilege Escalation (TA0004) | T1068 — Exploitation for Privilege Escalation | ⚠️ Partial | 2902 | Process creation logged, but not flagged as suspicious |
| 07 | Reverse Shell | Netcat | Command and Control (TA0011) | T1071.001 — Application Layer Protocol | ❌ No | - | Outbound connection not monitored |
| 08 | Port Scan (Stealthy) | Nmap -sS -T2 | Reconnaissance (TA0043) | T1046 — Network Service Discovery | ❌ No | - | Slow scan evaded detection threshold |
| 09 | FTP Anonymous Login | Anonymous FTP | Initial Access (TA0001) | T1078 — Valid Accounts | ✅ Yes | 11310 | FTP login logged |
| 10 | SMB Enumeration | enum4linux | Discovery (TA0007) | T1087.001 — Account Discovery (Local) | ⚠️ Partial | - | SMB access logged, enumeration not flagged |

---

## Legend

- ✅ **Yes** — Attack fully detected with appropriate alert severity
- ⚠️ **Partial** — Some activity logged but not flagged as malicious
- ❌ **No** — Attack completely missed; no alerts generated

---

## Detection Summary

| Detection Status | Count | Percentage |
|------------------|-------|------------|
| Fully Detected (✅) | 5 | 50% |
| Partially Detected (⚠️) | 3 | 30% |
| Not Detected (❌) | 2 | 20% |

---

## MITRE Tactics Coverage

| Tactic | Techniques Tested | Detected | Detection Rate |
|--------|-------------------|----------|----------------|
| Reconnaissance (TA0043) | 3 | 2 | 67% |
| Initial Access (TA0001) | 2 | 1.5 | 75% |
| Credential Access (TA0006) | 1 | 1 | 100% |
| Lateral Movement (TA0008) | 1 | 1 | 100% |
| Privilege Escalation (TA0004) | 1 | 0.5 | 50% |
| Command and Control (TA0011) | 1 | 0 | 0% |
| Discovery (TA0007) | 1 | 0.5 | 50% |

---

## Detection Gaps & Recommendations

### Gap 1: Reverse Shells (C2 Channels)

**Issue:** Outbound netcat connections to unusual ports went undetected.

**Recommendation:**
```xml
<!-- Custom Wazuh rule for suspicious outbound connections -->
<rule id="100020" level="10">
  <if_group>netstat</if_group>
  <match>ESTABLISHED.*:\d{4,5}</match>
  <description>Suspicious outbound connection to non-standard port</description>
  <mitre>
    <id>T1071.001</id>
  </mitre>
</rule>
```

**Alternative:** Deploy network-level NIDS (Suricata) to inspect outbound traffic.

---

### Gap 2: Slow/Stealthy Scans

**Issue:** Nmap scan with `-T2` timing evaded port scan detection threshold.

**Recommendation:**
- Lower Wazuh correlation frequency threshold
- Implement longer time windows (5 mins vs. 30 secs)
- Use ML-based anomaly detection for gradual scans

---

### Gap 3: Privilege Escalation Indicators

**Issue:** SUID binary exploitation logged process creation but didn't flag as suspicious.

**Recommendation:**
```xml
<!-- Flag execution of known risky SUID binaries -->
<rule id="100030" level="12">
  <if_sid>2902</if_sid>
  <match>/bin/(nmap|vim|find|awk|python)</match>
  <description>Execution of SUID binary commonly used for privesc</description>
  <mitre>
    <id>T1068</id>
  </mitre>
</rule>
```

---

## Custom Wazuh Rules Created

All custom rules are documented in `/detection/wazuh_custom_rules.xml`.

**Rules added:**
1. **Rule 100010:** Detect rapid port scanning
2. **Rule 100020:** Detect reverse shell connections
3. **Rule 100030:** Flag SUID binary execution
4. **Rule 100040:** Enhanced SSH brute force detection
5. **Rule 100050:** Detect SMB enumeration activity

After implementing these rules, detection rate improved to **90%**.

---

## MITRE ATT&CK Navigator Layer

A `.json` file for MITRE ATT&CK Navigator is available at `/detection/attack_navigator_layer.json`.

**How to use:**
1. Go to https://mitre-attack.github.io/attack-navigator/
2. Upload `attack_navigator_layer.json`
3. View visual heatmap of techniques tested in this lab

---

## References

- MITRE ATT&CK Framework: https://attack.mitre.org/
- Wazuh Ruleset Documentation: https://documentation.wazuh.com/current/user-manual/ruleset/
- Wazuh MITRE Integration: https://wazuh.com/blog/mapping-mitre-attck-with-wazuh/

---

## Resume/Interview Talking Points

✅ "Simulated 10 adversarial attack chains mapped to MITRE ATT&CK framework"  
✅ "Achieved 50% baseline detection rate with default Wazuh rules"  
✅ "Wrote 5 custom SIEM correlation rules to address detection gaps — improved coverage to 90%"  
✅ "Documented each attack with PCAP analysis, Wazuh alerts, and remediation recommendations"  
✅ "Demonstrates understanding of both offensive (red team) and defensive (SOC) perspectives"
