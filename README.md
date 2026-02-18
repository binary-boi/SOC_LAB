# SOC_LAB
# 🔴 Red Team SOC Lab — Proxmox + Wazuh SIEM

> A production-grade Security Operations Center lab featuring adversarial attack simulation, SIEM detection analysis, and incident response runbooks.

[![Proxmox](https://img.shields.io/badge/Proxmox-VE%208-orange?logo=proxmox)](https://www.proxmox.com)
[![Wazuh](https://img.shields.io/badge/Wazuh-4.7-blue?logo=wazuh)](https://wazuh.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-red)](https://attack.mitre.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 📌 Project Overview

This project demonstrates hands-on cybersecurity skills by building a complete SOC lab from scratch:

- **Virtualized Network:** 4 VMs in isolated networks (attacker, victim, SOC, vulnerable target)
- **SIEM Deployment:** Wazuh Manager with centralized logging and alerting
- **Red Team Simulation:** 10 adversarial attack chains mapped to MITRE ATT&CK
- **Blue Team Analysis:** Detection gap identification + custom correlation rules
- **Incident Response:** 3 detailed runbooks for common attack scenarios

**Built by:** Akshay Kumar Sankalapuram  
**LinkedIn:** [your-linkedin]  
**Resume:** Inspired by real SOC work at Netcracker Technologies (300+ incidents/month) and Saint Louis University Cybersecurity Lab experience

---

## 🏗️ Lab Architecture

```
                      Internet
                         │
                    ┌────┴────┐
                    │ Proxmox │ (Hypervisor)
                    │   VE    │
                    └────┬────┘
         ┌───────────────┼───────────────┐
         │               │               │
    ┌────▼────┐    ┌────▼────┐    ┌────▼────┐
    │ Attacker│    │ Victims │    │   SOC   │
    │ Network │    │ Network │    │ Network │
    │vmbr3    │    │vmbr1    │    │vmbr2    │
    └────┬────┘    └────┬────┘    └────┬────┘
         │              │               │
    ┌────▼─────┐  ┌────▼────┐    ┌────▼─────┐
    │   Kali   │  │ Ubuntu  │    │  Wazuh   │
    │ Attacker │  │ Victim  │    │ Manager  │
    │192.168   │  │192.168  │    │192.168   │
    │.50.5     │  │.100.10  │    │.200.10   │
    └──────────┘  └────┬────┘    └──────────┘
                       │
                  ┌────▼─────┐
                  │Metasploi-│
                  │ table2   │
                  │192.168   │
                  │.100.20   │
                  └──────────┘
```

**Network Segments:**
- `192.168.50.0/24` — Attacker (Kali Linux)
- `192.168.100.0/24` — Victims (Ubuntu + Metasploitable2)
- `192.168.200.0/24` — SOC (Wazuh Manager + Dashboard)

---

## 💻 VM Specifications

| VM Name | OS | RAM | CPU | Disk | IP Address | Role |
|---------|-----|-----|-----|------|------------|------|
| kali-attacker | Kali Linux 2024 | 4GB | 2 | 40GB | 192.168.50.5 | Red Team |
| ubuntu-victim | Ubuntu 22.04 | 2GB | 2 | 20GB | 192.168.100.10 | Victim Web Server |
| metasploitable2 | Ubuntu 8.04 | 1GB | 1 | 8GB | 192.168.100.20 | Vulnerable Target |
| wazuh-soc | Ubuntu 22.04 | 4GB | 2 | 30GB | 192.168.200.10 | SIEM + Dashboard |

**Total Resources:** 11GB RAM, 7 CPU cores, 98GB disk

---

## ⚔️ Attack Scenarios

### Complete Matrix (10 Attacks)

| # | Attack | Tool | MITRE Tactic | MITRE Technique | Detected? |
|---|--------|------|--------------|-----------------|-----------|
| 1 | Network Recon | Nmap | Reconnaissance | T1046 | ✅ Yes |
| 2 | Web Vuln Scan | Nikto | Reconnaissance | T1595.002 | ✅ Yes |
| 3 | SSH Brute Force | Hydra | Credential Access | T1110.001 | ✅ Yes |
| 4 | FTP Exploit | Metasploit | Initial Access | T1190 | ⚠️ Partial |
| 5 | Lateral Movement | SSH Pivot | Lateral Movement | T1021.004 | ✅ Yes |
| 6 | Privilege Escalation | SUID Binary | Privilege Escalation | T1068 | ⚠️ Partial |
| 7 | Reverse Shell | Netcat | Command & Control | T1071.001 | ❌ No |
| 8 | Stealthy Scan | Nmap -T2 | Reconnaissance | T1046 | ❌ No |
| 9 | FTP Anonymous | FTP | Initial Access | T1078 | ✅ Yes |
| 10 | SMB Enumeration | enum4linux | Discovery | T1087.001 | ⚠️ Partial |

**Detection Rate:**
- ✅ Fully Detected: **5/10 (50%)**
- ⚠️ Partially Detected: **3/10 (30%)**
- ❌ Missed: **2/10 (20%)**

After implementing **5 custom Wazuh rules**, detection improved to **90%**.

Full details: [`attack-scenarios/attack_matrix.md`](attack-scenarios/attack_matrix.md)

---

## 🛡️ Detection Analysis & Custom Rules

### Detection Gaps Identified

1. **Reverse Shells (C2)** — Outbound netcat connections not monitored
2. **Slow Port Scans** — Low-frequency scans evaded thresholds
3. **Privilege Escalation** — SUID binary execution not flagged

### Custom Wazuh Rules Created

```xml
<!-- Rule 100010: Detect Port Scans -->
<rule id="100010" level="8">
  <if_group>netstat</if_group>
  <match>SYN_SENT</match>
  <frequency>50</frequency>
  <timeframe>60</timeframe>
  <description>Possible port scan detected</description>
  <mitre><id>T1046</id></mitre>
</rule>

<!-- Rule 100020: Detect Reverse Shells -->
<rule id="100020" level="10">
  <if_group>netstat</if_group>
  <match>ESTABLISHED.*:\d{4,5}</match>
  <description>Suspicious outbound connection</description>
  <mitre><id>T1071.001</id></mitre>
</rule>

<!-- Rule 100030: Flag SUID Binary Execution -->
<rule id="100030" level="12">
  <if_sid>2902</if_sid>
  <match>/bin/(vim|find|python)</match>
  <description>SUID binary execution - possible privesc</description>
  <mitre><id>T1068</id></mitre>
</rule>
```

Full ruleset: [`detection/wazuh_custom_rules.xml`](detection/wazuh_custom_rules.xml)

---

## 📋 Incident Response Runbooks

Created 3 production-ready IR runbooks:

1. **[SSH Brute Force](runbooks/IR_brute_force.md)** — Detection → Triage → Containment → Recovery
2. **[Lateral Movement](runbooks/IR_lateral_movement.md)** — Compromised host isolation + forensics
3. **[Privilege Escalation](runbooks/IR_privilege_escalation.md)** — Root cause analysis + remediation

Each runbook includes:
- Detection criteria (Wazuh alert rules)
- Step-by-step response procedures
- Bash commands for triage/containment
- Lessons learned and prevention measures

---

## 📸 Screenshots

### Proxmox Dashboard
![Proxmox VMs](screenshots/proxmox_dashboard.png)

### Wazuh Alert Dashboard
![Wazuh Alerts](screenshots/wazuh_alerts.png)

### Attack Execution
![Kali Attack](screenshots/kali_attack.png)

### Wireshark Packet Capture
![Wireshark](screenshots/wireshark_capture.png)

---

## 🚀 Setup Guide

**Complete installation guide:** [`SETUP.md`](SETUP.md)

**Quick Summary:**
1. Install Proxmox VE on bare metal (or VMware nested)
2. Create 3 virtual networks (vmbr1, vmbr2, vmbr3)
3. Deploy 4 VMs from ISOs
4. Install Wazuh Manager + agents
5. Run attack scripts from Kali
6. Analyze Wazuh alerts + write custom rules

**Time Required:** 8-10 hours over 7 days

---

## 📂 Repository Structure

```
red-team-soc-lab/
├── README.md                     ← You are here
├── SETUP.md                      ← Complete setup guide
├── LICENSE
├── .gitignore
├── diagrams/
│   └── network_topology.png      ← Lab architecture diagram
├── attack-scenarios/
│   ├── attack_matrix.md          ← MITRE ATT&CK mapping table
│   ├── 01_recon_nmap.md          ← Detailed attack write-up
│   ├── 02_web_scan_nikto.md
│   ├── 03_brute_force.md
│   └── ...
├── detection/
│   ├── wazuh_custom_rules.xml    ← Custom SIEM rules
│   ├── detection_results.md      ← Analysis of what was caught
│   └── attack_navigator_layer.json
├── runbooks/
│   ├── IR_brute_force.md         ← Incident response runbooks
│   ├── IR_lateral_movement.md
│   └── IR_privilege_escalation.md
├── scripts/
│   ├── attack_01_recon.sh        ← Ready-to-run attack scripts
│   ├── attack_03_brute_force.sh
│   └── ...
├── screenshots/
│   ├── proxmox_dashboard.png
│   ├── wazuh_alerts.png
│   └── ...
└── pcaps/
    ├── brute_force_capture.pcap  ← Wireshark packet captures
    └── ...
```

---

## 🎯 Skills Demonstrated

**For SOC Analyst Roles:**
- ✅ SIEM deployment and configuration (Wazuh)
- ✅ Alert triage and investigation
- ✅ Custom correlation rule development
- ✅ MITRE ATT&CK framework mapping
- ✅ Incident response documentation

**For System Analyst Roles:**
- ✅ Virtualization platform management (Proxmox)
- ✅ Network architecture design
- ✅ Linux system administration
- ✅ Service monitoring and logging

**For IT Support Roles:**
- ✅ VM deployment and configuration
- ✅ Network troubleshooting
- ✅ User account and access management
- ✅ Documentation and runbook creation

---

## 📚 References

- [Wazuh Documentation](https://documentation.wazuh.com/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Proxmox VE Documentation](https://pve.proxmox.com/pve-docs/)
- [Kali Linux Tools](https://www.kali.org/tools/)

---

## 👤 Author

**Akshay Kumar Sankalapuram**

- **LinkedIn:** [your-linkedin-url]
- **GitHub:** [your-github-url]
- **Email:** akshaykumar.sankalapuram@slu.edu

**Education:** M.S. Cybersecurity — Saint Louis University (GPA: 3.94/4.0)

**Experience:**
- **Netcracker Technologies** — Operations Analyst L2 (300+ incidents/month, SIEM monitoring, vulnerability log automation)
- **Saint Louis University** — Cybersecurity Lab Coordinator (Proxmox SOC lab, Wazuh SIEM deployment, CTF competitions)
- **American Red Cross** — IT End User Support (Active Directory, access management, audit compliance)

---

## 📜 License

MIT License — See [LICENSE](LICENSE) file

---

## 🙏 Acknowledgments

- **Saint Louis University CyberBillikens** — Lab infrastructure access
- **Canadian Institute for Cybersecurity** — CIC-IDS2018 dataset (used in parallel Project 1)
- **Wazuh Team** — Open-source SIEM platform

---

**⭐ If this project helps you, please star the repo!**

**📌 Pin this repo on your GitHub profile to showcase it to recruiters.**
