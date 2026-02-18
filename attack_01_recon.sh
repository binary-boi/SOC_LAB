#!/bin/bash
# ============================================================
#  attack_01_recon.sh
#  Network Reconnaissance with Nmap
#  Run from Kali Linux
# ============================================================

TARGET_NETWORK="192.168.100.0/24"
TARGET_HOST="192.168.100.10"
OUTPUT_DIR="/root/soc-lab-attacks"

mkdir -p $OUTPUT_DIR

echo "[*] Starting Attack 1: Network Reconnaissance"
echo "[*] Target Network: $TARGET_NETWORK"
echo "[*] Target Host: $TARGET_HOST"
echo ""

# Phase 1: Ping Sweep
echo "[+] Phase 1: Ping Sweep (Host Discovery)"
nmap -sn $TARGET_NETWORK -oN $OUTPUT_DIR/01_ping_sweep.txt
echo "    ✓ Saved to: $OUTPUT_DIR/01_ping_sweep.txt"
echo ""

# Phase 2: Port Scan
echo "[+] Phase 2: Port Scan (Service Discovery)"
nmap -sV -O $TARGET_HOST -oN $OUTPUT_DIR/02_port_scan.txt
echo "    ✓ Saved to: $OUTPUT_DIR/02_port_scan.txt"
echo ""

# Phase 3: Aggressive Scan
echo "[+] Phase 3: Aggressive Scan (OS + Script Scan)"
nmap -A -T4 $TARGET_HOST -oN $OUTPUT_DIR/03_aggressive_scan.txt
echo "    ✓ Saved to: $OUTPUT_DIR/03_aggressive_scan.txt"
echo ""

# Phase 4: Vulnerability Scan
echo "[+] Phase 4: Vulnerability Scan (NSE Scripts)"
nmap --script vuln $TARGET_HOST -oN $OUTPUT_DIR/04_vuln_scan.txt
echo "    ✓ Saved to: $OUTPUT_DIR/04_vuln_scan.txt"
echo ""

echo "[✓] Attack 1 Complete!"
echo ""
echo "Check Wazuh Dashboard for:"
echo "  - Rule 5720 (Port scan detected)"
echo "  - MITRE ATT&CK: T1046 (Network Service Discovery)"
echo ""
echo "Next: Document results in attack-scenarios/01_recon_nmap.md"
