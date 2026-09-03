#!/bin/bash
# setup-cloud-nmap.sh
# Configure nmap to detect DARWIN Cloud Benchmark simulated services.
#
# Two steps:
#   1. Merge custom cloud probes into a complete Nmap data directory
#      (Nmap 7.x has no --servicedb option; use --datadir)
#   2. Run fix-nmap-tcpwrapped.sh (with sudo) to add iptables rules for
#      Docker-published cloud ports (10601-10642 and protocol aux ports)
#
# Usage:
#   bash setup-cloud-nmap.sh              # interactive (prompts for sudo)
#   sudo bash setup-cloud-nmap.sh         # run as root directly
#
# To revert:
#   rm ~/.nmap/nmap-service-probes        # (if it was a symlink we created)
#   sudo iptables -F DOCKER-USER          # remove iptables rules
#   sudo systemctl restart docker         # Docker will recreate its rules

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLOUD_PROBES="$SCRIPT_DIR/nmap-cloud-probes.txt"
SYSTEM_PROBES="/usr/share/nmap/nmap-service-probes"
USER_PROBES="$HOME/.nmap/nmap-service-probes"

echo "=== DARWIN Cloud Benchmark — nmap Setup ==="
echo ""

# ── Step 1: Merge custom probes ──────────────────────────────────────
mkdir -p "$HOME/.nmap"
cp -a /usr/share/nmap/. "$HOME/.nmap/"

if [ ! -f "$CLOUD_PROBES" ]; then
    echo "[!] Cloud probes file not found: $CLOUD_PROBES"
    echo "    Expected in cve_challenges/scripts/ alongside this script."
    exit 1
fi

cat "$SYSTEM_PROBES" "$CLOUD_PROBES" > "$USER_PROBES"
echo "[+] Merged cloud probes into $USER_PROBES"
echo "    ($(wc -l < "$SYSTEM_PROBES") system lines + $(wc -l < "$CLOUD_PROBES") cloud lines)"
echo "    nmap will auto-use $USER_PROBES for service detection."
echo "    For Nmap 7.x, invoke: nmap --datadir $HOME/.nmap -sV ..."
echo ""

# ── Step 2: iptables rules for cloud ports ──────────────────────────
FIX_SCRIPT="$SCRIPT_DIR/fix-nmap-tcpwrapped.sh"

if [ ! -f "$FIX_SCRIPT" ]; then
    echo "[!] fix-nmap-tcpwrapped.sh not found at $FIX_SCRIPT"
    exit 1
fi

if [ "$(id -u)" -eq 0 ]; then
    # Already root — run directly
    bash "$FIX_SCRIPT"
else
    echo "[*] iptables rules require root. Running: sudo bash $FIX_SCRIPT"
    sudo bash "$FIX_SCRIPT"
fi

echo ""
echo "=== Setup complete ==="
echo ""
echo "    Verify with:"
echo "      nmap --datadir $HOME/.nmap -sV --version-all -Pn -p 10601,10670,10671 localhost"
echo "      bash $SCRIPT_DIR/validate-cloud-nmap.sh cloud-01"
echo "    (requires a running cloud scenario, e.g. cloud-01)"
echo ""
echo "    Revert with:"
echo "      rm $USER_PROBES"
echo "      sudo iptables -F DOCKER-USER && sudo systemctl restart docker"
