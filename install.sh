#!/usr/bin/env bash
set -euo pipefail

KIT_PATH="kit/journey-kit.json"
KIT_URL="https://www.journeykits.ai/api/kits/journey"

echo "[*] MSP Daily Security Sweep — Install Pipeline"
echo "[*] Initializing..."

# Ensure directory structure
mkdir -p kit logs reports scripts

# Load or fetch the Journey Kit
if [ -f "$KIT_PATH" ]; then
    echo "[+] Local Journey Kit found at $KIT_PATH"
else
    echo "[!] Local kit missing — fetching from $KIT_URL"
    curl -sS "$KIT_URL" -o "$KIT_PATH"
    echo "[+] Kit saved to $KIT_PATH"
fi

if [ ! -s "$KIT_PATH" ]; then
    echo "[!] Error: Kit file is empty or corrupt. Exiting."
    exit 1
fi

echo "[*] Kit loaded ($(wc -c < "$KIT_PATH") bytes)"

# Ensure scripts are executable
chmod +x scripts/*.sh 2>/dev/null || true
chmod +x scripts/*.py 2>/dev/null || true

# Validate prerequisites
echo "[*] Checking prerequisites..."
if command -v python3 >/dev/null 2>&1; then
    echo "[+] Python3: $(python3 --version 2>&1)"
else
    echo "[!] Python3 not found — required for API scripts"
fi

if command -v curl >/dev/null 2>&1; then
    echo "[+] curl: available"
else
    echo "[!] curl not found — required for API calls"
fi

echo ""
echo "[*] To validate credentials, run:"
echo "    bash scripts/setup.sh"
echo ""
echo "[*] To enable daily scheduling, run:"
echo "    ./scripts/setup-cron.sh"
echo ""
echo "[+] MSP Daily Security Sweep fully deployed."
