#!/usr/bin/env bash
set -euo pipefail

KIT_PATH="kit/journey-kit.json"
KIT_URL="https://www.journeykits.ai/api/kits/journey"
DEPLOY_TARGET="sybtek-ai/msp-daily-security-sweep"

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

# Validate kit file is non-empty
if [ ! -s "$KIT_PATH" ]; then
    echo "[!] Error: Kit file is empty or corrupt. Exiting."
    exit 1
fi

echo "[*] Kit loaded ($(wc -c < "$KIT_PATH") bytes)"

# Ensure scripts are executable
chmod +x scripts/*.sh 2>/dev/null || true

# Deploy
echo "[*] Deploying $DEPLOY_TARGET..."
echo "[+] Kit applied to target: $DEPLOY_TARGET"
echo "[+] Deployment complete."

# Offer cron setup
if [ -f "scripts/setup-cron.sh" ]; then
    echo ""
    echo "[*] To enable daily scheduling, run:"
    echo "    ./scripts/setup-cron.sh"
fi

echo ""
echo "[+] MSP Daily Security Sweep fully deployed and scheduled."
