#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SWEEP_SCRIPT="$SCRIPT_DIR/run-sweep.sh"
CRON_ENTRY="0 2 * * * /usr/bin/env bash $SWEEP_SCRIPT >> /dev/null 2>&1"

echo "[*] MSP Daily Security Sweep — Cron Setup"

# Check if cron entry already exists
if crontab -l 2>/dev/null | grep -qF "$SWEEP_SCRIPT"; then
    echo "[+] Cron job already exists. No changes made."
else
    (crontab -l 2>/dev/null; echo "$CRON_ENTRY") | crontab -
    echo "[+] Cron job added: daily at 2:00 AM"
    echo "[+] Entry: $CRON_ENTRY"
fi

echo "[+] Cron setup complete."
