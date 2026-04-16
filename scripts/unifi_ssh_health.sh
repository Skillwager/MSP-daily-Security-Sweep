#!/bin/bash
# =============================================================================
# UniFi SSH Health Check
# Connects to UniFi gateways via SSH and collects health metrics.
# =============================================================================
#
# CONFIGURATION:
#   Create ~/.config/msp-tools/unifi_sites.conf with one site per line:
#     site-name:ip-or-hostname:KEYCHAIN_VAULT_KEY_NAME
#
#   Environment variables:
#     SITES_CONFIG       — Path to sites config file
#     KEYCHAIN_PATH      — Path to custom macOS keychain (optional)
#     KC_UNLOCK_PHRASE   — Phrase to unlock custom keychain (optional)
#
# USAGE:
#   bash unifi_ssh_health.sh         # Human-readable table
#   bash unifi_ssh_health.sh json    # JSON output
#
# REQUIRES: expect, ssh
# =============================================================================

JSON_MODE="${1:-}"

SITES_CONFIG="${SITES_CONFIG:-$HOME/.config/msp-tools/unifi_sites.conf}"

SITES=()
if [ -f "$SITES_CONFIG" ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
    SITES+=("$line")
  done < "$SITES_CONFIG"
else
  echo "ERROR: Sites config not found at $SITES_CONFIG" >&2
  echo "Create the file with one site per line: site-name:ip:KEYCHAIN_KEY" >&2
  exit 1
fi

if [ ${#SITES[@]} -eq 0 ]; then
  echo "ERROR: No sites configured in $SITES_CONFIG" >&2
  exit 1
fi

KEYCHAIN_PATH="${KEYCHAIN_PATH:-}"
KC_UNLOCK_PHRASE="${KC_UNLOCK_PHRASE:-}"

REMOTE_CMD='
echo "HNAME:$(hostname 2>/dev/null)";
echo "UPTM:$(uptime 2>/dev/null)";
FW=$(ubnt-device-info firmware 2>/dev/null || cat /etc/version 2>/dev/null || echo unknown);
echo "FWVR:$FW";
DISK=$(df / 2>/dev/null | tail -1 | awk "{print \$5}");
echo "DISK:$DISK";
LOAD=$(cat /proc/loadavg 2>/dev/null | awk "{print \$1}");
echo "LOAD:$LOAD";
TEMP=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null || echo 0);
echo "TEMP:$TEMP";
echo "XDONE"
'

get_credential() {
  local VAULT_KEY="$1"
  local env_val="${!VAULT_KEY}"
  if [ -n "$env_val" ]; then
    echo "$env_val"
    return
  fi

  if [ -n "$KEYCHAIN_PATH" ] && [ -n "$KC_UNLOCK_PHRASE" ]; then
    security unlock-keychain -p "$KC_UNLOCK_PHRASE" "$KEYCHAIN_PATH" 2>/dev/null
    local pass
    pass=$(security find-generic-credential -a openclaw -s "$VAULT_KEY" -w "$KEYCHAIN_PATH" 2>/dev/null)
    if [ -n "$pass" ]; then
      echo "$pass"
      return
    fi
  fi

  local pass
  pass=$(security find-generic-credential -s "$VAULT_KEY" -w 2>/dev/null)
  if [ -n "$pass" ]; then
    echo "$pass"
    return
  fi

  echo ""
}

RESULTS=""
FAILED_LIST=""
TOTAL=${#SITES[@]}
OK=0
WARN=0
CRIT=0
UNREACH=0

for site_entry in "${SITES[@]}"; do
  IFS=: read -r SITE_NAME IP VAULT_KEY <<< "$site_entry"

  CRED=$(get_credential "$VAULT_KEY")
  if [ -z "$CRED" ]; then
    FAILED_LIST="${FAILED_LIST}${SITE_NAME}|${IP}|NO_CREDENTIAL\n"
    ((UNREACH++))
    continue
  fi

  OUTPUT=$(expect -c "
    log_user 0
    set timeout 12
    spawn ssh -o StrictHostKeyChecking=no -o PubkeyAuthentication=no -o ConnectTimeout=8 root@$IP {$REMOTE_CMD}
    expect {
      \"*assword*\" { send \"${CRED}\r\" }
      timeout { puts \"CONNECT_TIMEOUT\"; exit 1 }
      eof { puts \"CONNECTION_CLOSED\"; exit 1 }
    }
    log_user 1
    expect {
      \"*assword*\" { puts \"AUTH_FAILED\"; exit 1 }
      eof {}
    }
  " 2>&1)

  if [ $? -ne 0 ]; then
    FAILED_LIST="${FAILED_LIST}${SITE_NAME}|${IP}|UNREACHABLE\n"
    ((UNREACH++))
    continue
  fi

  HOSTNAME=$(echo "$OUTPUT" | grep "^HNAME:" | head -1 | cut -d: -f2- | tr -d '\r')
  FIRMWARE=$(echo "$OUTPUT" | grep "^FWVR:" | head -1 | cut -d: -f2- | tr -d '\r')
  DISK_PCT=$(echo "$OUTPUT" | grep "^DISK:" | head -1 | cut -d: -f2- | tr -d '%\r ')
  LOAD_1M=$(echo "$OUTPUT" | grep "^LOAD:" | head -1 | cut -d: -f2- | tr -d '\r ')
  TEMP_RAW=$(echo "$OUTPUT" | grep "^TEMP:" | head -1 | cut -d: -f2- | tr -d '\r ')
  UPTIME_LINE=$(echo "$OUTPUT" | grep "^UPTM:" | head -1 | cut -d: -f2-)
  UPTIME_DAYS=$(echo "$UPTIME_LINE" | grep -oE '[0-9]+ day' | awk '{print $1}')
  [ -z "$UPTIME_DAYS" ] && UPTIME_DAYS="0"

  if [ -n "$TEMP_RAW" ] && [ "$TEMP_RAW" != "0" ]; then
    TEMP_C=$((TEMP_RAW / 1000))
  else
    TEMP_C="n/a"
  fi

  STATUS="OK"
  ISSUES=""
  if [ -n "$DISK_PCT" ] && [ "$DISK_PCT" -ge 80 ] 2>/dev/null; then
    STATUS="CRITICAL"; ISSUES="disk ${DISK_PCT}%"; ((CRIT++))
  elif [ -n "$DISK_PCT" ] && [ "$DISK_PCT" -ge 60 ] 2>/dev/null; then
    STATUS="WARNING"; ISSUES="disk ${DISK_PCT}%"; ((WARN++))
  fi

  LOAD_INT=$(echo "$LOAD_1M" | cut -d. -f1)
  if [ -n "$LOAD_INT" ] && [ "$LOAD_INT" -ge 5 ] 2>/dev/null; then
    [ "$STATUS" = "OK" ] && STATUS="WARNING"
    ISSUES="${ISSUES:+$ISSUES, }load ${LOAD_1M}"
    [ "$STATUS" = "WARNING" ] && ((WARN++))
  fi

  [ "$STATUS" = "OK" ] && ((OK++))

  RESULTS="${RESULTS}${SITE_NAME}|${HOSTNAME}|${IP}|${FIRMWARE}|${UPTIME_DAYS}|${DISK_PCT}|${LOAD_1M}|${TEMP_C}|${STATUS}|${ISSUES}\n"
done

if [ "$JSON_MODE" = "json" ]; then
  echo "{"
  echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
  echo "  \"total\": $TOTAL,"
  echo "  \"ok\": $OK, \"warning\": $WARN, \"critical\": $CRIT, \"unreachable\": $UNREACH,"
  echo "  \"sites\": ["

  FIRST=true
  while IFS='|' read -r name host ip fw updays disk load temp status issues; do
    [ -z "$name" ] && continue
    [ "$FIRST" = true ] && FIRST=false || echo ","
    printf '    {"name":"%s","hostname":"%s","ip":"%s","firmware":"%s","uptime_days":"%s","disk_pct":"%s","load_1m":"%s","temp_c":"%s","status":"%s","issues":"%s"}' \
      "$name" "$host" "$ip" "$fw" "$updays" "$disk" "$load" "$temp" "$status" "$issues"
  done <<< "$(echo -e "$RESULTS")"

  while IFS='|' read -r name ip reason; do
    [ -z "$name" ] && continue
    [ "$FIRST" = true ] && FIRST=false || echo ","
    printf '    {"name":"%s","ip":"%s","status":"UNREACHABLE","issues":"%s"}' "$name" "$ip" "$reason"
  done <<< "$(echo -e "$FAILED_LIST")"

  echo ""
  echo "  ]"
  echo "}"
else
  echo "==================================================="
  echo "  UniFi Gateway Health (SSH)"
  echo "  $(date '+%Y-%m-%d %H:%M %Z')"
  echo "==================================================="
  echo ""
  printf "%-20s %-8s %-6s %-6s %-6s %-5s %s\n" "SITE" "FW" "UP" "DISK" "LOAD" "TEMP" "STATUS"
  echo "------------------------------------------------------------------"

  while IFS='|' read -r name host ip fw updays disk load temp status issues; do
    [ -z "$name" ] && continue
    ICON="[OK]"
    [ "$status" = "WARNING" ] && ICON="[!!]"
    [ "$status" = "CRITICAL" ] && ICON="[XX]"
    printf "%-20s %-8s %-6s %-5s%% %-6s %-4sC %s %s\n" "$name" "$fw" "${updays}d" "$disk" "$load" "$temp" "$ICON" "$issues"
  done <<< "$(echo -e "$RESULTS")"

  while IFS='|' read -r name ip reason; do
    [ -z "$name" ] && continue
    printf "%-20s %-8s %-6s %-6s %-6s %-5s [XX] %s\n" "$name" "?" "?" "?" "?" "?" "$reason"
  done <<< "$(echo -e "$FAILED_LIST")"

  echo ""
  echo "Summary: $OK ok, $WARN warning, $CRIT critical, $UNREACH unreachable / $TOTAL total"
fi
