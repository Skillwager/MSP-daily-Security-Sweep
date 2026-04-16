#!/bin/bash
# =============================================================================
# Discord Bot Message Poster
# Posts a message to a Discord channel via the Discord API.
# =============================================================================
#
# CONFIGURATION:
#   DISCORD_AUTH_BOT_CRED     — Bot credential (env var)
#   DISCORD_BOT_CRED_FILE    — Path to file containing credential
#                             (default: ~/.config/msp-tools/discord_auth)
#   DISCORD_CHANNELS          — Colon-separated name=id mappings:
#     export DISCORD_CHANNELS="general=123456:alerts=789012:security=345678"
#
# USAGE:
#   discord_post.sh <channel-id-or-shortcut> <message>
#
# EXAMPLES:
#   discord_post.sh 123456789012345678 "Hello world"
#   discord_post.sh alerts "New critical alert detected"
# =============================================================================
set -euo pipefail

DISCORD_BOT_CRED_FILE="${DISCORD_BOT_CRED_FILE:-$HOME/.config/msp-tools/discord_auth}"

if [ -n "${DISCORD_AUTH_BOT_CRED:-}" ]; then
  BOT_CRED="$DISCORD_AUTH_BOT_CRED"
elif [ -f "$DISCORD_BOT_CRED_FILE" ]; then
  BOT_CRED=$(cat "$DISCORD_BOT_CRED_FILE")
else
  echo "ERROR: Set DISCORD_AUTH_BOT_CRED env var or create $DISCORD_BOT_CRED_FILE" >&2
  exit 1
fi

if [ -z "${1:-}" ]; then
  echo "Usage: $0 <channel-id-or-shortcut> <message>" >&2
  exit 1
fi

CHANNEL_ID="$1"
shift

resolve_channel() {
  local input="$1"

  if [[ "$input" =~ ^[0-9]{17,}$ ]]; then
    echo "$input"
    return
  fi

  local env_name="DISCORD_CHANNEL_$(echo "$input" | tr '[:lower:]-' '[:upper:]_')"
  local env_val="${!env_name:-}"
  if [ -n "$env_val" ]; then
    echo "$env_val"
    return
  fi

  if [ -n "${DISCORD_CHANNELS:-}" ]; then
    IFS=':' read -ra pairs <<< "$DISCORD_CHANNELS"
    for pair in "${pairs[@]}"; do
      local name="${pair%%=*}"
      local id="${pair#*=}"
      if [ "$name" = "$input" ]; then
        echo "$id"
        return
      fi
    done
  fi

  echo "ERROR: Unknown channel shortcut '$input'." >&2
  exit 1
}

CHANNEL_ID=$(resolve_channel "$CHANNEL_ID")

MSG_FILE=$(mktemp)
echo "$*" > "$MSG_FILE"
PAYLOAD_FILE=$(mktemp)
trap "rm -f $PAYLOAD_FILE $MSG_FILE" EXIT
python3 -c "
import json
with open('$MSG_FILE') as f:
    msg = f.read().strip()
with open('$PAYLOAD_FILE', 'w') as f:
    json.dump({'content': msg}, f)
"
RESPONSE=$(curl -s -X POST \
  -H "Authorization: Bot $BOT_CRED" \
  -H "Content-Type: application/json" \
  -d @"$PAYLOAD_FILE" \
  "https://discord.com/api/v10/channels/$CHANNEL_ID/messages")
echo "$RESPONSE" | python3 -c "
import json, sys
d = json.load(sys.stdin)
if 'id' in d:
    print(f'Sent: {d[\"id\"]}')
else:
    print(f'Error: {d}')
"
