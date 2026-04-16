#!/bin/bash
# =============================================================================
# MSP Security Sweep — Setup and Validation
# Checks prerequisites, validates credentials, and runs a test sweep.
# =============================================================================
#
# USAGE:
#   bash setup.sh              # Full setup check
#   bash setup.sh --check      # Prerequisites only
#   bash setup.sh --validate   # Credential validation only
#   bash setup.sh --test       # Run test sweep (dry run)
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ERRORS=0
WARNINGS=0

ok()   { echo "  [OK] $1"; }
warn() { echo "  [!!] $1"; ((WARNINGS++)); }
fail() { echo "  [XX] $1"; ((ERRORS++)); }

check_prerequisites() {
  echo ""
  echo "=== Prerequisites ==="

  if command -v python3 >/dev/null 2>&1; then
    ok "Python3: $(python3 --version 2>&1 | head -1)"
  else
    fail "Python3 not found. Install Python 3.10+"
  fi

  if command -v expect >/dev/null 2>&1; then
    ok "expect: installed"
  else
    fail "expect not found. Install: brew install expect (macOS) or apt install expect (Linux)"
  fi

  if command -v curl >/dev/null 2>&1; then
    ok "curl: installed"
  else
    fail "curl not found"
  fi

  if command -v ssh >/dev/null 2>&1; then
    ok "ssh: installed"
  else
    fail "ssh not found"
  fi

  if command -v tailscale >/dev/null 2>&1; then
    if tailscale status >/dev/null 2>&1; then
      ok "Tailscale: connected"
    else
      warn "Tailscale: installed but not connected (needed for UniFi SSH)"
    fi
  else
    warn "Tailscale: not installed (optional, needed for cross-site UniFi SSH)"
  fi

  if python3 -c "import requests" 2>/dev/null; then
    ok "Python requests: installed"
  else
    fail "Python requests not found. Install: pip3 install requests"
  fi
}

validate_credentials() {
  echo ""
  echo "=== Credentials ==="

  if [ -n "${NINJA_CLIENT_ID:-}" ] && [ -n "${NINJA_CLIENT_SECRET:-}" ]; then
    if python3 "$SCRIPT_DIR/ninja_api.py" --test >/dev/null 2>&1; then
      ok "NinjaRMM: OAuth working"
    else
      fail "NinjaRMM: credentials set but OAuth failed"
    fi
  else
    fail "NinjaRMM: set NINJA_CLIENT_ID and NINJA_CLIENT_SECRET"
  fi

  if [ -n "${GRAVITYZONE_API_KEY:-}" ]; then
    if python3 "$SCRIPT_DIR/gravityzone_api.py" --test >/dev/null 2>&1; then
      ok "GravityZone: API connected"
    else
      fail "GravityZone: key set but API test failed"
    fi
  else
    fail "GravityZone: set GRAVITYZONE_API_KEY"
  fi

  if [ -n "${DNSFILTER_API_KEY:-}" ]; then
    ok "DNSFilter: API key set"
  else
    fail "DNSFilter: set DNSFILTER_API_KEY"
  fi

  SITES_CONFIG="${SITES_CONFIG:-$HOME/.config/msp-tools/unifi_sites.conf}"
  if [ -f "$SITES_CONFIG" ]; then
    SITE_COUNT=$(grep -cv '^#\|^$' "$SITES_CONFIG" 2>/dev/null || echo 0)
    ok "UniFi sites: $SITE_COUNT sites configured in $SITES_CONFIG"
  else
    warn "UniFi sites: no config at $SITES_CONFIG"
  fi

  if [ -n "${DISCORD_AUTH_BOT_CRED:-}" ]; then
    ok "Discord: credential set via env var"
  elif [ -f "${DISCORD_BOT_CRED_FILE:-$HOME/.config/msp-tools/discord_auth}" ]; then
    ok "Discord: credential file found"
  else
    warn "Discord: set DISCORD_AUTH_BOT_CRED or create credential file (optional)"
  fi
}

test_sweep() {
  echo ""
  echo "=== Test Sweep (dry run) ==="

  echo "  Running NinjaRMM alerts check..."
  if python3 "$SCRIPT_DIR/ninja_api.py" --alerts 2>/dev/null; then
    ok "NinjaRMM alerts: working"
  else
    fail "NinjaRMM alerts: failed"
  fi

  echo "  Running GravityZone health..."
  if python3 "$SCRIPT_DIR/gravityzone_api.py" --health 2>/dev/null; then
    ok "GravityZone health: working"
  else
    fail "GravityZone health: failed"
  fi

  echo "  Running DNSFilter check..."
  if python3 "$SCRIPT_DIR/dnsfilter_api.py" 2>/dev/null; then
    ok "DNSFilter: working"
  else
    fail "DNSFilter: failed"
  fi

  SITES_CONFIG="${SITES_CONFIG:-$HOME/.config/msp-tools/unifi_sites.conf}"
  if [ -f "$SITES_CONFIG" ]; then
    echo "  Running UniFi SSH health..."
    if bash "$SCRIPT_DIR/unifi_ssh_health.sh" 2>/dev/null; then
      ok "UniFi SSH: working"
    else
      warn "UniFi SSH: some sites may be unreachable"
    fi
  else
    warn "UniFi SSH: skipped (no sites config)"
  fi
}

echo "MSP Security Sweep — Setup Validation"
echo "======================================"

case "${1:-}" in
  --check)    check_prerequisites ;;
  --validate) validate_credentials ;;
  --test)     test_sweep ;;
  *)
    check_prerequisites
    validate_credentials
    ;;
esac

echo ""
echo "======================================"
echo "Result: $ERRORS errors, $WARNINGS warnings"
if [ $ERRORS -gt 0 ]; then
  echo "Fix the errors above before running the sweep."
  exit 1
else
  echo "Ready to run."
  exit 0
fi
