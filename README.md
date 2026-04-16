# MSP Daily Security Sweep

Daily automated security posture assessment for Managed Service Providers. Battle-tested in production across multiple client sites, 40+ endpoints, and 4 security platforms.

## What It Does

Runs a comprehensive daily check across all managed clients and produces a prioritized P1/P2/P3 findings report:

- **NinjaRMM** — endpoint alerts, AV health, open tickets
- **Bitdefender GravityZone** — fleet health, quarantine, outdated signatures, expired licenses
- **DNSFilter** — DNS threat detection, query analytics, blocked domains
- **UniFi** — gateway health via SSH (firmware, temperature, load, disk)

Silent when healthy. Posts to Discord only when human action is needed.

## Quick Start

```bash
git clone https://github.com/Skillwager/MSP-daily-Security-Sweep.git
cd MSP-daily-Security-Sweep
./install.sh
```

### Setup

Set credentials as environment variables:

```bash
# NinjaRMM (OAuth)
export NINJA_CLIENT_ID="your-client-id"
export NINJA_CLIENT_SECRET="your-client-secret"

# Bitdefender GravityZone
export GRAVITYZONE_API_KEY="your-api-key"
export GZ_COMPANY_IDS='[{"id":"abc123","name":"Client A"}]'

# DNSFilter
export DNSFILTER_API_KEY="your-bearer-token"

# Discord (optional — for alert notifications)
export DISCORD_AUTH_BOT_CRED="your-bot-token"
export DISCORD_CHANNELS="alerts=123456789:security=987654321"
```

### Validate

```bash
bash scripts/setup.sh
```

### Test Each Script

```bash
python3 scripts/ninja_api.py --test
python3 scripts/gravityzone_api.py --test
python3 scripts/dnsfilter_api.py --orgs
bash scripts/unifi_ssh_health.sh
```

### Manual Run

```bash
./scripts/run-sweep.sh
```

### Automate via Cron

```bash
./scripts/setup-cron.sh
```

Adds a daily 2:00 AM sweep. Duplicate entries are prevented automatically.

## Project Structure

```
scripts/
  ninja_api.py           # NinjaRMM API — devices, alerts, tickets, AV, backups
  gravityzone_api.py     # Bitdefender GravityZone — endpoints, quarantine, scans
  dnsfilter_api.py       # DNSFilter — traffic reports, domain lookup, allowlists
  unifi_ssh_health.sh    # UniFi gateway health via SSH
  discord_post.sh        # Discord channel message posting
  setup.sh               # Prerequisites and credential validation
  run-sweep.sh           # Orchestrator — runs all checks, produces logs + reports
  setup-cron.sh          # Cron job installer
kit/
  journey-kit.json       # Locally versioned Journey Kit
logs/                    # Per-run execution logs
reports/                 # Per-run security reports
install.sh               # Install and deployment pipeline
```

## Stack

- Python 3.10+, Bash, SSH, Tailscale
- NinjaRMM API (OAuth), GravityZone API (JSON-RPC), DNSFilter API (REST), UniFi SSH
- macOS Keychain or env vars for credential storage

## License

MIT
