# MSP Daily Security Sweep

Enterprise-grade automated security sweep system for Managed Service Provider environments. Runs daily scans, logs all activity, and produces structured reports — designed for repeatable, autonomous operation.

## Features

- **Automated daily scans** via cron scheduling
- **Local Journey Kit execution** for deterministic, versioned deployments
- **Structured logging** with timestamped log files
- **Reporting** with per-run status summaries and finding counts
- **Cron-based scheduling** for unattended daily operation

## Installation

```bash
git clone https://github.com/Skillwager/MSP-daily-Security-Sweep.git
cd MSP-daily-Security-Sweep
./install.sh
```

The install script will:
1. Create the required directory structure
2. Load the Journey Kit (or fetch it if missing)
3. Set script permissions
4. Confirm deployment status

## Manual Run

```bash
./scripts/run-sweep.sh
```

Each run produces a timestamped log in `/logs` and a report in `/reports`.

## Enable Daily Scheduling

```bash
./scripts/setup-cron.sh
```

Adds a cron job to execute the sweep daily at 2:00 AM. Duplicate entries are prevented automatically.

## Project Structure

```
kit/
  journey-kit.json       # Locally versioned Journey Kit
scripts/
  run-sweep.sh           # Core sweep execution engine
  setup-cron.sh          # Cron job installer
logs/
  sweep-<timestamp>.log  # Per-run execution logs
reports/
  report-<timestamp>.txt # Per-run security reports
install.sh               # Install and deployment pipeline
```

## Logs

All sweep activity is logged to `/logs/sweep-<timestamp>.log` with start/end times, module status, and scan metrics.

## Reports

Each run generates `/reports/report-<timestamp>.txt` containing:
- Endpoint scan counts
- Alert review totals
- Critical vulnerability status
- Final health assessment (`HEALTHY` / `REVIEW REQUIRED`)

## License

MIT
