# MSP Daily Security Sweep

Automated, repeatable security sweep for MSP environments. Packages a locally versioned Journey Kit with a clean install pipeline for deterministic, portable deployments.

## Quick Start

```bash
git clone https://github.com/Skillwager/MSP-daily-Security-Sweep.git
cd MSP-daily-Security-Sweep
./install.sh
```

## How It Works

1. The install script loads the Journey Kit from `kit/journey-kit.json`.
2. If the local kit is missing, it fetches a fresh copy from the Journey registry.
3. The kit is validated and deployed against the target configuration.

## Project Structure

```
kit/
  journey-kit.json   # Locally versioned Journey Kit
install.sh           # Install and deployment pipeline
README.md
```

## Notes

- **Deterministic installs** — the kit is committed to the repo so every deploy uses the same artifact.
- **Repeatable daily execution** — run `./install.sh` on any schedule.
- **Scheduling** — pair with `cron` for automated daily sweeps:
  ```
  0 6 * * * cd /path/to/MSP-daily-Security-Sweep && ./install.sh >> /var/log/msp-sweep.log 2>&1
  ```

## License

MIT
