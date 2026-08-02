# Linux Self-Healing Monitor

A dependency-free Python operations tool for monitoring, troubleshooting, and safely recovering Linux hosts. It is designed as a portfolio-quality SRE starter project and runs in **observe-only mode by default**.

**Author:** Khaled Hassan  
**Focus:** Linux | HPC | AI Infrastructure | Platform Reliability

## What it monitors

- CPU load relative to available CPU cores
- Memory pressure
- Disk use for local filesystems
- Failed systemd services
- Time synchronization state
- Default route and DNS resolver details
- High CPU and memory processes
- Recent error-level journal entries
- A transparent 0-100 health score with severity-based findings
- JSON and Markdown reports for incident handoff or automation pipelines

## Safe recovery model

The tool never changes a system unless `--apply` is supplied. Even then, it only restarts services listed in `config.json`, applies a configurable cooldown, and validates each restart. It does not install packages, change firewall rules, alter network configuration, delete files, or reboot the host.

## Quick start

```bash
python3 self_healing_monitor.py
```

To write a JSON report:

```bash
python3 self_healing_monitor.py --report health-report.json
```

To create a Markdown incident handoff report:

```bash
python3 self_healing_monitor.py --format markdown --report incident-report.md
```

To allow listed service restarts after reviewing the configuration:

```bash
sudo python3 self_healing_monitor.py --apply --config config.json
```

## Configuration

`config.json` contains thresholds and the only services that may be restarted. Start with an empty allowlist and add services only after testing your runbook.

## Important

Use this as a starter project, not an unattended production remediation platform. Integrate monitoring, alerting, change control, backups, and environment-specific validation before enabling automated recovery in a production fleet.
