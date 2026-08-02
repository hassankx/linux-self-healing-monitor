#!/usr/bin/env python3
"""Linux health monitoring, incident triage, and safe allowlisted recovery.

Author: Khaled Hassan
Location: Global - Canada & Saudi Arabia
License: MIT-style portfolio sample; validate before production use.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

__author__ = "Khaled Hassan"
__version__ = "1.0.0"

DEFAULT_CONFIG: dict[str, Any] = {
    "load_per_cpu_warning": 1.5,
    "memory_used_percent_warning": 90,
    "disk_used_percent_warning": 90,
    "restart_cooldown_minutes": 30,
    "max_journal_error_lines": 40,
    "restart_allowlist": [],
}
PSEUDO_FILESYSTEMS = {"tmpfs", "devtmpfs", "proc", "sysfs", "cgroup", "cgroup2", "overlay", "squashfs"}


@dataclass
class Finding:
    severity: str
    check: str
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def run(command: list[str], timeout: int = 15) -> tuple[int, str]:
    """Run a local diagnostic command without shell evaluation."""
    try:
        completed = subprocess.run(command, text=True, capture_output=True, check=False, timeout=timeout)
        return completed.returncode, (completed.stdout or completed.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as error:
        return 1, str(error)


def load_json(path: Path, fallback: dict[str, Any]) -> dict[str, Any]:
    if not path.exists():
        return fallback.copy()
    try:
        with path.open(encoding="utf-8") as handle:
            return {**fallback, **json.load(handle)}
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"Cannot read {path}: {error}") from error


def memory_snapshot() -> dict[str, float] | None:
    try:
        values: dict[str, int] = {}
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            key, value = line.split(":", 1)
            values[key] = int(value.strip().split()[0])
        total_kib, available_kib = values["MemTotal"], values["MemAvailable"]
        return {
            "total_gib": round(total_kib / 1024 / 1024, 2),
            "available_gib": round(available_kib / 1024 / 1024, 2),
            "used_percent": round((1 - available_kib / total_kib) * 100, 1),
        }
    except (FileNotFoundError, KeyError, ValueError):
        return None


def filesystem_snapshot() -> list[dict[str, Any]]:
    mounts: list[dict[str, Any]] = []
    seen: set[str] = set()
    try:
        lines = Path("/proc/mounts").read_text(encoding="utf-8").splitlines()
    except OSError:
        return mounts
    for line in lines:
        device, mountpoint, fstype, *_ = line.split()
        if fstype in PSEUDO_FILESYSTEMS or mountpoint in seen:
            continue
        seen.add(mountpoint)
        try:
            usage = shutil.disk_usage(mountpoint)
        except OSError:
            continue
        if usage.total == 0:
            continue
        mounts.append({
            "device": device,
            "mountpoint": mountpoint,
            "filesystem": fstype,
            "used_percent": round(usage.used / usage.total * 100, 1),
            "free_gib": round(usage.free / 1024**3, 2),
        })
    return sorted(mounts, key=lambda item: item["used_percent"], reverse=True)


def failed_services() -> list[str]:
    if not shutil.which("systemctl"):
        return []
    code, output = run(["systemctl", "--failed", "--no-legend", "--plain"])
    if code != 0 or not output:
        return []
    return [line.split()[0] for line in output.splitlines() if line.split()]


def time_sync_status() -> str:
    if not shutil.which("timedatectl"):
        return "unavailable"
    _, output = run(["timedatectl", "show", "--property=NTPSynchronized", "--value"])
    return output.lower() if output else "unknown"


def network_snapshot() -> dict[str, Any]:
    code, route = run(["ip", "route", "show", "default"])
    if code != 0:
        route = "unavailable"
    resolvers: list[str] = []
    try:
        for line in Path("/etc/resolv.conf").read_text(encoding="utf-8").splitlines():
            if line.startswith("nameserver"):
                resolvers.append(line.split()[1])
    except OSError:
        pass
    return {"default_route": route, "resolvers": resolvers}


def top_processes() -> list[dict[str, str]]:
    if not shutil.which("ps"):
        return []
    code, output = run(["ps", "-eo", "pid,ppid,user,%cpu,%mem,comm", "--sort=-%cpu"])
    if code != 0:
        return []
    rows = []
    for line in output.splitlines()[1:11]:
        parts = line.split(None, 5)
        if len(parts) == 6:
            rows.append(dict(zip(["pid", "ppid", "user", "cpu_percent", "memory_percent", "command"], parts)))
    return rows


def journal_errors(max_lines: int) -> list[str]:
    if not shutil.which("journalctl"):
        return []
    code, output = run(["journalctl", "-p", "err..alert", "-n", str(max_lines), "--no-pager"])
    return output.splitlines() if code == 0 and output else []


def severity_weight(severity: str) -> int:
    return {"critical": 30, "warning": 12, "info": 0}.get(severity, 0)


def health_report(config: dict[str, Any]) -> dict[str, Any]:
    cpu_count = os.cpu_count() or 1
    load_average = os.getloadavg()[0] if hasattr(os, "getloadavg") else None
    memory = memory_snapshot()
    filesystems = filesystem_snapshot()
    failed = failed_services()
    findings: list[Finding] = []

    if load_average is not None and load_average / cpu_count >= config["load_per_cpu_warning"]:
        findings.append(Finding("warning", "cpu_load", "Load per CPU exceeds threshold.", {"load_1m": load_average, "cpu_count": cpu_count}))
    if memory and memory["used_percent"] >= config["memory_used_percent_warning"]:
        findings.append(Finding("warning", "memory", "Memory use exceeds threshold.", memory))
    for filesystem in filesystems:
        if filesystem["used_percent"] >= config["disk_used_percent_warning"]:
            findings.append(Finding("warning", "filesystem", "Filesystem use exceeds threshold.", filesystem))
    for service in failed:
        findings.append(Finding("critical", "systemd", "Service is in failed state.", {"service": service}))
    time_sync = time_sync_status()
    if time_sync != "yes":
        findings.append(Finding("warning", "time_sync", "System clock is not synchronized.", {"ntp_synchronized": time_sync}))

    score = max(0, 100 - sum(severity_weight(finding.severity) for finding in findings))
    return {
        "tool": {"name": "linux-self-healing-monitor", "version": __version__, "author": __author__},
        "timestamp_utc": utc_now(),
        "host": {"hostname": socket.gethostname(), "platform": platform.platform(), "kernel": platform.release()},
        "health_score": score,
        "metrics": {
            "cpu_count": cpu_count,
            "load_average_1m": load_average,
            "load_per_cpu": round(load_average / cpu_count, 2) if load_average is not None else None,
            "memory": memory,
            "filesystems": filesystems,
            "time_synchronized": time_sync,
            "network": network_snapshot(),
        },
        "failed_services": failed,
        "top_processes": top_processes(),
        "recent_journal_errors": journal_errors(int(config["max_journal_error_lines"])),
        "findings": [asdict(finding) for finding in findings],
    }


def recovery_allowed(service: str, state: dict[str, Any], cooldown: int) -> tuple[bool, str]:
    previous = state.get("restarts", {}).get(service)
    if not previous:
        return True, "no previous restart"
    try:
        previous_time = datetime.fromisoformat(previous)
    except ValueError:
        return True, "invalid previous timestamp"
    if datetime.now(UTC) - previous_time < timedelta(minutes=cooldown):
        return False, f"cooldown active until {(previous_time + timedelta(minutes=cooldown)).isoformat()}"
    return True, "cooldown expired"


def recover(report: dict[str, Any], config: dict[str, Any], state_path: Path) -> list[dict[str, Any]]:
    state = load_json(state_path, {"restarts": {}})
    allowed = set(config.get("restart_allowlist", []))
    cooldown = int(config["restart_cooldown_minutes"])
    actions: list[dict[str, Any]] = []
    for service in report["failed_services"]:
        if service not in allowed:
            actions.append({"service": service, "status": "skipped", "reason": "not in restart allowlist"})
            continue
        permitted, reason = recovery_allowed(service, state, cooldown)
        if not permitted:
            actions.append({"service": service, "status": "skipped", "reason": reason})
            continue
        code, output = run(["systemctl", "restart", service], timeout=45)
        validation_code, validation = run(["systemctl", "is-active", service])
        status = "restarted" if code == 0 and validation_code == 0 and validation == "active" else "failed"
        actions.append({"service": service, "status": status, "restart_output": output, "validation": validation})
        if status == "restarted":
            state.setdefault("restarts", {})[service] = utc_now()
    if actions:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    return actions


def markdown_report(report: dict[str, Any]) -> str:
    lines = [
        "# Linux Health Report",
        "",
        f"- **Host:** {report['host']['hostname']}",
        f"- **Collected (UTC):** {report['timestamp_utc']}",
        f"- **Health score:** {report['health_score']}/100",
        f"- **Author:** {report['tool']['author']}",
        "",
        "## Findings",
    ]
    if not report["findings"]:
        lines.append("No threshold violations or failed systemd services were found.")
    for finding in report["findings"]:
        lines.append(f"- **{finding['severity'].upper()}** - {finding['check']}: {finding['message']}")
    lines.extend(["", "## Top processes", "", "| PID | User | CPU % | Memory % | Command |", "| --- | --- | ---: | ---: | --- |"])
    for process in report["top_processes"]:
        lines.append(f"| {process['pid']} | {process['user']} | {process['cpu_percent']} | {process['memory_percent']} | {process['command']} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Linux monitoring, incident triage, and safe allowlisted recovery")
    parser.add_argument("--config", default="config.json", help="Path to JSON configuration")
    parser.add_argument("--report", help="Write the report to this file")
    parser.add_argument("--format", choices=["json", "markdown"], default="json", help="Report output format")
    parser.add_argument("--apply", action="store_true", help="Restart failed allowlisted services after safety checks")
    parser.add_argument("--state-file", default="/var/tmp/linux-self-healing-monitor-state.json", help="Path to restart cooldown state")
    args = parser.parse_args()

    config = load_json(Path(args.config), DEFAULT_CONFIG)
    report = health_report(config)
    report["mode"] = "apply" if args.apply else "observe_only"
    report["recovery_actions"] = recover(report, config, Path(args.state_file)) if args.apply else []
    rendered = markdown_report(report) if args.format == "markdown" else json.dumps(report, indent=2)
    print(rendered)
    if args.report:
        Path(args.report).write_text(rendered, encoding="utf-8")
    return 2 if report["findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
