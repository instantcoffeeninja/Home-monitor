"""Core helpers for Home Monitor baseline."""

from __future__ import annotations

import ipaddress
import re
import sqlite3
import subprocess
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

_ALLOWED_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-_")
DEFAULT_SCAN_NETWORK = "192.168.0.1/24"
DEFAULT_SCAN_INTERVAL_SECONDS = 300
DEFAULT_DEVICES_TABLE = "devices"

_HOST_REPORT_RE = re.compile(r"^Nmap scan report for (.+)$")
_MAC_REPORT_RE = re.compile(r"^MAC Address: ([0-9A-Fa-f:]{17})(?: \((.+)\))?$")


@dataclass(frozen=True)
class DiscoveredDevice:
    """A single discovered device from an nmap host sweep."""

    ip_address: str
    host_name: str | None
    mac_address: str | None
    vendor: str | None


def normalize_device_name(raw_name: str) -> str:
    """Return a safe lowercase device name using only [a-z0-9_-]."""
    if not isinstance(raw_name, str):
        raise TypeError("raw_name must be a string")

    lowered = raw_name.strip().lower().replace(" ", "-")
    sanitized = "".join(ch for ch in lowered if ch in _ALLOWED_CHARS)

    if not sanitized:
        raise ValueError("device name is empty after normalization")

    return sanitized


def summarize_status(device_name: str, is_online: bool) -> dict[str, str]:
    """Build a deterministic status payload for a device."""
    normalized = normalize_device_name(device_name)
    return {
        "device": normalized,
        "status": "online" if is_online else "offline",
    }


def _parse_scan_target(scan_target: str) -> str:
    try:
        network = ipaddress.ip_network(scan_target, strict=False)
    except ValueError as exc:
        raise ValueError(
            "scan_target must be a valid network, e.g. 192.168.0.1/24"
        ) from exc
    return str(network)


def _extract_host_and_ip(raw_target: str) -> tuple[str | None, str]:
    if raw_target.endswith(")") and "(" in raw_target:
        host, ip_part = raw_target.rsplit("(", maxsplit=1)
        return host.strip(), ip_part[:-1].strip()
    return None, raw_target.strip()


def parse_nmap_output(output: str) -> list[DiscoveredDevice]:
    """Parse nmap -sn output into discovered device records."""
    devices: list[DiscoveredDevice] = []
    current_host_name: str | None = None
    current_ip: str | None = None

    for line in output.splitlines():
        host_match = _HOST_REPORT_RE.match(line.strip())
        if host_match:
            current_host_name, current_ip = _extract_host_and_ip(host_match.group(1))
            if current_ip:
                devices.append(
                    DiscoveredDevice(
                        ip_address=current_ip,
                        host_name=current_host_name,
                        mac_address=None,
                        vendor=None,
                    )
                )
            continue

        mac_match = _MAC_REPORT_RE.match(line.strip())
        if mac_match and devices and current_ip:
            latest = devices[-1]
            devices[-1] = DiscoveredDevice(
                ip_address=latest.ip_address,
                host_name=latest.host_name,
                mac_address=mac_match.group(1).upper(),
                vendor=mac_match.group(2),
            )

    return devices


def run_nmap_scan(
    scan_target: str = DEFAULT_SCAN_NETWORK,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> list[DiscoveredDevice]:
    """Run an nmap ping sweep and parse discovered hosts."""
    normalized_target = _parse_scan_target(scan_target)
    proc = runner(
        ["nmap", "-sn", normalized_target],
        check=True,
        capture_output=True,
        text=True,
    )
    return parse_nmap_output(proc.stdout)


def ensure_devices_table(
    db_path: Path, table_name: str = DEFAULT_DEVICES_TABLE
) -> None:
    """Ensure the legacy devices table exists before scan writes."""
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {table_name} (
                ip_address TEXT PRIMARY KEY,
                host_name TEXT,
                mac_address TEXT,
                vendor TEXT,
                last_seen TEXT NOT NULL
            )
            """
        )
        conn.commit()


def persist_scan_results(
    devices: list[DiscoveredDevice],
    db_path: Path,
    table_name: str = DEFAULT_DEVICES_TABLE,
    now: datetime | None = None,
) -> int:
    """Upsert discovered devices into the existing devices table."""
    ensure_devices_table(db_path=db_path, table_name=table_name)
    seen_at = (now or datetime.now(UTC)).isoformat()

    with sqlite3.connect(db_path) as conn:
        conn.executemany(
            f"""
            INSERT INTO {table_name} (ip_address, host_name, mac_address, vendor, last_seen)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(ip_address) DO UPDATE SET
                host_name=excluded.host_name,
                mac_address=excluded.mac_address,
                vendor=excluded.vendor,
                last_seen=excluded.last_seen
            """,
            [
                (
                    device.ip_address,
                    device.host_name,
                    device.mac_address,
                    device.vendor,
                    seen_at,
                )
                for device in devices
            ],
        )
        conn.commit()

    return len(devices)


class NetworkScanWorker:
    """Background worker that periodically runs nmap and stores device data."""

    def __init__(
        self,
        db_path: Path,
        scan_target: str = DEFAULT_SCAN_NETWORK,
        interval_seconds: int = DEFAULT_SCAN_INTERVAL_SECONDS,
        table_name: str = DEFAULT_DEVICES_TABLE,
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be greater than zero")

        self._db_path = db_path
        self._scan_target = _parse_scan_target(scan_target)
        self._interval_seconds = interval_seconds
        self._table_name = table_name
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="network-scan-worker"
        )
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            self.run_scan_once()
            self._stop_event.wait(self._interval_seconds)

    def run_scan_once(self) -> int:
        devices = run_nmap_scan(self._scan_target)
        return persist_scan_results(
            devices, db_path=self._db_path, table_name=self._table_name
        )
