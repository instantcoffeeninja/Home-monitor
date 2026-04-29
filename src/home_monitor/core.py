"""Core helpers for the Home Monitor dashboard."""

from __future__ import annotations

import ipaddress
import re
import sqlite3
import subprocess
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from urllib.parse import quote_plus

_ALLOWED_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-_")
DEFAULT_SCAN_NETWORK = "192.168.0.0/24"
DEFAULT_SCAN_INTERVAL_SECONDS = 60 * 60
DEFAULT_PING_INTERVAL_SECONDS = 5 * 60
DEFAULT_DEVICES_TABLE = "devices"
DEFAULT_NMAP_BIN = "nmap"
DEFAULT_PING_BIN = "ping"
DEFAULT_AVAHI_RESOLVE_BIN = "avahi-resolve"

_HOST_REPORT_RE = re.compile(r"^Nmap scan report for (.+)$")
_MAC_REPORT_RE = re.compile(r"^MAC Address: ([0-9A-Fa-f:]{17})(?: \((.+)\))?$")
_DB_LOCK = threading.Lock()


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


def format_uptime(total_seconds: int) -> str:
    """Format uptime in HH:MM:SS."""
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02}:{minutes:02}:{seconds:02}"


def format_restart_time(restart_time: datetime) -> str:
    """Format restart time in a human-friendly UTC timestamp."""
    return restart_time.strftime("%d-%m-%Y %H:%M:%S UTC")


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
    """Parse regular nmap -sn output into discovered device records."""
    devices: list[DiscoveredDevice] = []
    current_ip: str | None = None

    for line in output.splitlines():
        host_match = _HOST_REPORT_RE.match(line.strip())
        if host_match:
            host_name, current_ip = _extract_host_and_ip(host_match.group(1))
            if current_ip:
                devices.append(
                    DiscoveredDevice(
                        ip_address=current_ip,
                        host_name=host_name,
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


def parse_nmap_grepable(output: str) -> list[tuple[str, str, str, str]]:
    """Parse nmap -oG output and return active hosts as (ip, hostname, mac, vendor)."""
    hosts: list[tuple[str, str, str, str]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line.startswith("Host:") or "Status: Up" not in line:
            continue

        ip = ""
        hostname = ""

        try:
            host_part = line.split("Host:", 1)[1].split("Status:", 1)[0].strip()
            if " (" in host_part and host_part.endswith(")"):
                ip, hostname_in_paren = host_part[:-1].split(" (", 1)
                hostname = hostname_in_paren.strip()
            else:
                ip = host_part.split()[0]
        except (IndexError, ValueError):
            continue

        mac_address = ""
        mac_vendor = ""
        if "MAC Address:" in line:
            try:
                mac_part = line.split("MAC Address:", 1)[1].strip()
                mac_address = mac_part.split()[0]
                if " (" in mac_part and mac_part.endswith(")"):
                    mac_vendor = mac_part.split(" (", 1)[1][:-1].strip()
            except IndexError:
                mac_address = ""
                mac_vendor = ""

        if ip:
            hosts.append((ip, hostname, mac_address, mac_vendor))

    return hosts


def run_nmap_scan(
    scan_target: str = DEFAULT_SCAN_NETWORK,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    nmap_bin: str = DEFAULT_NMAP_BIN,
) -> list[DiscoveredDevice]:
    """Run an nmap ping sweep and parse discovered hosts."""
    normalized_target = _parse_scan_target(scan_target)
    proc = runner(
        [nmap_bin, "-sn", "-R", normalized_target, "-oG", "-"],
        check=True,
        capture_output=True,
        text=True,
    )
    hosts = parse_nmap_grepable(proc.stdout)
    if hosts:
        return [
            DiscoveredDevice(
                ip_address=ip,
                host_name=hostname or None,
                mac_address=mac_address or None,
                vendor=mac_vendor or None,
            )
            for ip, hostname, mac_address, mac_vendor in hosts
        ]
    return parse_nmap_output(proc.stdout)


def init_db(db_path: str | Path = "home_monitor.db") -> None:
    """Ensure SQLite schema exists and migrate known older layouts."""
    target_db_path = str(db_path)
    with _DB_LOCK:
        with sqlite3.connect(target_db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS nmap_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scanned_at TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    hostname TEXT,
                    mac_address TEXT,
                    mac_vendor TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    ip TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL,
                    mac_address TEXT,
                    mac_vendor TEXT,
                    ping_enabled INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS device_name_overrides (
                    mac_address TEXT PRIMARY KEY,
                    custom_name TEXT NOT NULL
                )
                """
            )
            _ensure_columns(
                conn,
                "nmap_results",
                {"hostname": "TEXT", "mac_address": "TEXT", "mac_vendor": "TEXT"},
            )
            _ensure_columns(
                conn,
                "devices",
                {
                    "ip": "TEXT",
                    "hostname": "TEXT",
                    "mac_address": "TEXT",
                    "mac_vendor": "TEXT",
                    "ping_enabled": "INTEGER NOT NULL DEFAULT 0",
                },
            )
            device_columns = _table_columns(conn, "devices")
            if "ip_address" in device_columns:
                conn.execute("UPDATE devices SET ip = COALESCE(ip, ip_address)")
            if "host_name" in device_columns:
                conn.execute(
                    "UPDATE devices SET hostname = COALESCE(NULLIF(hostname, ''), host_name, ip)"
                )
            if "vendor" in device_columns:
                conn.execute(
                    "UPDATE devices SET mac_vendor = COALESCE(mac_vendor, vendor)"
                )
            conn.execute(
                "UPDATE devices SET hostname = COALESCE(NULLIF(hostname, ''), ip)"
            )
            conn.commit()


def _table_columns(conn: sqlite3.Connection, table_name: str) -> set[str]:
    return {
        row[1] for row in conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    }


def _ensure_columns(
    conn: sqlite3.Connection, table_name: str, columns: dict[str, str]
) -> None:
    existing = _table_columns(conn, table_name)
    for column_name, column_type in columns.items():
        if column_name not in existing:
            conn.execute(
                f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"
            )


def _normalize_hostname(hostname: str | None, ip: str) -> str:
    clean_hostname = (hostname or "").strip()
    return clean_hostname if clean_hostname else ip


def resolve_hostname_with_avahi(
    ip: str, avahi_resolve_bin: str = DEFAULT_AVAHI_RESOLVE_BIN
) -> str:
    """Resolve hostname via avahi-resolve -a and return blank when unavailable."""
    try:
        result = subprocess.run(
            [avahi_resolve_bin, "-a", ip],
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""

    output = (result.stdout or "").strip()
    if "\t" in output:
        return output.split("\t", 1)[1].strip()
    if output and " " in output:
        return output.split(None, 1)[1].strip()
    return ""


def save_scan_results(
    hosts: list[tuple[str, str, str, str]], db_path: str | Path = "home_monitor.db"
) -> None:
    """Save a scan result batch to SQLite."""
    target_db_path = str(db_path)
    scanned_at = datetime.now(timezone.utc).isoformat()
    init_db(target_db_path)
    with _DB_LOCK:
        with sqlite3.connect(target_db_path) as conn:
            conn.executemany(
                """
                INSERT INTO nmap_results (scanned_at, ip, hostname, mac_address, mac_vendor)
                VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (scanned_at, ip, hostname, mac_address, mac_vendor)
                    for ip, hostname, mac_address, mac_vendor in hosts
                ],
            )
            for ip, hostname, mac_address, mac_vendor in hosts:
                resolved_hostname = resolve_hostname_with_avahi(ip)
                preferred_hostname = resolved_hostname or hostname
                conn.execute(
                    """
                    INSERT INTO devices (ip, hostname, mac_address, mac_vendor)
                    VALUES (?, ?, NULLIF(?, ''), NULLIF(?, ''))
                    ON CONFLICT(ip) DO UPDATE SET
                      hostname = CASE
                        WHEN excluded.hostname IS NOT NULL AND excluded.hostname <> excluded.ip THEN excluded.hostname
                        ELSE devices.hostname
                      END,
                      mac_address = COALESCE(NULLIF(excluded.mac_address, ''), devices.mac_address),
                      mac_vendor = COALESCE(NULLIF(excluded.mac_vendor, ''), devices.mac_vendor)
                    """,
                    (
                        ip,
                        _normalize_hostname(preferred_hostname, ip),
                        mac_address,
                        mac_vendor,
                    ),
                )
            conn.commit()


def persist_scan_results(
    devices: list[DiscoveredDevice],
    db_path: Path,
    table_name: str = DEFAULT_DEVICES_TABLE,
    now: datetime | None = None,
) -> int:
    """Compatibility wrapper that persists discovered devices into the dashboard schema."""
    del table_name, now
    save_scan_results(
        [
            (
                device.ip_address,
                device.host_name or "",
                device.mac_address or "",
                device.vendor or "",
            )
            for device in devices
        ],
        db_path=db_path,
    )
    return len(devices)


def get_ping_enabled_ips(db_path: str | Path = "home_monitor.db") -> set[str]:
    """Return all IPs where ping monitoring is enabled."""
    target_db_path = str(db_path)
    init_db(target_db_path)
    with _DB_LOCK:
        with sqlite3.connect(target_db_path) as conn:
            rows = conn.execute(
                "SELECT ip FROM devices WHERE ping_enabled = 1 ORDER BY ip ASC"
            ).fetchall()
    return {ip for (ip,) in rows}


def ping_host(ip: str, ping_bin: str = DEFAULT_PING_BIN) -> bool:
    """Return True when one ICMP ping succeeds."""
    try:
        subprocess.run(
            [ping_bin, "-c", "1", "-W", "1", ip],
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False
    return True


def _record_ping_success(ip: str, db_path: str | Path = "home_monitor.db") -> None:
    target_db_path = str(db_path)
    scanned_at = datetime.now(timezone.utc).isoformat()
    with _DB_LOCK:
        with sqlite3.connect(target_db_path) as conn:
            row = conn.execute(
                """
                SELECT COALESCE(hostname, ip), COALESCE(mac_address, ''), COALESCE(mac_vendor, '')
                FROM devices
                WHERE ip = ?
                LIMIT 1
                """,
                (ip,),
            ).fetchone()
            if not row:
                return
            hostname, mac_address, mac_vendor = row
            conn.execute(
                """
                INSERT INTO nmap_results (scanned_at, ip, hostname, mac_address, mac_vendor)
                VALUES (?, ?, ?, NULLIF(?, ''), NULLIF(?, ''))
                """,
                (
                    scanned_at,
                    ip,
                    _normalize_hostname(hostname, ip),
                    mac_address,
                    mac_vendor,
                ),
            )
            conn.commit()


def set_ping_enabled(
    ip: str, enabled: bool, db_path: str | Path = "home_monitor.db"
) -> None:
    """Store ping-enabled flag per device and run an immediate ping when enabled."""
    target_db_path = str(db_path)
    init_db(target_db_path)
    normalized_ip = ip.strip()
    if not normalized_ip:
        return

    with _DB_LOCK:
        with sqlite3.connect(target_db_path) as conn:
            conn.execute(
                "UPDATE devices SET ping_enabled = ? WHERE ip = ?",
                (1 if enabled else 0, normalized_ip),
            )
            conn.commit()

    if enabled and ping_host(normalized_ip):
        _record_ping_success(normalized_ip, db_path=target_db_path)


def run_ping_checks(db_path: str | Path = "home_monitor.db") -> None:
    """Ping all selected devices and record successful responses."""
    target_db_path = str(db_path)
    for ip in get_ping_enabled_ips(db_path=target_db_path):
        if ping_host(ip):
            _record_ping_success(ip, db_path=target_db_path)


def get_latest_scan_results(
    db_path: str | Path = "home_monitor.db",
) -> list[tuple[str, str, str]]:
    """Fetch latest known hostname and last seen per IP."""
    target_db_path = str(db_path)
    init_db(target_db_path)
    with _DB_LOCK:
        with sqlite3.connect(target_db_path) as conn:
            row = conn.execute("SELECT COUNT(*) FROM nmap_results").fetchone()
            if not row or row[0] == 0:
                return []

            rows = conn.execute(
                """
                SELECT latest.ip,
                       COALESCE(d.hostname, latest.ip) AS hostname,
                       latest.last_seen
                FROM (
                    SELECT ip, MAX(scanned_at) AS last_seen
                    FROM nmap_results
                    GROUP BY ip
                ) AS latest
                LEFT JOIN devices d ON d.ip = latest.ip
                ORDER BY latest.ip ASC
                """
            ).fetchall()

    return [(ip, hostname, last_seen) for ip, hostname, last_seen in rows]


def scan_and_store(
    db_path: str | Path = "home_monitor.db",
    network_range: str = DEFAULT_SCAN_NETWORK,
    nmap_bin: str = DEFAULT_NMAP_BIN,
) -> list[tuple[str, str, str, str]]:
    """Run scan and persist the results."""
    devices = run_nmap_scan(scan_target=network_range, nmap_bin=nmap_bin)
    hosts = [
        (
            device.ip_address,
            device.host_name or "",
            device.mac_address or "",
            device.vendor or "",
        )
        for device in devices
    ]
    save_scan_results(hosts, db_path=db_path)
    return hosts


def scan_scheduler(
    stop_event: threading.Event,
    db_path: str | Path = "home_monitor.db",
    network_range: str = DEFAULT_SCAN_NETWORK,
    nmap_bin: str = DEFAULT_NMAP_BIN,
    interval_seconds: int = DEFAULT_SCAN_INTERVAL_SECONDS,
) -> None:
    """Run nmap scans on an interval."""
    while not stop_event.is_set():
        try:
            scan_and_store(
                db_path=db_path, network_range=network_range, nmap_bin=nmap_bin
            )
        except subprocess.CalledProcessError as exc:
            print(f"Nmap scan failed with exit code {exc.returncode}: {exc}")
        except FileNotFoundError:
            print("Nmap binary not found. Install nmap or set NMAP_BIN.")
        except sqlite3.Error as exc:
            print(f"SQLite error during scan: {exc}")

        stop_event.wait(interval_seconds)


def ping_scheduler(
    stop_event: threading.Event,
    db_path: str | Path = "home_monitor.db",
    interval_seconds: int = DEFAULT_PING_INTERVAL_SECONDS,
) -> None:
    """Run ping checks on an interval."""
    while not stop_event.is_set():
        try:
            run_ping_checks(db_path=db_path)
        except sqlite3.Error as exc:
            print(f"SQLite error during ping checks: {exc}")
        stop_event.wait(interval_seconds)


def _format_last_seen(last_seen: str, now: datetime | None = None) -> str:
    """Format ISO timestamp as relative, human-readable last seen time."""
    try:
        parsed = datetime.fromisoformat(last_seen)
    except ValueError:
        return escape(last_seen)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)

    current_time = now or datetime.now(timezone.utc)
    if current_time.tzinfo is None:
        current_time = current_time.replace(tzinfo=timezone.utc)
    else:
        current_time = current_time.astimezone(timezone.utc)

    seconds_since_seen = max(0, int((current_time - parsed).total_seconds()))
    if seconds_since_seen < 60:
        return "online now"

    minutes_since_seen = seconds_since_seen // 60
    if minutes_since_seen < 60:
        unit = "minute" if minutes_since_seen == 1 else "minutes"
        return f"{minutes_since_seen} {unit} ago"

    hours_since_seen = minutes_since_seen // 60
    unit = "hour" if hours_since_seen == 1 else "hours"
    return f"{hours_since_seen} {unit} ago"


def _status_class_for_last_seen(last_seen: str, now: datetime | None = None) -> str:
    """Map a device timestamp to online/idle/offline status."""
    try:
        parsed = datetime.fromisoformat(last_seen)
    except ValueError:
        return "status-offline"

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)

    current_time = now or datetime.now(timezone.utc)
    if current_time.tzinfo is None:
        current_time = current_time.replace(tzinfo=timezone.utc)
    else:
        current_time = current_time.astimezone(timezone.utc)

    seconds_since_seen = max(0, int((current_time - parsed).total_seconds()))
    if seconds_since_seen < 60:
        return "status-online"
    if seconds_since_seen < 10 * 60:
        return "status-idle"
    return "status-offline"


def get_dashboard_rows(
    db_path: str | Path = "home_monitor.db",
) -> list[tuple[str, str, str, str, str, str]]:
    """Fetch host rows and assign online/idle/offline status classes."""
    target_db_path = str(db_path)
    init_db(target_db_path)
    with _DB_LOCK:
        with sqlite3.connect(target_db_path) as conn:
            host_rows = conn.execute(
                """
                SELECT latest.ip,
                       COALESCE(o.custom_name, d.hostname, latest.ip) AS hostname,
                       latest.last_seen,
                       COALESCE(d.mac_address, '') AS mac_address,
                       COALESCE(d.mac_vendor, '') AS mac_vendor
                FROM (
                    SELECT ip, MAX(scanned_at) AS last_seen
                    FROM nmap_results
                    GROUP BY ip
                ) AS latest
                LEFT JOIN devices d ON d.ip = latest.ip
                LEFT JOIN device_name_overrides o ON o.mac_address = d.mac_address
                ORDER BY latest.ip ASC
                """
            ).fetchall()

    return [
        (
            ip,
            _normalize_hostname(hostname, ip),
            last_seen,
            _status_class_for_last_seen(last_seen),
            mac_address,
            mac_vendor,
        )
        for ip, hostname, last_seen, mac_address, mac_vendor in host_rows
    ]


def get_recently_discovered_ips(
    db_path: str | Path = "home_monitor.db", within_seconds: int = 5 * 60
) -> set[str]:
    """Return IPs whose first seen timestamp is within the provided window."""
    target_db_path = str(db_path)
    init_db(target_db_path)
    if within_seconds < 0:
        return set()

    current_time = datetime.now(timezone.utc)
    with _DB_LOCK:
        with sqlite3.connect(target_db_path) as conn:
            rows = conn.execute(
                """
                SELECT ip, MIN(scanned_at) AS first_seen
                FROM nmap_results
                GROUP BY ip
                """
            ).fetchall()

    recent_ips: set[str] = set()
    for ip, first_seen in rows:
        try:
            parsed = datetime.fromisoformat(first_seen)
        except (TypeError, ValueError):
            continue

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        else:
            parsed = parsed.astimezone(timezone.utc)

        age_seconds = (current_time - parsed).total_seconds()
        if 0 <= age_seconds <= within_seconds:
            recent_ips.add(ip)
    return recent_ips


def render_hosts_table(
    rows: list[tuple[str, str, str, str, str, str]],
    ping_enabled_ips: set[str] | None = None,
    newly_discovered_ips: set[str] | None = None,
) -> str:
    """Build HTML table for hosts list."""
    if not rows:
        return "<p>Ingen nmap-resultater endnu.</p>"

    selected_ips = ping_enabled_ips or set()
    recent_ips = newly_discovered_ips or set()
    rendered_rows = []
    for ip, hostname, last_seen, status_class, mac_address, mac_vendor in rows:
        row_class = ' class="new-device-row"' if ip in recent_ips else ""
        checked = "checked" if ip in selected_ips else ""
        new_badge = (
            ' <span class="new-device-badge">New</span>' if ip in recent_ips else ""
        )
        rendered_rows.append(
            f"<tr{row_class}>"
            f'<td><form method="post" action="/dashboard/ping-selection"><input type="hidden" name="ip" value="{escape(ip)}" /><input type="hidden" name="ping_enabled" value="0" /><input type="checkbox" name="ping_enabled" value="1" aria-label="Enable ping for {escape(ip)}" {checked} onchange="this.form.submit()" /></form></td>'
            f"<td>{escape(ip)}</td>"
            f'<td><span class="status-dot {status_class}" aria-hidden="true"></span>{_render_hostname_cell(hostname, ip)}{new_badge}{_render_vendor_detail(mac_vendor, mac_address)}</td>'
            f"<td>{_format_last_seen(last_seen)}</td>"
            "</tr>"
        )
    body_rows = "\n".join(rendered_rows)
    return f"""
    <table>
      <thead>
        <tr><th>Ping</th><th>IP</th><th>Hostname</th><th>Sidst fundet</th></tr>
      </thead>
      <tbody>
        {body_rows}
      </tbody>
    </table>
    """


def render_status_legend() -> str:
    """Build legend that explains dashboard status colors."""
    legend_items = [
        ("status-online", "Online", "Set for mindre end 60 sekunder siden."),
        ("status-idle", "Idle", "Set for mindre end 10 minutter siden."),
        ("status-offline", "Offline", "Ikke set de seneste 10 minutter."),
    ]
    legend_rows = "\n".join(
        (
            "<li>"
            f'<span class="legend-swatch {status_class}" aria-hidden="true"></span>'
            f"<span><strong>{label}:</strong> {description}</span>"
            "</li>"
        )
        for status_class, label, description in legend_items
    )
    return f"""
    <aside class="status-legend" aria-label="Farveforklaring for status">
      <h3>Farveforklaring</h3>
      <ul>
        {legend_rows}
      </ul>
    </aside>
    """


def render_device_summary_bar(rows: list[tuple[str, str, str, str, str, str]]) -> str:
    """Build summary counts for total and each status bucket."""
    total_devices = len(rows)
    online_devices = sum(
        1 for _ip, _hn, _ls, status, _mac, _vendor in rows if status == "status-online"
    )
    idle_devices = sum(
        1 for _ip, _hn, _ls, status, _mac, _vendor in rows if status == "status-idle"
    )
    offline_devices = sum(
        1 for _ip, _hn, _ls, status, _mac, _vendor in rows if status == "status-offline"
    )

    return (
        '<section class="summary-bar" aria-label="Device summary">'
        f"<span><strong>Total:</strong> {total_devices}</span>"
        f"<span><strong>Online:</strong> {online_devices}</span>"
        f"<span><strong>Idle:</strong> {idle_devices}</span>"
        f"<span><strong>Offline:</strong> {offline_devices}</span>"
        "</section>"
    )


def _render_hostname_cell(hostname: str, ip: str) -> str:
    clean_hostname = _normalize_hostname(hostname, ip)
    encoded_ip = quote_plus(ip)
    return (
        f'<a href="/history?ip={encoded_ip}" '
        f'title="Vis historik for {escape(clean_hostname)}">{escape(clean_hostname)}</a>'
    )


def _render_vendor_detail(mac_vendor: str, mac_address: str) -> str:
    if mac_vendor.strip():
        return f' <span class="vendor-label">({escape(mac_vendor.strip())})</span>'
    if mac_address.strip():
        return f' <span class="vendor-label">({escape(mac_address.strip())})</span>'
    return ""


def get_ip_history(
    ip: str, db_path: str | Path = "home_monitor.db"
) -> list[tuple[str, str, str, str]]:
    """Return all saved rows for a specific IP."""
    target_db_path = str(db_path)
    init_db(target_db_path)
    with _DB_LOCK:
        with sqlite3.connect(target_db_path) as conn:
            rows = conn.execute(
                """
                SELECT scanned_at, ip, hostname, COALESCE(mac_address, '')
                FROM nmap_results
                WHERE ip = ?
                ORDER BY scanned_at DESC, id DESC
                """,
                (ip,),
            ).fetchall()

    return [
        (scanned_at, row_ip, row_hostname or "", row_mac or "")
        for scanned_at, row_ip, row_hostname, row_mac in rows
    ]


def get_saved_hostname(ip: str, db_path: str | Path = "home_monitor.db") -> str:
    """Return editable custom device name for one IP when MAC is known."""
    target_db_path = str(db_path)
    init_db(target_db_path)
    with _DB_LOCK:
        with sqlite3.connect(target_db_path) as conn:
            row = conn.execute(
                """
                SELECT COALESCE(o.custom_name, d.hostname, d.ip), COALESCE(d.mac_address, '')
                FROM devices d
                LEFT JOIN device_name_overrides o ON o.mac_address = d.mac_address
                WHERE d.ip = ?
                LIMIT 1
                """,
                (ip,),
            ).fetchone()

    if not row:
        return ip
    return _normalize_hostname(row[0], ip)


def update_saved_hostname(
    ip: str, hostname: str, db_path: str | Path = "home_monitor.db"
) -> str:
    """Update custom device name for IP/MAC mapping and return normalized hostname."""
    target_db_path = str(db_path)
    normalized_hostname = _normalize_hostname(hostname, ip)
    init_db(target_db_path)
    with _DB_LOCK:
        with sqlite3.connect(target_db_path) as conn:
            mac_row = conn.execute(
                "SELECT COALESCE(mac_address, '') FROM devices WHERE ip = ? LIMIT 1",
                (ip,),
            ).fetchone()
            mac_address = (mac_row[0] if mac_row else "").strip()

            if mac_address:
                conn.execute(
                    """
                    INSERT INTO device_name_overrides (mac_address, custom_name)
                    VALUES (?, ?)
                    ON CONFLICT(mac_address) DO UPDATE SET custom_name = excluded.custom_name
                    """,
                    (mac_address, normalized_hostname),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO devices (ip, hostname, mac_address)
                    VALUES (?, ?, NULL)
                    ON CONFLICT(ip) DO UPDATE SET hostname = excluded.hostname
                    """,
                    (ip, normalized_hostname),
                )
            conn.commit()
    return normalized_hostname


def render_hostname_history_table(
    ip: str, saved_hostname: str, rows: list[tuple[str, str, str, str]]
) -> str:
    """Build HTML table with historical records for one IP."""
    escaped_ip = escape(ip)
    escaped_saved_hostname = escape(saved_hostname)
    if not rows:
        return f"<p>Ingen historik fundet for IP: <strong>{escaped_ip}</strong>.</p>"

    body_rows = "\n".join(
        (
            "<tr>"
            f"<td>{_format_last_seen(scanned_at)}</td>"
            f"<td>{escape(row_ip)}</td>"
            f"<td>{escape(_normalize_hostname(row_hostname, row_ip))}</td>"
            f"<td>{escape(row_mac or '-')}</td>"
            "</tr>"
        )
        for scanned_at, row_ip, row_hostname, row_mac in rows
    )
    return f"""
    <h2>Historik for IP: {escaped_ip}</h2>
    <form method="post" action="/history/update">
      <input type="hidden" name="ip" value="{escaped_ip}" />
      <label for="hostname"><strong>Enhedsnavn (brugerdefineret):</strong></label>
      <input id="hostname" name="hostname" value="{escaped_saved_hostname}" />
      <button type="submit">Gem enhedsnavn</button>
    </form>
    <p><a href="/dashboard">Luk historik og gå tilbage</a></p>
    <table>
      <thead>
        <tr><th>Scannet</th><th>IP</th><th>Hostname (scan)</th><th>MAC adresse</th></tr>
      </thead>
      <tbody>
        {body_rows}
      </tbody>
    </table>
    """


class NetworkScanWorker:
    """Background worker that periodically runs nmap and stores device data."""

    def __init__(
        self,
        db_path: Path,
        scan_target: str = DEFAULT_SCAN_NETWORK,
        interval_seconds: int = DEFAULT_SCAN_INTERVAL_SECONDS,
        table_name: str = DEFAULT_DEVICES_TABLE,
    ) -> None:
        del table_name
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be greater than zero")

        self._db_path = db_path
        self._scan_target = _parse_scan_target(scan_target)
        self._interval_seconds = interval_seconds
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
            try:
                self.run_scan_once()
            except subprocess.CalledProcessError as exc:
                print(f"Nmap scan failed with exit code {exc.returncode}: {exc}")
            except FileNotFoundError:
                print("Nmap binary not found. Install nmap or set NMAP_BIN.")
            except sqlite3.Error as exc:
                print(f"SQLite error during scan: {exc}")
            self._stop_event.wait(self._interval_seconds)

    def run_scan_once(self) -> int:
        devices = run_nmap_scan(self._scan_target)
        return persist_scan_results(devices, db_path=self._db_path)
