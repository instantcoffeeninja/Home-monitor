"""Minimal webserver scaffold for Home Monitor dashboard."""

from datetime import datetime, timezone
from html import escape
from importlib.util import find_spec
import os
import sqlite3
import subprocess
import threading
import time
from urllib.parse import quote_plus

if find_spec("flask") is not None:
    from flask import Flask, abort, redirect, render_template, request, url_for
else:
    from lite_flask import Flask, abort, redirect, render_template, request, url_for

HOST = "0.0.0.0"
PORT = int(os.getenv("PORT", "8000"))
START_TIME_MONOTONIC = time.monotonic()
SERVER_RESTART_TIME = datetime.now(timezone.utc)
DB_PATH = os.getenv("DB_PATH", "home_monitor.db")
NETWORK_RANGE = os.getenv("NETWORK_RANGE", "192.168.0.0/24")
NMAP_BIN = os.getenv("NMAP_BIN", "nmap")
SCAN_INTERVAL_SECONDS = int(os.getenv("SCAN_INTERVAL_SECONDS", str(60 * 60)))
PING_INTERVAL_SECONDS = int(os.getenv("PING_INTERVAL_SECONDS", str(5 * 60)))
PING_BIN = os.getenv("PING_BIN", "ping")
AVAHI_RESOLVE_BIN = os.getenv("AVAHI_RESOLVE_BIN", "avahi-resolve")


_DB_LOCK = threading.Lock()


def format_uptime(total_seconds: int) -> str:
    """Formats uptime in HH:MM:SS."""

    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02}:{minutes:02}:{seconds:02}"


def format_restart_time(restart_time: datetime) -> str:
    """Formats restart time in a human-friendly UTC timestamp."""

    return restart_time.strftime("%d-%m-%Y %H:%M:%S UTC")


def init_db(db_path: str | None = None) -> None:
    """Ensures SQLite schema exists."""

    target_db_path = db_path or DB_PATH
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
            columns = {
                row[1]
                for row in conn.execute("PRAGMA table_info(nmap_results)").fetchall()
            }
            if "hostname" not in columns:
                conn.execute("ALTER TABLE nmap_results ADD COLUMN hostname TEXT")
            if "mac_address" not in columns:
                conn.execute("ALTER TABLE nmap_results ADD COLUMN mac_address TEXT")
            if "mac_vendor" not in columns:
                conn.execute("ALTER TABLE nmap_results ADD COLUMN mac_vendor TEXT")
            device_columns = {row[1] for row in conn.execute("PRAGMA table_info(devices)").fetchall()}
            if "mac_vendor" not in device_columns:
                conn.execute("ALTER TABLE devices ADD COLUMN mac_vendor TEXT")
            if "ping_enabled" not in device_columns:
                conn.execute("ALTER TABLE devices ADD COLUMN ping_enabled INTEGER NOT NULL DEFAULT 0")
            conn.commit()


def parse_nmap_grepable(output: str) -> list[tuple[str, str, str, str]]:
    """Parses nmap -oG output and returns active hosts as (ip, hostname, mac, vendor)."""

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
    network_range: str = NETWORK_RANGE, nmap_bin: str = NMAP_BIN
) -> list[tuple[str, str, str, str]]:
    """Runs nmap ping scan and returns active hosts."""

    command = [nmap_bin, "-sn", "-R", network_range, "-oG", "-"]
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    return parse_nmap_grepable(result.stdout)


def _normalize_hostname(hostname: str, ip: str) -> str:
    """Normalizes hostname; defaults to IP when hostname is blank."""

    clean_hostname = (hostname or "").strip()
    return clean_hostname if clean_hostname else ip


def resolve_hostname_with_avahi(ip: str, avahi_resolve_bin: str = AVAHI_RESOLVE_BIN) -> str:
    """Resolves hostname via avahi-resolve -a and returns blank when unavailable."""

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
    if "	" in output:
        return output.split("	", 1)[1].strip()
    if output and " " in output:
        return output.split(None, 1)[1].strip()
    return ""


def save_scan_results(hosts: list[tuple[str, str, str, str]], db_path: str | None = None) -> None:
    """Saves a scan result batch to sqlite."""

    target_db_path = db_path or DB_PATH
    scanned_at = datetime.now(timezone.utc).isoformat()
    init_db(target_db_path)
    with _DB_LOCK:
        with sqlite3.connect(target_db_path) as conn:
            conn.executemany(
                """
                INSERT INTO nmap_results (scanned_at, ip, hostname, mac_address, mac_vendor)
                VALUES (?, ?, ?, ?, ?)
                """,
                [(scanned_at, ip, hostname, mac_address, mac_vendor) for ip, hostname, mac_address, mac_vendor in hosts],
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
                    (ip, _normalize_hostname(preferred_hostname, ip), mac_address, mac_vendor),
                )
            conn.commit()


def get_ping_enabled_ips(db_path: str | None = None) -> set[str]:
    """Returns all IPs where ping monitoring is enabled."""

    target_db_path = db_path or DB_PATH
    init_db(target_db_path)
    with _DB_LOCK:
        with sqlite3.connect(target_db_path) as conn:
            rows = conn.execute(
                "SELECT ip FROM devices WHERE ping_enabled = 1 ORDER BY ip ASC"
            ).fetchall()
    return {ip for (ip,) in rows}


def ping_host(ip: str, ping_bin: str = PING_BIN) -> bool:
    """Returns True when one ICMP ping succeeds."""

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


def _record_ping_success(ip: str, db_path: str | None = None) -> None:
    """Persists a successful ping as a seen event."""

    target_db_path = db_path or DB_PATH
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
                (scanned_at, ip, _normalize_hostname(hostname, ip), mac_address, mac_vendor),
            )
            conn.commit()


def set_ping_enabled(ip: str, enabled: bool, db_path: str | None = None) -> None:
    """Stores ping-enabled flag per device and runs an immediate ping when enabled."""

    target_db_path = db_path or DB_PATH
    init_db(target_db_path)
    normalized_ip = ip.strip()
    if not normalized_ip:
        return

    with _DB_LOCK:
        with sqlite3.connect(target_db_path) as conn:
            conn.execute(
                """
                UPDATE devices
                SET ping_enabled = ?
                WHERE ip = ?
                """,
                (1 if enabled else 0, normalized_ip),
            )
            conn.commit()

    if enabled and ping_host(normalized_ip):
        _record_ping_success(normalized_ip, db_path=target_db_path)


def run_ping_checks(db_path: str | None = None) -> None:
    """Pings all selected devices and records successful responses."""

    target_db_path = db_path or DB_PATH
    for ip in get_ping_enabled_ips(db_path=target_db_path):
        if ping_host(ip):
            _record_ping_success(ip, db_path=target_db_path)


def ping_scheduler(stop_event: threading.Event, interval_seconds: int = PING_INTERVAL_SECONDS) -> None:
    """Runs ping checks every five minutes (configurable interval)."""

    while not stop_event.is_set():
        try:
            run_ping_checks()
        except sqlite3.Error as exc:
            print(f"SQLite error during ping checks: {exc}")
        stop_event.wait(interval_seconds)


def get_latest_scan_results(db_path: str | None = None) -> list[tuple[str, str, str]]:
    """Fetches latest known hostname and last seen per IP."""

    target_db_path = db_path or DB_PATH
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
                ORDER BY ip ASC
                """,
            ).fetchall()

    return [(ip, hostname, last_seen) for ip, hostname, last_seen in rows]


def scan_and_store(
    db_path: str | None = None,
    network_range: str = NETWORK_RANGE,
    nmap_bin: str = NMAP_BIN,
) -> list[tuple[str, str, str, str]]:
    """Runs scan and persists the results."""

    hosts = run_nmap_scan(network_range=network_range, nmap_bin=nmap_bin)
    save_scan_results(hosts, db_path=db_path or DB_PATH)
    return hosts


def scan_scheduler(stop_event: threading.Event, interval_seconds: int = SCAN_INTERVAL_SECONDS) -> None:
    """Runs nmap scan once an hour (configurable interval)."""

    while not stop_event.is_set():
        try:
            scan_and_store()
        except subprocess.CalledProcessError as exc:
            print(f"Nmap scan failed with exit code {exc.returncode}: {exc}")
        except FileNotFoundError:
            print("Nmap binary not found. Install nmap or set NMAP_BIN.")
        except sqlite3.Error as exc:
            print(f"SQLite error during scan: {exc}")

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
    """Maps a device timestamp to online/idle/offline status."""

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


def get_dashboard_rows(db_path: str | None = None) -> list[tuple[str, str, str, str, str, str]]:
    """Fetches host rows and assigns online/idle/offline status classes."""

    target_db_path = db_path or DB_PATH
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
    db_path: str | None = None, within_seconds: int = 5 * 60
) -> set[str]:
    """Returns IPs whose first seen timestamp is within the provided window."""

    target_db_path = db_path or DB_PATH
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
        if age_seconds < 0:
            continue

        if age_seconds <= within_seconds:
            recent_ips.add(ip)
    return recent_ips


def render_hosts_table(
    rows: list[tuple[str, str, str, str, str, str]],
    ping_enabled_ips: set[str] | None = None,
    newly_discovered_ips: set[str] | None = None,
) -> str:
    """Builds HTML table for hosts list."""

    if not rows:
        return "<p>Ingen nmap-resultater endnu.</p>"

    selected_ips = ping_enabled_ips or set()
    recent_ips = newly_discovered_ips or set()
    body_rows = "\n".join(
        (
            f"<tr{' class=\"new-device-row\"' if ip in recent_ips else ''}>"
            f"<td><form method=\"post\" action=\"/dashboard/ping-selection\"><input type=\"hidden\" name=\"ip\" value=\"{escape(ip)}\" /><input type=\"hidden\" name=\"ping_enabled\" value=\"0\" /><input type=\"checkbox\" name=\"ping_enabled\" value=\"1\" aria-label=\"Enable ping for {escape(ip)}\" {'checked' if ip in selected_ips else ''} onchange=\"this.form.submit()\" /></form></td>"
            f"<td>{escape(ip)}</td>"
            f"<td><span class=\"status-dot {status_class}\" aria-hidden=\"true\"></span>{_render_hostname_cell(hostname, ip)}{' <span class=\"new-device-badge\">New</span>' if ip in recent_ips else ''}{_render_vendor_detail(mac_vendor, mac_address)}</td>"
            f"<td>{_format_last_seen(last_seen)}</td>"
            "</tr>"
        )
        for ip, hostname, last_seen, status_class, mac_address, mac_vendor in rows
    )
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
    """Builds legend that explains dashboard status colors."""

    legend_items = [
        ("status-online", "Online", "Set for mindre end 60 sekunder siden."),
        ("status-idle", "Idle", "Set for mindre end 10 minutter siden."),
        ("status-offline", "Offline", "Ikke set de seneste 10 minutter."),
    ]
    legend_rows = "\n".join(
        (
            "<li>"
            f"<span class=\"legend-swatch {status_class}\" aria-hidden=\"true\"></span>"
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
    """Builds summary counts for total and each status bucket."""

    total_devices = len(rows)
    online_devices = sum(1 for _ip, _hn, _ls, status, _mac, _vendor in rows if status == "status-online")
    idle_devices = sum(1 for _ip, _hn, _ls, status, _mac, _vendor in rows if status == "status-idle")
    offline_devices = sum(1 for _ip, _hn, _ls, status, _mac, _vendor in rows if status == "status-offline")

    return (
        '<section class="summary-bar" aria-label="Device summary">'
        f"<span><strong>Total:</strong> {total_devices}</span>"
        f"<span><strong>Online:</strong> {online_devices}</span>"
        f"<span><strong>Idle:</strong> {idle_devices}</span>"
        f"<span><strong>Offline:</strong> {offline_devices}</span>"
        "</section>"
    )


def _render_hostname_cell(hostname: str, ip: str) -> str:
    """Renders hostname as history link when present."""

    clean_hostname = _normalize_hostname(hostname, ip)

    encoded_ip = quote_plus(ip)
    return (
        f"<a href=\"/history?ip={encoded_ip}\" "
        f"title=\"Vis historik for {escape(clean_hostname)}\">{escape(clean_hostname)}</a>"
    )


def _render_vendor_detail(mac_vendor: str, mac_address: str) -> str:
    """Renders vendor text next to hostname with MAC fallback when vendor is unknown."""

    if mac_vendor.strip():
        return f' <span class="vendor-label">({escape(mac_vendor.strip())})</span>'
    if mac_address.strip():
        return f' <span class="vendor-label">({escape(mac_address.strip())})</span>'
    return ""


def get_ip_history(ip: str, db_path: str | None = None) -> list[tuple[str, str, str, str]]:
    """Returns all saved rows for a specific IP."""

    target_db_path = db_path or DB_PATH
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

    return [(scanned_at, row_ip, row_hostname or "", row_mac or "") for scanned_at, row_ip, row_hostname, row_mac in rows]


def get_saved_hostname(ip: str, db_path: str | None = None) -> str:
    """Returns editable custom device name for one IP when MAC is known."""

    target_db_path = db_path or DB_PATH
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


def update_saved_hostname(ip: str, hostname: str, db_path: str | None = None) -> str:
    """Updates custom device name for IP MAC mapping and returns normalized hostname."""

    target_db_path = db_path or DB_PATH
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


def render_hostname_history_table(ip: str, saved_hostname: str, rows: list[tuple[str, str, str, str]]) -> str:
    """Builds HTML table with historical records for one IP."""

    escaped_ip = escape(ip)
    escaped_saved_hostname = escape(saved_hostname)
    if not rows:
        return f"<p>Ingen historik fundet for IP: <strong>{escaped_ip}</strong>.</p>"

    body_rows = "\n".join(
        (
            "<tr>"
            f"<td>{_format_last_seen(scanned_at)}</td>"
            f"<td>{escape(ip)}</td>"
            f"<td>{escape(_normalize_hostname(row_hostname, ip))}</td>"
            f"<td>{escape(row_mac or '-')}</td>"
            "</tr>"
        )
        for scanned_at, ip, row_hostname, row_mac in rows
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


app = Flask(__name__)


@app.route("/health")
def health() -> tuple[str, int, dict[str, str]]:
    uptime_seconds = int(time.monotonic() - START_TIME_MONOTONIC)
    body = f"OK\nUptime: {format_uptime(uptime_seconds)}"
    return body, 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.route("/")
@app.route("/dashboard")
def dashboard() -> str:
    restart_time = format_restart_time(SERVER_RESTART_TIME)
    rows = get_dashboard_rows()
    ping_enabled_ips = get_ping_enabled_ips()
    newly_discovered_ips = get_recently_discovered_ips()
    hosts_table = render_hosts_table(
        rows,
        ping_enabled_ips=ping_enabled_ips,
        newly_discovered_ips=newly_discovered_ips,
    )
    status_legend = render_status_legend()
    summary_bar = render_device_summary_bar(rows)
    return render_template(
        "index.html",
        restart_time=restart_time,
        hosts_table=hosts_table,
        status_legend=status_legend,
        summary_bar=summary_bar,
    )


@app.route("/history")
def history() -> str:
    selected_ip = request.args.get("ip", "").strip()
    if not selected_ip:
        abort(400, description="IP query parameter is required")

    history_rows = get_ip_history(selected_ip)
    saved_hostname = get_saved_hostname(selected_ip)
    history_table = render_hostname_history_table(selected_ip, saved_hostname, history_rows)
    return render_template("history.html", history_table=history_table)


@app.post("/history/update")
def update_history() -> tuple[str, int] | tuple[object, int]:
    ip = request.form.get("ip", "").strip()
    hostname = request.form.get("hostname", "")
    if not ip:
        abort(400, description="IP field is required")

    update_saved_hostname(ip, hostname)
    return redirect(url_for("history", ip=ip), code=303)


@app.post("/dashboard/ping-selection")
def update_ping_selection() -> tuple[str, int] | tuple[object, int]:
    ip = request.form.get("ip", "").strip()
    enabled = request.form.get("ping_enabled", "0") == "1"
    if not ip:
        abort(400, description="IP field is required")

    set_ping_enabled(ip, enabled)
    return redirect(url_for("dashboard"), code=303)


@app.post("/dashboard/scan")
def run_manual_scan() -> tuple[str, int] | tuple[object, int]:
    scan_and_store()
    return redirect(url_for("dashboard"), code=303)


def main() -> None:
    init_db()
    stop_event = threading.Event()
    scanner_thread = threading.Thread(target=scan_scheduler, args=(stop_event,), daemon=True)
    ping_thread = threading.Thread(target=ping_scheduler, args=(stop_event,), daemon=True)
    scanner_thread.start()
    ping_thread.start()

    print(f"Home Monitor kører på http://{HOST}:{PORT}")
    try:
        app.run(host=HOST, port=PORT)
    except KeyboardInterrupt:
        print("\nStopper server ...")
    finally:
        stop_event.set()


if __name__ == "__main__":
    main()
