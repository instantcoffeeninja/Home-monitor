"""Minimal webserver scaffold for Home Monitor dashboard."""

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timezone
from html import escape
import os
import sqlite3
import subprocess
import threading
import time
from urllib.parse import parse_qs, quote_plus, urlparse

HOST = "0.0.0.0"
PORT = int(os.getenv("PORT", "8000"))
START_TIME_MONOTONIC = time.monotonic()
SERVER_RESTART_TIME = datetime.now(timezone.utc)
DB_PATH = os.getenv("DB_PATH", "home_monitor.db")
NETWORK_RANGE = os.getenv("NETWORK_RANGE", "192.168.0.0/24")
NMAP_BIN = os.getenv("NMAP_BIN", "nmap")
SCAN_INTERVAL_SECONDS = int(os.getenv("SCAN_INTERVAL_SECONDS", str(60 * 60)))


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
                    mac_address TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    ip TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL,
                    mac_address TEXT
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
            conn.commit()


def parse_nmap_grepable(output: str) -> list[tuple[str, str, str]]:
    """Parses nmap -oG output and returns active hosts as (ip, hostname, mac)."""

    hosts: list[tuple[str, str, str]] = []
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
        if "MAC Address:" in line:
            try:
                mac_part = line.split("MAC Address:", 1)[1].strip()
                mac_address = mac_part.split()[0]
            except IndexError:
                mac_address = ""

        if ip:
            hosts.append((ip, hostname, mac_address))

    return hosts


def run_nmap_scan(
    network_range: str = NETWORK_RANGE, nmap_bin: str = NMAP_BIN
) -> list[tuple[str, str, str]]:
    """Runs nmap ping scan and returns active hosts."""

    command = [nmap_bin, "-sn", "-R", network_range, "-oG", "-"]
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    return parse_nmap_grepable(result.stdout)


def _normalize_hostname(hostname: str, ip: str) -> str:
    """Normalizes hostname; defaults to IP when hostname is blank."""

    clean_hostname = (hostname or "").strip()
    return clean_hostname if clean_hostname else ip


def save_scan_results(hosts: list[tuple[str, str, str]], db_path: str | None = None) -> None:
    """Saves a scan result batch to sqlite."""

    target_db_path = db_path or DB_PATH
    scanned_at = datetime.now(timezone.utc).isoformat()
    init_db(target_db_path)
    with _DB_LOCK:
        with sqlite3.connect(target_db_path) as conn:
            conn.executemany(
                "INSERT INTO nmap_results (scanned_at, ip, hostname, mac_address) VALUES (?, ?, ?, ?)",
                [(scanned_at, ip, hostname, mac_address) for ip, hostname, mac_address in hosts],
            )
            for ip, hostname, mac_address in hosts:
                conn.execute(
                    """
                    INSERT INTO devices (ip, hostname, mac_address)
                    VALUES (?, ?, NULLIF(?, ''))
                    ON CONFLICT(ip) DO UPDATE SET
                      mac_address = COALESCE(NULLIF(excluded.mac_address, ''), devices.mac_address)
                    """,
                    (ip, _normalize_hostname(hostname, ip), mac_address),
                )
            conn.commit()


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
) -> list[tuple[str, str, str]]:
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


def get_dashboard_rows(db_path: str | None = None) -> list[tuple[str, str, str, str]]:
    """Fetches host rows and assigns dashboard color status classes."""

    target_db_path = db_path or DB_PATH
    init_db(target_db_path)
    with _DB_LOCK:
        with sqlite3.connect(target_db_path) as conn:
            scan_timestamps = [
                row[0]
                for row in conn.execute(
                    "SELECT DISTINCT scanned_at FROM nmap_results ORDER BY scanned_at DESC"
                ).fetchall()
            ]
            if not scan_timestamps:
                return []

            host_rows = conn.execute(
                """
                SELECT latest.ip,
                       COALESCE(d.hostname, latest.ip) AS hostname,
                       latest.last_seen,
                       first_seen.first_seen
                FROM (
                    SELECT ip, MAX(scanned_at) AS last_seen
                    FROM nmap_results
                    GROUP BY ip
                ) AS latest
                JOIN (
                    SELECT ip, MIN(scanned_at) AS first_seen
                    FROM nmap_results
                    GROUP BY ip
                ) AS first_seen ON first_seen.ip = latest.ip
                LEFT JOIN devices d ON d.ip = latest.ip
                ORDER BY latest.ip ASC
                """
            ).fetchall()

            presence_rows = conn.execute(
                """
                SELECT ip, scanned_at
                FROM nmap_results
                GROUP BY ip, scanned_at
                """
            ).fetchall()

    scans_by_ip: dict[str, set[str]] = {}
    for ip, scanned_at in presence_rows:
        scans_by_ip.setdefault(ip, set()).add(scanned_at)

    classified_rows: list[tuple[str, str, str, str]] = []
    latest_scan = scan_timestamps[0]

    for ip, hostname, last_seen, first_seen in host_rows:
        scans_for_ip = scans_by_ip.get(ip, set())
        status_class = ""

        if first_seen == latest_scan:
            status_class = "status-new"
        elif latest_scan not in scans_for_ip:
            offline_streak = 0
            for scan_ts in scan_timestamps:
                if scan_ts in scans_for_ip:
                    break
                offline_streak += 1
            status_class = "status-offline-long" if offline_streak > 3 else "status-offline"
        else:
            online_streak = 0
            for scan_ts in scan_timestamps:
                if scan_ts not in scans_for_ip:
                    break
                online_streak += 1
            if online_streak > 3:
                status_class = "status-online-long"

        classified_rows.append((ip, hostname, last_seen, status_class))

    return classified_rows


def render_hosts_table(rows: list[tuple[str, str, str, str]]) -> str:
    """Builds HTML table for hosts list."""

    if not rows:
        return "<p>Ingen nmap-resultater endnu.</p>"

    body_rows = "\n".join(
        (
            "<tr>"
            f"<td class=\"{status_class}\">{escape(ip)}</td>"
            f"<td class=\"{status_class}\">{_render_hostname_cell(hostname, ip)}</td>"
            f"<td class=\"{status_class}\">{_format_last_seen(last_seen)}</td>"
            "</tr>"
        )
        for ip, hostname, last_seen, status_class in rows
    )
    return f"""
    <table>
      <thead>
        <tr><th>IP</th><th>Hostname</th><th>Sidst fundet</th></tr>
      </thead>
      <tbody>
        {body_rows}
      </tbody>
    </table>
    """


def render_status_legend() -> str:
    """Builds legend that explains dashboard status colors."""

    legend_items = [
        ("status-new", "Ny enhed", "Set første gang i seneste scanning."),
        ("status-offline", "Offline", "Ikke set i seneste scanning."),
        ("status-offline-long", "Offline længe", "Ikke set i mere end 3 scanninger."),
        ("status-online-long", "Stabil online", "Set i mere end 3 scanninger i træk."),
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


def _render_hostname_cell(hostname: str, ip: str) -> str:
    """Renders hostname as history link when present."""

    clean_hostname = _normalize_hostname(hostname, ip)

    encoded_ip = quote_plus(ip)
    return (
        f"<a href=\"/history?ip={encoded_ip}\" "
        f"title=\"Vis historik for {escape(clean_hostname)}\">{escape(clean_hostname)}</a>"
    )


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
    """Returns editable hostname from devices table for one IP."""

    target_db_path = db_path or DB_PATH
    init_db(target_db_path)
    with _DB_LOCK:
        with sqlite3.connect(target_db_path) as conn:
            row = conn.execute(
                "SELECT hostname FROM devices WHERE ip = ? LIMIT 1",
                (ip,),
            ).fetchone()

    if not row:
        return ip
    return _normalize_hostname(row[0], ip)


def update_saved_hostname(ip: str, hostname: str, db_path: str | None = None) -> str:
    """Updates editable hostname for IP and returns normalized hostname."""

    target_db_path = db_path or DB_PATH
    normalized_hostname = _normalize_hostname(hostname, ip)
    init_db(target_db_path)
    with _DB_LOCK:
        with sqlite3.connect(target_db_path) as conn:
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
      <label for="hostname"><strong>Hostname (redigerbar):</strong></label>
      <input id="hostname" name="hostname" value="{escaped_saved_hostname}" />
      <button type="submit">Gem hostname</button>
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


class HomeMonitorHandler(BaseHTTPRequestHandler):
    """Serves Home Monitor dashboard page."""

    def do_POST(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler naming)
        parsed_path = urlparse(self.path)
        if parsed_path.path == "/dashboard/scan":
            scan_and_store()
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", "/dashboard")
            self.end_headers()
            return

        if parsed_path.path != "/history/update":
            self.send_error(HTTPStatus.NOT_FOUND, "Page not found")
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(content_length).decode("utf-8")
        form_data = parse_qs(raw_body)

        ip = form_data.get("ip", [""])[0].strip()
        hostname = form_data.get("hostname", [""])[0]
        if not ip:
            self.send_error(HTTPStatus.BAD_REQUEST, "IP field is required")
            return

        update_saved_hostname(ip, hostname)
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", f"/history?ip={quote_plus(ip)}")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler naming)
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        query_params = parse_qs(parsed_path.query)

        if path == "/health":
            uptime_seconds = int(time.monotonic() - START_TIME_MONOTONIC)
            body = f"OK\nUptime: {format_uptime(uptime_seconds)}".encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/history":
            ip_values = query_params.get("ip", [])
            selected_ip = ip_values[0].strip() if ip_values else ""
            if not selected_ip:
                self.send_error(HTTPStatus.BAD_REQUEST, "IP query parameter is required")
                return

            history_rows = get_ip_history(selected_ip)
            saved_hostname = get_saved_hostname(selected_ip)
            history_table = render_hostname_history_table(selected_ip, saved_hostname, history_rows)
            html = f"""<!doctype html>
<html lang=\"da\">
  <head>
    <meta charset=\"utf-8\" />
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
    <title>Home Monitor - Hostname historik</title>
    <style>
      body {{
        margin: 0;
        padding: 24px;
        font-family: Arial, sans-serif;
      }}

      table {{
        border-collapse: collapse;
        margin-top: 16px;
        min-width: 450px;
      }}

      th, td {{
        border: 1px solid #d0d0d0;
        padding: 8px 10px;
        text-align: left;
      }}

      th {{
        background: #f5f5f5;
      }}
    </style>
  </head>
  <body>
    <h1>Home Monitor</h1>
    {history_table}
  </body>
</html>
"""
            body = html.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path not in {"/", "/dashboard"}:
            self.send_error(HTTPStatus.NOT_FOUND, "Page not found")
            return

        restart_time = format_restart_time(SERVER_RESTART_TIME)
        rows = get_dashboard_rows()
        hosts_table = render_hosts_table(rows)
        status_legend = render_status_legend()
        html = f"""<!doctype html>
<html lang=\"da\">
  <head>
    <meta charset=\"utf-8\" />
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
    <title>Home Monitor</title>
    <style>
      body {{
        margin: 0;
        padding: 24px;
        font-family: Arial, sans-serif;
      }}

      .top-bar {{
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        gap: 16px;
      }}

      .restart-time {{
        margin: 0;
        font-size: 14px;
        color: #3d3d3d;
        text-align: right;
      }}

      table {{
        border-collapse: collapse;
        min-width: 380px;
      }}

      th, td {{
        border: 1px solid #d0d0d0;
        padding: 8px 10px;
        text-align: left;
      }}

      th {{
        background: #f5f5f5;
      }}

      .status-new {{
        background: #f8caca;
      }}

      .status-offline {{
        background: #fff4b8;
      }}

      .status-offline-long {{
        background: #ffd8a8;
      }}

      .status-online-long {{
        background: #d8f5c0;
      }}

      .dashboard-content {{
        margin-top: 16px;
        display: flex;
        align-items: flex-start;
        gap: 24px;
        flex-wrap: wrap;
      }}

      .status-legend {{
        border: 1px solid #d0d0d0;
        border-radius: 6px;
        padding: 12px;
        min-width: 280px;
        background: #fafafa;
      }}

      .status-legend h3 {{
        margin: 0 0 10px 0;
        font-size: 16px;
      }}

      .status-legend ul {{
        margin: 0;
        padding: 0;
        list-style: none;
      }}

      .status-legend li {{
        display: flex;
        align-items: center;
        gap: 10px;
      }}

      .status-legend li + li {{
        margin-top: 8px;
      }}

      .legend-swatch {{
        width: 14px;
        height: 14px;
        border: 1px solid #bdbdbd;
        border-radius: 3px;
        display: inline-block;
        flex: 0 0 14px;
      }}
    </style>
  </head>
  <body>
    <div class=\"top-bar\">
      <h1>Home Monitor</h1>
      <p class=\"restart-time\">Sidste server-restart: {restart_time}</p>
    </div>
    <form method="post" action="/dashboard/scan">
      <button type="submit">Scan network</button>
    </form>
    <h2>Aktive enheder (192.168.0.x)</h2>
    <div class="dashboard-content">
      {hosts_table}
      {status_legend}
    </div>
  </body>
</html>
"""
        body = html.encode("utf-8")

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    init_db()
    stop_event = threading.Event()
    scanner_thread = threading.Thread(target=scan_scheduler, args=(stop_event,), daemon=True)
    scanner_thread.start()

    server = ThreadingHTTPServer((HOST, PORT), HomeMonitorHandler)
    print(f"Home Monitor kører på http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopper server ...")
    finally:
        stop_event.set()
        server.server_close()


if __name__ == "__main__":
    main()
