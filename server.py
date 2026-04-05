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
                    hostname TEXT
                )
                """
            )
            columns = {
                row[1]
                for row in conn.execute("PRAGMA table_info(nmap_results)").fetchall()
            }
            if "hostname" not in columns:
                conn.execute("ALTER TABLE nmap_results ADD COLUMN hostname TEXT")
            conn.commit()


def parse_nmap_grepable(output: str) -> list[tuple[str, str]]:
    """Parses nmap -oG output and returns active hosts as (ip, hostname)."""

    hosts: list[tuple[str, str]] = []
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

        if ip:
            hosts.append((ip, hostname))

    return hosts


def run_nmap_scan(network_range: str = NETWORK_RANGE, nmap_bin: str = NMAP_BIN) -> list[tuple[str, str]]:
    """Runs nmap ping scan and returns active hosts."""

    command = [nmap_bin, "-sn", "-R", network_range, "-oG", "-"]
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    return parse_nmap_grepable(result.stdout)


def save_scan_results(hosts: list[tuple[str, str]], db_path: str | None = None) -> None:
    """Saves a scan result batch to sqlite."""

    target_db_path = db_path or DB_PATH
    scanned_at = datetime.now(timezone.utc).isoformat()
    with _DB_LOCK:
        with sqlite3.connect(target_db_path) as conn:
            conn.executemany(
                "INSERT INTO nmap_results (scanned_at, ip, hostname) VALUES (?, ?, ?)",
                [(scanned_at, ip, hostname) for ip, hostname in hosts],
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
                       COALESCE(
                           (
                               SELECT nr.hostname
                               FROM nmap_results nr
                               WHERE nr.ip = latest.ip
                                 AND NULLIF(TRIM(COALESCE(nr.hostname, '')), '') IS NOT NULL
                               ORDER BY nr.scanned_at DESC, nr.id DESC
                               LIMIT 1
                           ),
                           ''
                       ) AS hostname,
                       latest.last_seen
                FROM (
                    SELECT ip, MAX(scanned_at) AS last_seen
                    FROM nmap_results
                    GROUP BY ip
                ) AS latest
                ORDER BY ip ASC
                """,
            ).fetchall()

    return [(ip, hostname, last_seen) for ip, hostname, last_seen in rows]


def scan_and_store(
    db_path: str | None = None,
    network_range: str = NETWORK_RANGE,
    nmap_bin: str = NMAP_BIN,
) -> list[tuple[str, str]]:
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


def _format_last_seen(last_seen: str) -> str:
    """Format ISO timestamp to dashboard-friendly UTC string."""

    try:
        parsed = datetime.fromisoformat(last_seen)
    except ValueError:
        return escape(last_seen)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)
    return parsed.strftime("%d-%m-%Y %H:%M:%S UTC")


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
                       COALESCE(
                           (
                               SELECT nr.hostname
                               FROM nmap_results nr
                               WHERE nr.ip = latest.ip
                                 AND NULLIF(TRIM(COALESCE(nr.hostname, '')), '') IS NOT NULL
                               ORDER BY nr.scanned_at DESC, nr.id DESC
                               LIMIT 1
                           ),
                           ''
                       ) AS hostname,
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
            f"<td class=\"{status_class}\">{_render_hostname_cell(hostname)}</td>"
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


def _render_hostname_cell(hostname: str) -> str:
    """Renders hostname as history link when present."""

    clean_hostname = (hostname or "").strip()
    if not clean_hostname:
        return "-"

    encoded_hostname = quote_plus(clean_hostname)
    return (
        f"<a href=\"/history?hostname={encoded_hostname}\" "
        f"title=\"Vis historik for {escape(clean_hostname)}\">{escape(clean_hostname)}</a>"
    )


def get_hostname_history(hostname: str, db_path: str | None = None) -> list[tuple[str, str, str]]:
    """Returns all saved rows for a specific hostname."""

    target_db_path = db_path or DB_PATH
    init_db(target_db_path)
    with _DB_LOCK:
        with sqlite3.connect(target_db_path) as conn:
            rows = conn.execute(
                """
                SELECT scanned_at, ip, hostname
                FROM nmap_results
                WHERE hostname = ?
                ORDER BY scanned_at DESC, id DESC
                """,
                (hostname,),
            ).fetchall()

    return [(scanned_at, ip, row_hostname or "") for scanned_at, ip, row_hostname in rows]


def render_hostname_history_table(hostname: str, rows: list[tuple[str, str, str]]) -> str:
    """Builds HTML table with historical records for one hostname."""

    escaped_hostname = escape(hostname)
    if not rows:
        return f"<p>Ingen historik fundet for hostname: <strong>{escaped_hostname}</strong>.</p>"

    body_rows = "\n".join(
        (
            "<tr>"
            f"<td>{_format_last_seen(scanned_at)}</td>"
            f"<td>{escape(ip)}</td>"
            f"<td>{escape(row_hostname or '-')}</td>"
            "</tr>"
        )
        for scanned_at, ip, row_hostname in rows
    )
    return f"""
    <h2>Historik for hostname: {escaped_hostname}</h2>
    <p><a href="/dashboard">Luk historik og gå tilbage</a></p>
    <table>
      <thead>
        <tr><th>Scannet</th><th>IP</th><th>Hostname</th></tr>
      </thead>
      <tbody>
        {body_rows}
      </tbody>
    </table>
    """


class HomeMonitorHandler(BaseHTTPRequestHandler):
    """Serves Home Monitor dashboard page."""

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
            hostname_values = query_params.get("hostname", [])
            selected_hostname = hostname_values[0].strip() if hostname_values else ""
            if not selected_hostname:
                self.send_error(HTTPStatus.BAD_REQUEST, "Hostname query parameter is required")
                return

            history_rows = get_hostname_history(selected_hostname)
            history_table = render_hostname_history_table(selected_hostname, history_rows)
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
        margin-top: 16px;
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
    </style>
  </head>
  <body>
    <div class=\"top-bar\">
      <h1>Home Monitor</h1>
      <p class=\"restart-time\">Sidste server-restart: {restart_time}</p>
    </div>
    <h2>Aktive enheder (192.168.0.x)</h2>
    {hosts_table}
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
