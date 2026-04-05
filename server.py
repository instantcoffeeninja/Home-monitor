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
import math

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

    command = [nmap_bin, "-sn", network_range, "-oG", "-"]
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


def get_latest_scan_results(db_path: str | None = None) -> list[tuple[str, str]]:
    """Fetches the latest batch of scan rows."""

    target_db_path = db_path or DB_PATH
    init_db(target_db_path)
    with _DB_LOCK:
        with sqlite3.connect(target_db_path) as conn:
            row = conn.execute("SELECT MAX(scanned_at) FROM nmap_results").fetchone()
            latest_scanned_at = row[0] if row else None
            if not latest_scanned_at:
                return []

            rows = conn.execute(
                """
                SELECT ip, COALESCE(hostname, '')
                FROM nmap_results
                WHERE scanned_at = ?
                ORDER BY ip ASC
                """,
                (latest_scanned_at,),
            ).fetchall()

    return [(ip, hostname) for ip, hostname in rows]


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


def render_hosts_table(rows: list[tuple[str, str]]) -> str:
    """Builds HTML table for hosts list."""

    if not rows:
        return "<p>Ingen nmap-resultater endnu.</p>"

    body_rows = "\n".join(
        f"<tr><td>{escape(ip)}</td><td>{escape(hostname or '-')}</td></tr>" for ip, hostname in rows
    )
    return f"""
    <table>
      <thead>
        <tr><th>IP</th><th>Hostname</th></tr>
      </thead>
      <tbody>
        {body_rows}
      </tbody>
    </table>
    """


class HomeMonitorHandler(BaseHTTPRequestHandler):
    """Serves Home Monitor dashboard page."""

    def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler naming)
        if self.path == "/health":
            uptime_seconds = int(time.monotonic() - START_TIME_MONOTONIC)
            body = f"OK\nUptime: {format_uptime(uptime_seconds)}".encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path not in {"/", "/dashboard"}:
            self.send_error(HTTPStatus.NOT_FOUND, "Page not found")
            return

        restart_time = format_restart_time(SERVER_RESTART_TIME)
        rows = get_latest_scan_results()
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
