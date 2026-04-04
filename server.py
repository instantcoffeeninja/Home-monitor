"""Minimal webserver scaffold for Home Monitor dashboard."""

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timezone
import os
import time


HOST = "0.0.0.0"
PORT = int(os.getenv("PORT", "8000"))
START_TIME_MONOTONIC = time.monotonic()
SERVER_RESTART_TIME = datetime.now(timezone.utc)


def format_uptime(total_seconds: int) -> str:
    """Formats uptime in HH:MM:SS."""

    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02}:{minutes:02}:{seconds:02}"


def format_restart_time(restart_time: datetime) -> str:
    """Formats restart time in a human-friendly UTC timestamp."""

    return restart_time.strftime("%d-%m-%Y %H:%M:%S UTC")


class HomeMonitorHandler(BaseHTTPRequestHandler):
    """Serves a simple placeholder dashboard page."""

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
    </style>
  </head>
  <body>
    <div class=\"top-bar\">
      <h1>Home Monitor</h1>
      <p class=\"restart-time\">Sidste server-restart: {restart_time}</p>
    </div>
    <p>Webserver er klar. Dashboard-indhold kommer i næste trin!</p>
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
    server = ThreadingHTTPServer((HOST, PORT), HomeMonitorHandler)
    print(f"Home Monitor kører på http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopper server ...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
