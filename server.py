"""Minimal webserver scaffold for Home Monitor dashboard."""

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os


HOST = "0.0.0.0"
PORT = int(os.getenv("PORT", "8000"))


class HomeMonitorHandler(BaseHTTPRequestHandler):
    """Serves a simple placeholder dashboard page."""

    def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler naming)
        if self.path == "/health":
            body = b"ok"
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path not in {"/", "/dashboard"}:
            self.send_error(HTTPStatus.NOT_FOUND, "Page not found")
            return

        html = """<!doctype html>
<html lang=\"da\">
  <head>
    <meta charset=\"utf-8\" />
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
    <title>Home Monitor</title>
  </head>
  <body>
    <h1>Home Monitor</h1>
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
