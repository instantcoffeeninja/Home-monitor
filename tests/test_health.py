import threading
import time
from pathlib import Path
import sys
from urllib.request import urlopen

from http.server import ThreadingHTTPServer

sys.path.append(str(Path(__file__).resolve().parents[1]))
from server import HomeMonitorHandler


def start_test_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), HomeMonitorHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


def test_health_returns_200_and_ok():
    server, port = start_test_server()
    try:
        time.sleep(0.1)
        with urlopen(f"http://127.0.0.1:{port}/health") as response:
            body = response.read().decode("utf-8")
            assert response.status == 200
            assert body == "ok"
    finally:
        server.shutdown()
        server.server_close()
