"""Tests for health endpoint."""

from http.server import ThreadingHTTPServer
import threading
import unittest
from urllib.request import urlopen

from app import HomeMonitorHandler


class HealthEndpointTest(unittest.TestCase):
    def setUp(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), HomeMonitorHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_health_returns_ok(self) -> None:
        url = f"http://127.0.0.1:{self.server.server_port}/health"
        with urlopen(url, timeout=2) as response:
            body = response.read().decode("utf-8")
            self.assertEqual(response.status, 200)
            self.assertEqual(body, "ok")


if __name__ == "__main__":
    unittest.main()
