import threading
import time
from urllib.request import urlopen
from urllib.error import HTTPError

from http.server import ThreadingHTTPServer
import server
from server import HomeMonitorHandler


def start_test_server():
    server_instance = ThreadingHTTPServer(("127.0.0.1", 0), HomeMonitorHandler)
    port = server_instance.server_address[1]
    thread = threading.Thread(target=server_instance.serve_forever, daemon=True)
    thread.start()
    return server_instance, port


def test_homepage_returns_200():
    server_instance, port = start_test_server()
    try:
        time.sleep(0.1)
        with urlopen(f"http://127.0.0.1:{port}/") as response:
            body = response.read().decode("utf-8")
            assert response.status == 200
            assert "Home Monitor" in body
    finally:
        server_instance.shutdown()
        server_instance.server_close()


def test_dashboard_returns_200():
    server_instance, port = start_test_server()
    try:
        time.sleep(0.1)
        with urlopen(f"http://127.0.0.1:{port}/dashboard") as response:
            body = response.read().decode("utf-8")
            assert response.status == 200
            assert "Sidste server-restart:" in body
            assert "Aktive enheder (192.168.0.x)" in body
            assert ("IP" in body and "Hostname" in body) or "Ingen nmap-resultater endnu." in body
    finally:
        server_instance.shutdown()
        server_instance.server_close()


def test_unknown_page_returns_404():
    server_instance, port = start_test_server()
    try:
        time.sleep(0.1)
        try:
            urlopen(f"http://127.0.0.1:{port}/does-not-exist")
            assert False, "Expected 404 error"
        except HTTPError as exc:
            assert exc.code == 404
    finally:
        server_instance.shutdown()
        server_instance.server_close()


def test_dashboard_shows_saved_hosts(tmp_path):
    db_path = tmp_path / "home_monitor_test.db"
    original_db_path = server.DB_PATH
    server.DB_PATH = str(db_path)

    try:
        server.init_db(server.DB_PATH)
        server.save_scan_results(
            [("192.168.0.10", "printer"), ("192.168.0.20", "")],
            db_path=server.DB_PATH,
        )

        server_instance, port = start_test_server()
        try:
            time.sleep(0.1)
            with urlopen(f"http://127.0.0.1:{port}/dashboard") as response:
                body = response.read().decode("utf-8")
                assert "192.168.0.10" in body
                assert "printer" in body
                assert "192.168.0.20" in body
        finally:
            server_instance.shutdown()
            server_instance.server_close()
    finally:
        server.DB_PATH = original_db_path
