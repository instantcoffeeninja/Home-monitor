import threading
import time
from urllib.request import urlopen
from urllib.error import HTTPError
import sqlite3

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
            assert ("IP" in body and "Hostname" in body and "Sidst fundet" in body) or "Ingen nmap-resultater endnu." in body
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
                assert "Sidst fundet" in body
        finally:
            server_instance.shutdown()
            server_instance.server_close()
    finally:
        server.DB_PATH = original_db_path


def test_dashboard_shows_hosts_last_seen_from_previous_scans(tmp_path):
    db_path = tmp_path / "home_monitor_test_history.db"
    original_db_path = server.DB_PATH
    server.DB_PATH = str(db_path)

    try:
        server.init_db(server.DB_PATH)
        server.save_scan_results([("192.168.0.30", "nas.local")], db_path=server.DB_PATH)
        server.save_scan_results([("192.168.0.40", "tv.local")], db_path=server.DB_PATH)

        server_instance, port = start_test_server()
        try:
            time.sleep(0.1)
            with urlopen(f"http://127.0.0.1:{port}/dashboard") as response:
                body = response.read().decode("utf-8")
                assert "192.168.0.30" in body
                assert "nas.local" in body
                assert "192.168.0.40" in body
                assert "tv.local" in body
        finally:
            server_instance.shutdown()
            server_instance.server_close()
    finally:
        server.DB_PATH = original_db_path


def test_dashboard_status_color_classes(tmp_path):
    db_path = tmp_path / "home_monitor_test_status.db"
    original_db_path = server.DB_PATH
    server.DB_PATH = str(db_path)

    try:
        server.init_db(server.DB_PATH)

        with sqlite3.connect(server.DB_PATH) as conn:
            conn.executemany(
                "INSERT INTO nmap_results (scanned_at, ip, hostname) VALUES (?, ?, ?)",
                [
                    ("2026-04-01T00:00:00+00:00", "192.168.0.10", "offline-long.local"),
                    ("2026-04-02T00:00:00+00:00", "192.168.0.20", "online-long.local"),
                    ("2026-04-03T00:00:00+00:00", "192.168.0.20", "online-long.local"),
                    ("2026-04-04T00:00:00+00:00", "192.168.0.20", "online-long.local"),
                    ("2026-04-04T00:00:00+00:00", "192.168.0.30", "offline-short.local"),
                    ("2026-04-05T00:00:00+00:00", "192.168.0.20", "online-long.local"),
                    ("2026-04-05T00:00:00+00:00", "192.168.0.40", "new.local"),
                ],
            )
            conn.commit()

        rows = server.get_dashboard_rows(server.DB_PATH)
        status_by_ip = {ip: status for ip, _hostname, _last_seen, status in rows}

        assert status_by_ip["192.168.0.10"] == "status-offline-long"
        assert status_by_ip["192.168.0.20"] == "status-online-long"
        assert status_by_ip["192.168.0.30"] == "status-offline"
        assert status_by_ip["192.168.0.40"] == "status-new"

        rendered_table = server.render_hosts_table(rows)
        assert "class=\"status-offline-long\"" in rendered_table
        assert "class=\"status-online-long\"" in rendered_table
        assert "class=\"status-offline\"" in rendered_table
        assert "class=\"status-new\"" in rendered_table
    finally:
        server.DB_PATH = original_db_path
