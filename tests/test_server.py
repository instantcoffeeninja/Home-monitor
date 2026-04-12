from datetime import datetime, timezone
import sqlite3

import server



def test_homepage_returns_200():
    with server.app.test_client() as client:
        response = client.get("/")

    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "Home Monitor" in body


def test_dashboard_returns_200():
    with server.app.test_client() as client:
        response = client.get("/dashboard")

    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "Sidste server-restart:" in body
    assert "Aktive enheder (192.168.0.x)" in body
    assert '<meta http-equiv="refresh" content="30" />' in body
    assert "Scan network" in body
    assert "<strong>Total:</strong>" in body
    assert "<strong>Online:</strong>" in body
    assert "<strong>Idle:</strong>" in body
    assert "<strong>Offline:</strong>" in body
    assert "Farveforklaring" in body
    assert 'class="dashboard-content"' in body
    assert (
        ("Ping" in body and "IP" in body and "Hostname" in body and "Sidst fundet" in body)
        or "Ingen nmap-resultater endnu." in body
    )


def test_unknown_page_returns_404():
    with server.app.test_client() as client:
        response = client.get("/does-not-exist")

    assert response.status_code == 404


def test_dashboard_shows_saved_hosts(tmp_path):
    db_path = tmp_path / "home_monitor_test.db"
    original_db_path = server.DB_PATH
    server.DB_PATH = str(db_path)

    try:
        server.init_db(server.DB_PATH)
        server.save_scan_results(
            [("192.168.0.10", "printer", "", ""), ("192.168.0.20", "", "", "")],
            db_path=server.DB_PATH,
        )

        with server.app.test_client() as client:
            response = client.get("/dashboard")

        body = response.get_data(as_text=True)
        assert "192.168.0.10" in body
        assert "printer" in body
        assert "192.168.0.20" in body
        assert "Sidst fundet" in body
    finally:
        server.DB_PATH = original_db_path


def test_dashboard_shows_hosts_last_seen_from_previous_scans(tmp_path):
    db_path = tmp_path / "home_monitor_test_history.db"
    original_db_path = server.DB_PATH
    server.DB_PATH = str(db_path)

    try:
        server.init_db(server.DB_PATH)
        server.save_scan_results([("192.168.0.30", "nas.local", "", "")], db_path=server.DB_PATH)
        server.save_scan_results([("192.168.0.40", "tv.local", "", "")], db_path=server.DB_PATH)

        with server.app.test_client() as client:
            response = client.get("/dashboard")

        body = response.get_data(as_text=True)
        assert "192.168.0.30" in body
        assert "nas.local" in body
        assert "192.168.0.40" in body
        assert "tv.local" in body
    finally:
        server.DB_PATH = original_db_path


def test_dashboard_shows_vendor_name_with_mac_fallback(tmp_path):
    db_path = tmp_path / "home_monitor_test_vendor.db"
    original_db_path = server.DB_PATH
    server.DB_PATH = str(db_path)

    try:
        server.init_db(server.DB_PATH)
        server.save_scan_results(
            [
                ("192.168.0.91", "speaker.local", "AA:BB:CC:DD:EE:11", "Acme Corp"),
                ("192.168.0.92", "camera.local", "AA:BB:CC:DD:EE:22", ""),
            ],
            db_path=server.DB_PATH,
        )

        rows = server.get_dashboard_rows(server.DB_PATH)
        rendered_table = server.render_hosts_table(rows)
        assert "speaker.local" in rendered_table
        assert "(Acme Corp)" in rendered_table
        assert "camera.local" in rendered_table
        assert "(AA:BB:CC:DD:EE:22)" in rendered_table
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
        status_by_ip = {ip: status for ip, _hostname, _last_seen, status, _mac, _vendor in rows}

        assert status_by_ip["192.168.0.10"] == "status-offline"
        assert status_by_ip["192.168.0.20"] == "status-offline"
        assert status_by_ip["192.168.0.30"] == "status-offline"
        assert status_by_ip["192.168.0.40"] == "status-offline"

        rendered_table = server.render_hosts_table(rows)
        rendered_legend = server.render_status_legend()
        assert 'class="status-dot status-offline"' in rendered_table
        assert "Farveforklaring" in rendered_legend
        assert "Online" in rendered_legend
        assert "Idle" in rendered_legend
        assert "Offline" in rendered_legend
    finally:
        server.DB_PATH = original_db_path


def test_status_class_for_last_seen_thresholds():
    now = datetime(2026, 4, 6, 12, 0, 0, tzinfo=timezone.utc)

    assert server._status_class_for_last_seen("2026-04-06T11:59:10+00:00", now=now) == "status-online"
    assert server._status_class_for_last_seen("2026-04-06T11:51:00+00:00", now=now) == "status-idle"
    assert server._status_class_for_last_seen("2026-04-06T11:49:59+00:00", now=now) == "status-offline"


def test_hostname_history_links_and_page_content(tmp_path):
    db_path = tmp_path / "home_monitor_test_hostname_history.db"
    original_db_path = server.DB_PATH
    server.DB_PATH = str(db_path)

    try:
        server.init_db(server.DB_PATH)
        with sqlite3.connect(server.DB_PATH) as conn:
            conn.executemany(
                "INSERT INTO nmap_results (scanned_at, ip, hostname, mac_address) VALUES (?, ?, ?, ?)",
                [
                    ("2026-04-04T10:00:00+00:00", "192.168.0.50", "laptop.local", "11:22:33:44:55:66"),
                    ("2026-04-05T10:00:00+00:00", "192.168.0.50", "laptop.local", "11:22:33:44:55:66"),
                    ("2026-04-05T10:00:00+00:00", "192.168.0.60", "phone.local", ""),
                ],
            )
            conn.executemany(
                "INSERT INTO devices (ip, hostname, mac_address) VALUES (?, ?, ?)",
                [
                    ("192.168.0.50", "laptop.local", "11:22:33:44:55:66"),
                    ("192.168.0.60", "phone.local", None),
                ],
            )
            conn.commit()

        with server.app.test_client() as client:
            response = client.get("/dashboard")
            body = response.get_data(as_text=True)
            assert response.status_code == 200
            assert "/history?ip=192.168.0.50" in body
            assert "/history?ip=192.168.0.60" in body

            history_response = client.get("/history?ip=192.168.0.50")
            history_body = history_response.get_data(as_text=True)
            assert history_response.status_code == 200
            assert "Historik for IP: 192.168.0.50" in history_body
            assert "192.168.0.50" in history_body
            assert "laptop.local" in history_body
            assert "11:22:33:44:55:66" in history_body
            assert "Gem enhedsnavn" in history_body
            assert "Luk historik og gå tilbage" in history_body
            assert "phone.local" not in history_body
    finally:
        server.DB_PATH = original_db_path


def test_history_page_can_update_hostname_and_defaults_to_ip(tmp_path):
    db_path = tmp_path / "home_monitor_test_update_hostname.db"
    original_db_path = server.DB_PATH
    server.DB_PATH = str(db_path)

    try:
        server.init_db(server.DB_PATH)
        server.save_scan_results([("192.168.0.70", "", "AA:AA:AA:AA:AA:AA", "")], db_path=server.DB_PATH)

        rows = server.get_dashboard_rows(server.DB_PATH)
        hostname_by_ip = {ip: hostname for ip, hostname, _last_seen, _status, _mac, _vendor in rows}
        assert hostname_by_ip["192.168.0.70"] == "192.168.0.70"

        with server.app.test_client() as client:
            response = client.post(
                "/history/update",
                data={"ip": "192.168.0.70", "hostname": "Min Laptop"},
                follow_redirects=True,
            )

        assert response.status_code == 200
        redirected_body = response.get_data(as_text=True)
        assert "Historik for IP: 192.168.0.70" in redirected_body
        assert "Min Laptop" in redirected_body

        with sqlite3.connect(server.DB_PATH) as conn:
            override_row = conn.execute(
                "SELECT custom_name FROM device_name_overrides WHERE mac_address = ?",
                ("AA:AA:AA:AA:AA:AA",),
            ).fetchone()
        assert override_row == ("Min Laptop",)

        rows_after_update = server.get_dashboard_rows(server.DB_PATH)
        hostname_by_ip_after_update = {ip: hostname for ip, hostname, _last_seen, _status, _mac, _vendor in rows_after_update}
        assert hostname_by_ip_after_update["192.168.0.70"] == "Min Laptop"
    finally:
        server.DB_PATH = original_db_path


def test_avahi_resolve_result_is_used_for_blank_hostname(tmp_path):
    db_path = tmp_path / "home_monitor_test_avahi.db"
    original_db_path = server.DB_PATH
    original_resolver = server.resolve_hostname_with_avahi
    server.DB_PATH = str(db_path)

    try:
        server.init_db(server.DB_PATH)
        server.resolve_hostname_with_avahi = lambda _ip, avahi_resolve_bin=server.AVAHI_RESOLVE_BIN: "resolved.local"

        server.save_scan_results([("192.168.0.88", "", "", "")], db_path=server.DB_PATH)

        rows = server.get_dashboard_rows(server.DB_PATH)
        hostname_by_ip = {ip: hostname for ip, hostname, _last_seen, _status, _mac, _vendor in rows}
        assert hostname_by_ip["192.168.0.88"] == "resolved.local"
    finally:
        server.resolve_hostname_with_avahi = original_resolver
        server.DB_PATH = original_db_path


def test_dashboard_scan_button_triggers_scan_and_refreshes_ui(tmp_path):
    db_path = tmp_path / "home_monitor_test_manual_scan.db"
    original_db_path = server.DB_PATH
    original_scan_and_store = server.scan_and_store
    server.DB_PATH = str(db_path)

    call_count = {"value": 0}

    def fake_scan_and_store(db_path=None, network_range=server.NETWORK_RANGE, nmap_bin=server.NMAP_BIN):
        call_count["value"] += 1
        server.save_scan_results(
            [("192.168.0.80", "scan-device.local", "AA:BB:CC:DD:EE:FF", "")],
            db_path=db_path or server.DB_PATH,
        )
        return [("192.168.0.80", "scan-device.local", "AA:BB:CC:DD:EE:FF", "")]

    server.scan_and_store = fake_scan_and_store

    try:
        server.init_db(server.DB_PATH)
        with server.app.test_client() as client:
            response = client.post("/dashboard/scan", data={}, follow_redirects=True)

        body = response.get_data(as_text=True)
        assert response.status_code == 200
        assert "scan-device.local" in body
        assert "192.168.0.80" in body
        assert call_count["value"] == 1
    finally:
        server.scan_and_store = original_scan_and_store
        server.DB_PATH = original_db_path


def test_format_last_seen_human_readable_time():
    now = datetime(2026, 4, 6, 12, 0, 0, tzinfo=timezone.utc)

    assert server._format_last_seen("2026-04-06T11:59:30+00:00", now=now) == "online now"
    assert server._format_last_seen("2026-04-06T11:55:00+00:00", now=now) == "5 minutes ago"
    assert server._format_last_seen("2026-04-06T09:00:00+00:00", now=now) == "3 hours ago"


def test_resolve_hostname_with_avahi_uses_expected_command(monkeypatch):
    called = {}

    class DummyResult:
        stdout = "192.168.0.90\tprinter.local\n"

    def fake_run(command, capture_output, text, check):
        called["command"] = command
        return DummyResult()

    monkeypatch.setattr(server.subprocess, "run", fake_run)

    resolved = server.resolve_hostname_with_avahi("192.168.0.90")

    assert called["command"] == [server.AVAHI_RESOLVE_BIN, "-a", "192.168.0.90"]
    assert resolved == "printer.local"


def test_render_device_summary_bar_counts_statuses():
    rows = [
        ("192.168.0.10", "online", "2026-04-06T11:59:40+00:00", "status-online", "", ""),
        ("192.168.0.20", "idle", "2026-04-06T11:55:00+00:00", "status-idle", "", ""),
        ("192.168.0.30", "offline", "2026-04-06T10:00:00+00:00", "status-offline", "", ""),
        ("192.168.0.40", "offline-2", "2026-04-06T09:00:00+00:00", "status-offline", "", ""),
    ]

    summary = server.render_device_summary_bar(rows)

    assert "<strong>Total:</strong> 4" in summary
    assert "<strong>Online:</strong> 1" in summary
    assert "<strong>Idle:</strong> 1" in summary
    assert "<strong>Offline:</strong> 2" in summary


def test_ping_selection_defaults_off_and_triggers_backend_ping(tmp_path):
    db_path = tmp_path / "home_monitor_test_ping_selection.db"
    original_db_path = server.DB_PATH
    original_ping_host = server.ping_host
    server.DB_PATH = str(db_path)

    ping_calls = []

    def fake_ping_host(ip, ping_bin=server.PING_BIN):
        ping_calls.append(ip)
        return True

    server.ping_host = fake_ping_host

    try:
        server.init_db(server.DB_PATH)
        server.save_scan_results([("192.168.0.81", "ping-target.local", "", "")], db_path=server.DB_PATH)

        with sqlite3.connect(server.DB_PATH) as conn:
            default_row = conn.execute("SELECT ping_enabled FROM devices WHERE ip = ?", ("192.168.0.81",)).fetchone()
        assert default_row == (0,)

        with server.app.test_client() as client:
            response = client.get("/dashboard")
            body = response.get_data(as_text=True)
            assert 'action="/dashboard/ping-selection"' in body
            assert 'name="ping_enabled"' in body
            assert 'value="1"' in body
            assert "checked" not in body

            checked_response = client.post(
                "/dashboard/ping-selection",
                data={"ip": "192.168.0.81", "ping_enabled": "1"},
                follow_redirects=True,
            )
            checked_body = checked_response.get_data(as_text=True)
            assert checked_response.status_code == 200
            assert 'value="1" aria-label="Enable ping for 192.168.0.81" checked' in checked_body

        with sqlite3.connect(server.DB_PATH) as conn:
            enabled_row = conn.execute("SELECT ping_enabled FROM devices WHERE ip = ?", ("192.168.0.81",)).fetchone()
            ping_seen_count = conn.execute("SELECT COUNT(*) FROM nmap_results WHERE ip = ?", ("192.168.0.81",)).fetchone()
        assert enabled_row == (1,)
        assert ping_seen_count[0] >= 2
        assert ping_calls == ["192.168.0.81"]
    finally:
        server.ping_host = original_ping_host
        server.DB_PATH = original_db_path


def test_new_devices_are_highlighted_with_badge(tmp_path):
    db_path = tmp_path / "home_monitor_test_new_devices.db"
    original_db_path = server.DB_PATH
    server.DB_PATH = str(db_path)

    try:
        server.init_db(server.DB_PATH)
        with sqlite3.connect(server.DB_PATH) as conn:
            conn.executemany(
                "INSERT INTO nmap_results (scanned_at, ip, hostname) VALUES (?, ?, ?)",
                [
                    ((datetime.now(timezone.utc).isoformat()), "192.168.0.100", "new.local"),
                    ("2026-01-01T00:00:00+00:00", "192.168.0.101", "old.local"),
                ],
            )
            conn.executemany(
                "INSERT INTO devices (ip, hostname) VALUES (?, ?)",
                [
                    ("192.168.0.100", "new.local"),
                    ("192.168.0.101", "old.local"),
                ],
            )
            conn.commit()

        rows = server.get_dashboard_rows(server.DB_PATH)
        recent_ips = server.get_recently_discovered_ips(server.DB_PATH)
        rendered_table = server.render_hosts_table(rows, newly_discovered_ips=recent_ips)

        assert "192.168.0.100" in recent_ips
        assert "192.168.0.101" not in recent_ips
        assert 'class="new-device-row"' in rendered_table
        assert '<span class="new-device-badge">New</span>' in rendered_table
    finally:
        server.DB_PATH = original_db_path


def test_new_devices_excludes_future_first_seen(tmp_path):
    db_path = tmp_path / "home_monitor_test_future_device.db"
    original_db_path = server.DB_PATH
    server.DB_PATH = str(db_path)

    try:
        server.init_db(server.DB_PATH)
        with sqlite3.connect(server.DB_PATH) as conn:
            conn.execute(
                "INSERT INTO nmap_results (scanned_at, ip, hostname) VALUES (?, ?, ?)",
                ("3026-01-01T00:00:00+00:00", "192.168.0.200", "future.local"),
            )
            conn.execute(
                "INSERT INTO devices (ip, hostname) VALUES (?, ?)",
                ("192.168.0.200", "future.local"),
            )
            conn.commit()

        recent_ips = server.get_recently_discovered_ips(server.DB_PATH)
        assert "192.168.0.200" not in recent_ips
    finally:
        server.DB_PATH = original_db_path
