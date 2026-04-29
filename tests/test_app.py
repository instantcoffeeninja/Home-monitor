import os
import sqlite3

from home_monitor.app import DEFAULT_PORT, create_app
from home_monitor.core import init_db, save_scan_results


def test_dashboard_returns_old_home_monitor_ui(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("HOME_MONITOR_DB_PATH", str(tmp_path / "home-monitor.db"))
    app = create_app()

    with app.test_client() as client:
        response = client.get("/dashboard")

    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "Home Monitor" in body
    assert "Sidste server-restart:" in body
    assert "CET" in body or "CEST" in body
    assert "Aktive enheder (192.168.0.x)" in body
    assert '<meta http-equiv="refresh" content="30" />' in body
    assert "Scan network" in body
    assert "Farveforklaring" in body
    assert "<strong>Total:</strong>" in body


def test_root_serves_dashboard(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("HOME_MONITOR_DB_PATH", str(tmp_path / "home-monitor.db"))
    app = create_app()

    with app.test_client() as client:
        response = client.get("/")

    assert response.status_code == 200
    assert "Home Monitor" in response.get_data(as_text=True)


def test_health_returns_uptime() -> None:
    app = create_app()

    with app.test_client() as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert "OK" in response.get_data(as_text=True)
    assert "Uptime:" in response.get_data(as_text=True)


def test_history_requires_ip_query_param() -> None:
    app = create_app()

    with app.test_client() as client:
        response = client.get("/history")

    assert response.status_code == 400


def test_default_port_remains_5000() -> None:
    assert DEFAULT_PORT == 5000
    assert os.getenv("PORT", str(DEFAULT_PORT)) == "5000"


def test_ping_checkbox_checked_value_is_preserved(monkeypatch, tmp_path) -> None:
    db_path = tmp_path / "home-monitor.db"
    monkeypatch.setenv("HOME_MONITOR_DB_PATH", str(db_path))
    monkeypatch.setattr("home_monitor.core.ping_host", lambda _ip: True)
    init_db(db_path)
    save_scan_results([("192.168.0.77", "ping-device.local", "", "")], db_path=db_path)
    app = create_app()

    with app.test_client() as client:
        response = client.post(
            "/dashboard/ping-selection",
            data={"ip": "192.168.0.77", "ping_enabled": ["0", "1"]},
            follow_redirects=True,
        )

    assert response.status_code == 200
    assert 'aria-label="Enable ping for 192.168.0.77" checked' in response.get_data(
        as_text=True
    )
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT ping_enabled FROM devices WHERE ip = ?", ("192.168.0.77",)
        ).fetchone()
    assert row == (1,)
