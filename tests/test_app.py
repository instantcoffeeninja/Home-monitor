import os

from home_monitor.app import DEFAULT_PORT, create_app


def test_dashboard_returns_old_home_monitor_ui(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("HOME_MONITOR_DB_PATH", str(tmp_path / "home-monitor.db"))
    app = create_app()

    with app.test_client() as client:
        response = client.get("/dashboard")

    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "Home Monitor" in body
    assert "Sidste server-restart:" in body
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
