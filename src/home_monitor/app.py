"""Flask application for Home Monitor."""

from __future__ import annotations

import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Protocol, cast

from .core import (
    DEFAULT_DEVICES_TABLE,
    DEFAULT_NMAP_BIN,
    DEFAULT_PING_INTERVAL_SECONDS,
    DEFAULT_SCAN_INTERVAL_SECONDS,
    DEFAULT_SCAN_NETWORK,
    NetworkScanWorker,
    format_restart_time,
    format_uptime,
    get_dashboard_rows,
    get_ip_history,
    get_ping_enabled_ips,
    get_recently_discovered_ips,
    get_saved_hostname,
    init_db,
    ping_scheduler,
    render_device_summary_bar,
    render_hostname_history_table,
    render_hosts_table,
    render_status_legend,
    scan_and_store,
    set_ping_enabled,
    update_saved_hostname,
)

DEFAULT_PORT = 5000
START_TIME_MONOTONIC = time.monotonic()
SERVER_RESTART_TIME = datetime.now(timezone.utc)


class _FlaskLike(Protocol):
    def get(self, rule: str): ...

    def post(self, rule: str): ...

    def route(self, rule: str, **options): ...

    def run(self, host: str, port: int, debug: bool) -> None: ...


def _load_flask_module() -> ModuleType:
    try:
        import flask
    except ModuleNotFoundError as exc:  # pragma: no cover - exercised via tests
        raise RuntimeError(
            "Flask is not installed. Install dependencies with: python -m pip install -r requirements.txt"
        ) from exc

    return flask


def _db_path() -> Path:
    return Path(
        os.getenv("HOME_MONITOR_DB_PATH", os.getenv("DB_PATH", "home_monitor.db"))
    )


def _scan_target() -> str:
    return os.getenv(
        "HOME_MONITOR_SCAN_TARGET", os.getenv("NETWORK_RANGE", DEFAULT_SCAN_NETWORK)
    )


def _scan_interval() -> int:
    return int(
        os.getenv(
            "HOME_MONITOR_SCAN_INTERVAL_SECONDS",
            os.getenv("SCAN_INTERVAL_SECONDS", str(DEFAULT_SCAN_INTERVAL_SECONDS)),
        )
    )


def _ping_interval() -> int:
    return int(
        os.getenv(
            "HOME_MONITOR_PING_INTERVAL_SECONDS",
            os.getenv("PING_INTERVAL_SECONDS", str(DEFAULT_PING_INTERVAL_SECONDS)),
        )
    )


def _nmap_bin() -> str:
    return os.getenv("HOME_MONITOR_NMAP_BIN", os.getenv("NMAP_BIN", DEFAULT_NMAP_BIN))


def _port() -> int:
    return int(os.getenv("PORT", str(DEFAULT_PORT)))


def create_app() -> _FlaskLike:
    """Create and configure the Flask app."""
    flask = _load_flask_module()
    app = cast(_FlaskLike, flask.Flask(__name__))

    @app.get("/health")
    def health() -> tuple[str, int, dict[str, str]]:
        uptime_seconds = int(time.monotonic() - START_TIME_MONOTONIC)
        body = f"OK\nUptime: {format_uptime(uptime_seconds)}"
        return body, 200, {"Content-Type": "text/plain; charset=utf-8"}

    @app.get("/")
    @app.get("/dashboard")
    def dashboard() -> str:
        db_path = _db_path()
        rows = get_dashboard_rows(db_path)
        hosts_table = render_hosts_table(
            rows,
            ping_enabled_ips=get_ping_enabled_ips(db_path),
            newly_discovered_ips=get_recently_discovered_ips(db_path),
        )
        return flask.render_template(
            "index.html",
            restart_time=format_restart_time(SERVER_RESTART_TIME),
            hosts_table=hosts_table,
            status_legend=render_status_legend(),
            summary_bar=render_device_summary_bar(rows),
        )

    @app.get("/history")
    def history() -> str:
        selected_ip = flask.request.args.get("ip", "").strip()
        if not selected_ip:
            flask.abort(400, description="IP query parameter is required")

        db_path = _db_path()
        history_table = render_hostname_history_table(
            selected_ip,
            get_saved_hostname(selected_ip, db_path),
            get_ip_history(selected_ip, db_path),
        )
        return flask.render_template("history.html", history_table=history_table)

    @app.post("/history/update")
    def update_history():
        ip = flask.request.form.get("ip", "").strip()
        hostname = flask.request.form.get("hostname", "")
        if not ip:
            flask.abort(400, description="IP field is required")

        update_saved_hostname(ip, hostname, _db_path())
        return flask.redirect(flask.url_for("history", ip=ip), code=303)

    @app.post("/dashboard/ping-selection")
    def update_ping_selection():
        ip = flask.request.form.get("ip", "").strip()
        enabled = flask.request.form.get("ping_enabled", "0") == "1"
        if not ip:
            flask.abort(400, description="IP field is required")

        set_ping_enabled(ip, enabled, _db_path())
        return flask.redirect(flask.url_for("dashboard"), code=303)

    @app.post("/dashboard/scan")
    def run_manual_scan():
        scan_and_store(
            db_path=_db_path(), network_range=_scan_target(), nmap_bin=_nmap_bin()
        )
        return flask.redirect(flask.url_for("dashboard"), code=303)

    return app


def _build_worker() -> NetworkScanWorker:
    return NetworkScanWorker(
        db_path=_db_path(),
        scan_target=_scan_target(),
        interval_seconds=_scan_interval(),
        table_name=os.getenv("HOME_MONITOR_DEVICES_TABLE", DEFAULT_DEVICES_TABLE),
    )


def run_server() -> None:
    """Run the Flask development server on the configured port."""
    app = create_app()
    db_path = _db_path()
    init_db(db_path)

    worker = _build_worker()
    worker.start()

    stop_event = threading.Event()
    ping_thread = threading.Thread(
        target=ping_scheduler,
        args=(stop_event,),
        kwargs={"db_path": db_path, "interval_seconds": _ping_interval()},
        daemon=True,
        name="ping-worker",
    )
    ping_thread.start()

    print(f"Home Monitor kører på http://0.0.0.0:{_port()}")
    try:
        app.run(host="0.0.0.0", port=_port(), debug=False)
    finally:
        stop_event.set()
        worker.stop()


if __name__ == "__main__":
    run_server()
