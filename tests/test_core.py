from __future__ import annotations

import subprocess
from datetime import UTC, datetime
from pathlib import Path

from home_monitor.core import (
    DiscoveredDevice,
    NetworkScanWorker,
    normalize_device_name,
    parse_nmap_output,
    persist_scan_results,
    run_nmap_scan,
    summarize_status,
)


def test_normalize_device_name_removes_unsafe_characters() -> None:
    assert normalize_device_name(" Front Door Cam #1 ") == "front-door-cam-1"


def test_normalize_device_name_rejects_empty_output() -> None:
    try:
        normalize_device_name("!!!")
        assert False, "Expected ValueError"
    except ValueError:
        assert True


def test_summarize_status_uses_normalized_device_name() -> None:
    assert summarize_status(" Living Room ", True) == {
        "device": "living-room",
        "status": "online",
    }


def test_parse_nmap_output_extracts_host_ip_mac_and_vendor() -> None:
    output = """Starting Nmap 7.95 ( https://nmap.org )\nNmap scan report for router.local (192.168.0.1)\nHost is up (0.0020s latency).\nMAC Address: AA:BB:CC:DD:EE:FF (Netgear)\nNmap scan report for 192.168.0.20\nHost is up (0.021s latency).\nNmap done: 256 IP addresses (2 hosts up) scanned in 2.15 seconds\n"""

    devices = parse_nmap_output(output)

    assert devices == [
        DiscoveredDevice(
            ip_address="192.168.0.1",
            host_name="router.local",
            mac_address="AA:BB:CC:DD:EE:FF",
            vendor="Netgear",
        ),
        DiscoveredDevice(
            ip_address="192.168.0.20",
            host_name=None,
            mac_address=None,
            vendor=None,
        ),
    ]


def test_run_nmap_scan_runs_expected_command() -> None:
    calls: list[list[str]] = []

    def fake_runner(cmd, check, capture_output, text):
        del check, capture_output, text
        calls.append(cmd)
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout="Nmap scan report for 192.168.0.5\nHost is up\n",
        )

    devices = run_nmap_scan("192.168.0.1/24", runner=fake_runner)

    assert calls == [["nmap", "-sn", "192.168.0.0/24"]]
    assert devices[0].ip_address == "192.168.0.5"


def test_persist_scan_results_upserts_into_devices_table(tmp_path: Path) -> None:
    db_path = tmp_path / "home-monitor.db"
    first_scan = [
        DiscoveredDevice(
            ip_address="192.168.0.10",
            host_name="tv.local",
            mac_address="11:22:33:44:55:66",
            vendor="Samsung",
        )
    ]
    second_scan = [
        DiscoveredDevice(
            ip_address="192.168.0.10",
            host_name="smart-tv",
            mac_address="11:22:33:44:55:66",
            vendor="Samsung",
        )
    ]

    first_written = persist_scan_results(
        first_scan,
        db_path=db_path,
        now=datetime(2026, 4, 19, tzinfo=UTC),
    )
    second_written = persist_scan_results(
        second_scan,
        db_path=db_path,
        now=datetime(2026, 4, 20, tzinfo=UTC),
    )

    import sqlite3

    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT ip_address, host_name, mac_address, vendor, last_seen FROM devices"
        ).fetchone()

    assert first_written == 1
    assert second_written == 1
    assert row == (
        "192.168.0.10",
        "smart-tv",
        "11:22:33:44:55:66",
        "Samsung",
        "2026-04-20T00:00:00+00:00",
    )


def test_network_scan_worker_runs_single_scan_with_persistence(monkeypatch, tmp_path: Path) -> None:
    db_path = tmp_path / "home-monitor.db"

    monkeypatch.setattr(
        "home_monitor.core.run_nmap_scan",
        lambda _: [
            DiscoveredDevice(
                ip_address="192.168.0.30",
                host_name="camera",
                mac_address=None,
                vendor=None,
            )
        ],
    )

    worker = NetworkScanWorker(db_path=db_path, interval_seconds=60)
    inserted = worker.run_scan_once()

    assert inserted == 1
