import sqlite3
import subprocess

import server


class DummyCompletedProcess:
    def __init__(self, stdout: str):
        self.stdout = stdout


def test_database_connection_and_nmap_results_are_saved(tmp_path, monkeypatch):
    db_path = tmp_path / "scan_results.db"

    nmap_output = """\
# Nmap 7.94 scan initiated
Host: 192.168.0.2 (router.local) Status: Up
Host: 192.168.0.12 (tv.local) Status: Up
# Nmap done
"""

    def fake_run(command, capture_output, text, check):
        assert command[0] == "nmap"
        assert "-sn" in command
        return DummyCompletedProcess(stdout=nmap_output)

    monkeypatch.setattr(subprocess, "run", fake_run)

    server.init_db(str(db_path))
    saved_hosts = server.scan_and_store(db_path=str(db_path), network_range="192.168.0.0/24", nmap_bin="nmap")

    assert saved_hosts == [("192.168.0.2", "router.local"), ("192.168.0.12", "tv.local")]

    with sqlite3.connect(str(db_path)) as conn:
        connection_check = conn.execute("SELECT 1").fetchone()[0]
        assert connection_check == 1

        rows = conn.execute(
            "SELECT ip, hostname FROM nmap_results ORDER BY ip ASC"
        ).fetchall()

    assert rows == [("192.168.0.12", "tv.local"), ("192.168.0.2", "router.local")]
