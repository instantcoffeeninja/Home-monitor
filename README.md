# Home Monitor (Reset Baseline)

This repository has been reset to a clean Python baseline.

## What this includes
- A small, secure utility module in `src/home_monitor/core.py`
- A Flask app in `src/home_monitor/app.py` with an information/hello-world front page
- Unit tests in `tests/`

## Run tests
```bash
python -m pytest -q
```

## Run the Flask server
```bash
python -m home_monitor.app
```

The server runs on port `5000`.

## Network scan background task
When `python -m home_monitor.app` starts, a background worker runs `nmap -sn` on `192.168.0.1/24` and upserts discovered devices into the SQLite table `devices` in `home_monitor.db`.

Environment overrides:
- `HOME_MONITOR_DB_PATH` (default: `home_monitor.db`)
- `HOME_MONITOR_DEVICES_TABLE` (default: `devices`)
- `HOME_MONITOR_SCAN_TARGET` (default: `192.168.0.1/24`)
- `HOME_MONITOR_SCAN_INTERVAL_SECONDS` (default: `300`)
