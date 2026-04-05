# Home Monitor

Minimal Python-webserver som dashboard over aktive enheder på hjemmenetværket.

## Funktioner

- Kører `nmap -sn` mod netværket `192.168.0.0/24` (kan ændres via miljøvariabler)
- Gemmer scanningsresultater i SQLite (`home_monitor.db`)
- Scanner automatisk én gang i timen
- Viser seneste nmap-resultat på dashboard med kolonnerne IP og Hostname

## Krav

- Python 3.10+
- `nmap` installeret på maskinen hvor serveren kører

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Kør lokalt

```bash
python3 server.py
```

Serveren lytter på `0.0.0.0` og kører som standard på `http://localhost:8000`.

## Konfiguration (miljøvariabler)

- `PORT` (default: `8000`)
- `DB_PATH` (default: `home_monitor.db`)
- `NETWORK_RANGE` (default: `192.168.0.0/24`)
- `NMAP_BIN` (default: `nmap`)
- `SCAN_INTERVAL_SECONDS` (default: `3600`)

Eksempel:

```bash
PORT=9000 DB_PATH=./data.db NETWORK_RANGE=192.168.0.0/24 python3 server.py
```

## Endpoints

- `GET /` — dashboard med seneste nmap-resultat
- `GET /dashboard` — samme dashboard
- `GET /health` — health-check, returnerer `OK` + uptime

## Test

```bash
pytest
```
