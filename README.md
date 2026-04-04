# Home Monitor

Minimal Python-webserver som fundament for et kommende dashboard over:
- status på systemer
- tilsluttede enheder i hjemmenetværket

## Krav

- Python 3.10+

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

Du kan ændre port via miljøvariablen `PORT`:

```bash
PORT=9000 python3 server.py
```

## Endpoints

- `GET /` — simpel placeholder-side
- `GET /dashboard` — samme placeholder-side
- `GET /health` — health-check, returnerer `ok`

## Test

```bash
pytest
```
