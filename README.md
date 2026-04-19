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
