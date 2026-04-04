# Home Monitor

Minimal Python-webserver som fundament for et kommende dashboard over:
- status på systemer
- tilsluttede enheder i hjemmenetværket

## Kør lokalt

```bash
python3 app.py
```

Serveren starter som standard på `http://localhost:8000`.

## Næste skridt

1. Erstat statisk HTML med templates.
2. Tilføj endpoint(s) til system- og enhedsdata.
3. Tilføj health-check endpoint (`/health`).
4. Tilføj tests og CI.
