# Home Monitor

Minimal Python-webserver som fundament for et kommende dashboard over:
- status på systemer
- tilsluttede enheder i hjemmenetværket

## Kør lokalt

```bash
python3 app.py
```

Serveren starter som standard på `http://localhost:8000`.

## Endpoints

- `/` og `/dashboard`: placeholder dashboard
- `/health`: returnerer status `200` og teksten `ok`

## Test

```bash
python3 -m unittest discover -s tests
```
