from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))
from server import app


def test_health_returns_200_and_ok():
    with app.test_client() as client:
        response = client.get("/health")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    lines = body.splitlines()
    assert lines[0] == "OK"
    assert lines[1].startswith("Uptime: ")
