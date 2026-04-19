"""Flask application for Home Monitor."""

from __future__ import annotations

from types import ModuleType
from typing import Protocol, cast

DEFAULT_PORT = 5000


class _FlaskLike(Protocol):
    def get(self, rule: str): ...

    def run(self, host: str, port: int, debug: bool) -> None: ...


def _load_flask_module() -> ModuleType:
    try:
        import flask
    except ModuleNotFoundError as exc:  # pragma: no cover - exercised via tests
        raise RuntimeError(
            "Flask is not installed. Install dependencies with: python -m pip install -r requirements.txt"
        ) from exc

    return flask


def create_app() -> _FlaskLike:
    """Create and configure the Flask app."""
    flask = _load_flask_module()
    app = cast(_FlaskLike, flask.Flask(__name__))

    @app.get("/")
    def index() -> str:
        return "This is a test / hello world information page for Home Monitor."

    return app


def run_server() -> None:
    """Run the Flask development server on the configured port."""
    app = create_app()
    app.run(host="0.0.0.0", port=DEFAULT_PORT, debug=False)


if __name__ == "__main__":
    run_server()
