import sys
import types

from home_monitor.app import DEFAULT_PORT, create_app, run_server


class FakeFlaskApp:
    def __init__(self, import_name: str) -> None:
        self.import_name = import_name
        self.routes: dict[str, object] = {}
        self.run_calls: list[dict[str, object]] = []

    def get(self, rule: str):
        def decorator(fn):
            self.routes[rule] = fn
            return fn

        return decorator

    def run(self, host: str, port: int, debug: bool) -> None:
        self.run_calls.append({"host": host, "port": port, "debug": debug})


class FakeFlaskModule(types.SimpleNamespace):
    def __init__(self) -> None:
        self.last_app: FakeFlaskApp | None = None

        def flask_factory(import_name: str) -> FakeFlaskApp:
            app = FakeFlaskApp(import_name)
            self.last_app = app
            return app

        super().__init__(Flask=flask_factory)


def test_index_route_returns_information_message(monkeypatch) -> None:
    fake_flask = FakeFlaskModule()
    monkeypatch.setitem(sys.modules, "flask", fake_flask)

    app = create_app()

    handler = app.routes["/"]
    assert (
        handler() == "This is a test / hello world information page for Home Monitor."
    )


def test_run_server_uses_port_5000(monkeypatch) -> None:
    fake_flask = FakeFlaskModule()
    monkeypatch.setitem(sys.modules, "flask", fake_flask)

    run_server()

    run_call = fake_flask.last_app.run_calls[0]
    assert run_call["port"] == DEFAULT_PORT == 5000
    assert run_call["host"] == "0.0.0.0"
    assert run_call["debug"] is False
