"""Small Flask-compatible subset used by tests in this repository."""

from __future__ import annotations

from dataclasses import dataclass
from html import escape as html_escape
import os
import threading
from types import SimpleNamespace
from typing import Any, Callable
from urllib.parse import parse_qs, urlencode, urlsplit


@dataclass
class Response:
    body: bytes
    status_code: int = 200
    headers: dict[str, str] | None = None

    def __post_init__(self) -> None:
        if self.headers is None:
            self.headers = {}

    def get_data(self, as_text: bool = False) -> str | bytes:
        if as_text:
            return self.body.decode("utf-8")
        return self.body


class HTTPAbort(Exception):
    def __init__(self, status_code: int, description: str = "") -> None:
        super().__init__(description)
        self.status_code = status_code
        self.description = description


class _RequestProxy:
    _state = threading.local()

    def _get_current(self) -> Any:
        req = getattr(self._state, "request", None)
        if req is None:
            raise RuntimeError("request is not available outside a request context")
        return req

    def _set_current(self, req: Any) -> None:
        self._state.request = req

    def _clear_current(self) -> None:
        self._state.request = None

    def __getattr__(self, item: str) -> Any:
        return getattr(self._get_current(), item)


request = _RequestProxy()


class Flask:
    _latest_app: "Flask | None" = None

    def __init__(self, import_name: str):
        self.import_name = import_name
        Flask._latest_app = self
        self._routes: dict[tuple[str, str], Callable[[], Any]] = {}
        self._endpoint_paths: dict[str, str] = {}

    def route(self, rule: str, methods: list[str] | None = None) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        allowed_methods = methods or ["GET"]

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            for method in allowed_methods:
                self._routes[(method.upper(), rule)] = func
            self._endpoint_paths.setdefault(func.__name__, rule)
            return func

        return decorator

    def post(self, rule: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        return self.route(rule, methods=["POST"])

    def test_client(self) -> "_TestClient":
        return _TestClient(self)

    def run(self, host: str = "127.0.0.1", port: int = 5000) -> None:
        # Minimal compatibility for local usage; not needed in tests.
        raise RuntimeError("This lightweight Flask stub does not implement app.run().")


class _TestClient:
    def __init__(self, app: Flask):
        self.app = app

    def __enter__(self) -> "_TestClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def get(self, path: str, follow_redirects: bool = False) -> Response:
        return self._request("GET", path, data=None, follow_redirects=follow_redirects)

    def post(self, path: str, data: dict[str, Any] | None = None, follow_redirects: bool = False) -> Response:
        return self._request("POST", path, data=data or {}, follow_redirects=follow_redirects)

    def _request(self, method: str, path: str, data: dict[str, Any] | None, follow_redirects: bool) -> Response:
        current_path = path
        for _ in range(10):
            response = self._dispatch_once(method, current_path, data)
            if not follow_redirects:
                return response
            if response.status_code not in {301, 302, 303, 307, 308}:
                return response
            location = response.headers.get("Location", "")
            if not location:
                return response
            current_path = location
            method = "GET"
            data = None
        return response

    def _dispatch_once(self, method: str, path: str, data: dict[str, Any] | None) -> Response:
        split = urlsplit(path)
        route = split.path
        query_args = {k: v[-1] for k, v in parse_qs(split.query, keep_blank_values=True).items()}

        handler = self.app._routes.get((method.upper(), route))
        if handler is None:
            return Response(b"Not Found", 404, {"Content-Type": "text/plain; charset=utf-8"})

        req = SimpleNamespace(args=query_args, form=data or {})
        request._set_current(req)
        try:
            result = handler()
        except HTTPAbort as err:
            return Response((err.description or "").encode("utf-8"), err.status_code, {"Content-Type": "text/plain; charset=utf-8"})
        finally:
            request._clear_current()

        return _coerce_response(result)


def _coerce_response(result: Any) -> Response:
    if isinstance(result, Response):
        return result

    if isinstance(result, tuple):
        if len(result) == 2:
            body, status = result
            headers: dict[str, str] = {}
        elif len(result) == 3:
            body, status, headers = result
            headers = dict(headers)
        else:
            raise ValueError("Unsupported response tuple")
        body_bytes = body.encode("utf-8") if isinstance(body, str) else bytes(body)
        if "Content-Type" not in headers:
            headers["Content-Type"] = "text/html; charset=utf-8"
        return Response(body_bytes, int(status), headers)

    body_bytes = result.encode("utf-8") if isinstance(result, str) else bytes(result)
    return Response(body_bytes, 200, {"Content-Type": "text/html; charset=utf-8"})


def abort(status_code: int, description: str = "") -> None:
    raise HTTPAbort(status_code, description=description)


def redirect(location: str, code: int = 302) -> Response:
    return Response(b"", code, {"Location": location})


def url_for(endpoint: str, **values: Any) -> str:
    app = _find_current_app()
    path = app._endpoint_paths.get(endpoint)
    if path is None:
        raise KeyError(f"Unknown endpoint: {endpoint}")
    if values:
        return f"{path}?{urlencode(values)}"
    return path


def _find_current_app() -> Flask:
    if Flask._latest_app is None:
        raise RuntimeError("No Flask app found")
    return Flask._latest_app


def render_template(template_name: str, **context: Any) -> str:
    path = os.path.join("templates", template_name)
    with open(path, encoding="utf-8") as handle:
        template = handle.read()

    rendered = template
    for key, value in context.items():
        safe_token = "{{ " + key + "|safe }}"
        plain_token = "{{ " + key + " }}"
        rendered = rendered.replace(safe_token, str(value))
        rendered = rendered.replace(plain_token, html_escape(str(value)))
    return rendered
