"""HTTP API for frozen overlay audits.

Endpoints:

* ``POST /audits``      body ``{"id": str, "layers": [b64gzipTAR, ...]}``
                        (1..6 layers, bottom-to-top).  Validates and
                        adjudicates all layers; on success the frozen result
                        is stored and returned with 201.  Any layer failure
                        yields 400 and stores nothing.  Re-using an existing
                        id yields 409 (audits are immutable once frozen).
* ``GET  /audits/{id}`` return the frozen result (404 if unknown).
* ``GET  /audits``      list frozen audit ids.
* ``GET  /healthz``     liveness probe used by the Compose healthcheck.

Run: ``python -m app.server`` (env ``PORT``, default 8080; ``HOST``).
Healthcheck mode: ``python -m app.server healthcheck`` exits 0 iff the
local service answers on ``PORT``.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import sys
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import engine, tarparse

MAX_LAYERS = 6
MAX_BODY = 64 * 1024 * 1024
MAX_LAYER_BYTES = 16 * 1024 * 1024
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class AuditStore:
    """In-memory registry of frozen audits (id -> immutable result)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._audits: dict[str, dict] = {}

    def freeze(self, audit_id: str, result: dict) -> bool:
        with self._lock:
            if audit_id in self._audits:
                return False
            self._audits[audit_id] = result
            return True

    def get(self, audit_id: str) -> dict | None:
        with self._lock:
            return self._audits.get(audit_id)

    def ids(self) -> list[str]:
        with self._lock:
            return sorted(self._audits)


def build_audit(audit_id, layers_b64) -> dict:
    """Validate the request payload and adjudicate all layers atomically."""
    if not isinstance(audit_id, str) or not ID_RE.match(audit_id):
        raise ValueError("invalid audit id "
                         "(1-128 chars: letters, digits, '.', '_', '-')")
    if not isinstance(layers_b64, list) or not 1 <= len(layers_b64) <= MAX_LAYERS:
        raise ValueError(f"layers must be a list of 1..{MAX_LAYERS} entries")
    layers = []
    for i, blob in enumerate(layers_b64):
        if not isinstance(blob, str):
            raise ValueError(f"layer {i}: not a base64 string")
        try:
            raw = base64.b64decode(blob, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError(f"layer {i}: invalid base64: {exc}") from exc
        if len(raw) > MAX_LAYER_BYTES:
            raise ValueError(f"layer {i}: compressed layer exceeds size limit")
        try:
            layers.append(tarparse.parse_layer(raw))
        except tarparse.TarError as exc:
            raise ValueError(f"layer {i}: {exc}") from exc
    try:
        result = engine.apply_layers(layers)
    except engine.EngineError as exc:
        raise ValueError(str(exc)) from exc
    return {"id": audit_id, "layerCount": len(layers), **result}


def make_handler(store: AuditStore):
    class Handler(BaseHTTPRequestHandler):
        server_version = "PayloadAudit/1.0"
        protocol_version = "HTTP/1.1"

        def _send(self, code: int, obj: dict) -> None:
            body = json.dumps(obj, indent=2).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _error(self, code: int, message: str) -> None:
            self._send(code, {"error": message})

        def do_GET(self) -> None:  # noqa: N802 (http.server naming)
            path = urllib.parse.urlsplit(self.path).path
            if path == "/healthz":
                self._send(200, {"status": "ok"})
            elif path == "/":
                self._send(200, {
                    "service": "payload-overlay-audit",
                    "endpoints": ["POST /audits", "GET /audits/{id}",
                                  "GET /audits", "GET /healthz"],
                })
            elif path == "/audits":
                self._send(200, {"audits": store.ids()})
            elif path.startswith("/audits/"):
                audit_id = urllib.parse.unquote(path[len("/audits/"):])
                result = store.get(audit_id)
                if result is None:
                    self._error(404, "audit not found")
                else:
                    self._send(200, result)
            else:
                self._error(404, "not found")

        def do_POST(self) -> None:  # noqa: N802
            path = urllib.parse.urlsplit(self.path).path
            if path != "/audits":
                self._error(404, "not found")
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                self._error(400, "invalid Content-Length")
                return
            if length <= 0:
                self._error(400, "empty request body")
                return
            if length > MAX_BODY:
                self._error(413, "request body too large")
                return
            try:
                payload = json.loads(self.rfile.read(length))
            except json.JSONDecodeError as exc:
                self._error(400, f"invalid JSON: {exc}")
                return
            if not isinstance(payload, dict):
                self._error(400, "JSON object expected")
                return
            try:
                result = build_audit(payload.get("id"), payload.get("layers"))
            except ValueError as exc:
                self._error(400, str(exc))
                return
            if not store.freeze(result["id"], result):
                self._error(409, "audit id already frozen")
                return
            self._send(201, result)

        def log_message(self, fmt, *args) -> None:
            sys.stderr.write("audit-server: " + fmt % args + "\n")

    return Handler


def _healthcheck() -> int:
    port = int(os.environ.get("PORT", "8080"))
    try:
        with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/healthz", timeout=3) as resp:
            return 0 if resp.status == 200 else 1
    except Exception:
        return 1


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "healthcheck":
        sys.exit(_healthcheck())
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    httpd = ThreadingHTTPServer((host, port), make_handler(AuditStore()))
    httpd.daemon_threads = True
    print(f"audit server listening on {host}:{port}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
