from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

from .domain import (ConflictError, DomainError, NotFoundError, PermissionDenied,
                     ValidationError)
from .service import Service


def make_handler(service: Service, static_dir: str):
    root = Path(static_dir)

    class Handler(BaseHTTPRequestHandler):
        server_version = "ModularHell/1.0"

        def log_message(self, fmt: str, *args: Any) -> None:
            return

        def _json(self, status: int, payload: Any) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _html(self, path: Path) -> None:
            if not path.exists():
                self._json(404, {"error": "not_found"})
                return
            body = path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _identity(self) -> Tuple[str, str]:
            return self.headers.get("X-Actor", ""), self.headers.get("X-Role", "")

        @staticmethod
        def _zone_id(path: str) -> int:
            segment = path.split("/")[3]
            if not segment.isdigit():
                raise NotFoundError("任务区不存在")
            return int(segment)

        def _body(self) -> Dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0") or 0)
            if length <= 0:
                return {}
            if length > 2_000_000:
                raise ValidationError("请求体过大")
            try:
                value = json.loads(self.rfile.read(length).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValidationError("请求体不是有效JSON") from exc
            if not isinstance(value, dict):
                raise ValidationError("请求体必须是JSON对象")
            return value

        def _send_error(self, exc: Exception) -> None:
            if isinstance(exc, ValidationError):
                status = 422
            elif isinstance(exc, NotFoundError):
                status = 404
            elif isinstance(exc, PermissionDenied):
                status = 403
            elif isinstance(exc, ConflictError):
                status = 409
            elif isinstance(exc, ValueError):
                status = 422
            elif isinstance(exc, DomainError):
                status = 400
            else:
                status = 500
            self._json(status, {"error": exc.__class__.__name__, "message": str(exc)})

        def do_GET(self) -> None:
            try:
                path = urlparse(self.path).path
                if path == "/health":
                    self._json(200, {"status": "ok"})
                elif path == "/":
                    self._html(root / "index.html")
                elif path == "/api/items":
                    actor, role = self._identity()
                    del actor
                    self._json(200, {"items": service.list_items(role)})
                elif path.startswith("/api/items/") and path.endswith("/records"):
                    item_id = int(path.split("/")[3])
                    actor, role = self._identity()
                    del actor
                    self._json(200, {"records": service.list_records(item_id, role)})
                elif path.startswith("/api/items/"):
                    item_id = int(path.rsplit("/", 1)[-1])
                    actor, role = self._identity()
                    del actor
                    self._json(200, service.get_item(item_id, role))
                elif path == "/api/audit":
                    actor, role = self._identity()
                    del actor
                    self._json(200, {"events": service.audit(role)})
                elif path == "/api/zones":
                    actor, role = self._identity()
                    del actor
                    self._json(200, {"zones": service.list_zones(role)})
                elif path.startswith("/api/zones/"):
                    parts = urlparse(self.path).path.strip("/").split("/")
                    zone_id = self._zone_id(path)
                    actor, role = self._identity()
                    if len(parts) == 3:
                        self._json(200, service.get_zone(zone_id, role))
                    elif len(parts) == 4 and parts[3] == "batches":
                        status = parse_qs(urlparse(self.path).query).get("status", [None])[0]
                        self._json(200, {"batches": service.list_batches(zone_id, role, status)})
                    elif len(parts) == 4 and parts[3] == "events":
                        self._json(200, {"events": service.list_zone_events(zone_id, role)})
                    elif len(parts) == 4 and parts[3] == "verify":
                        self._json(200, service.verify_zone_chain(zone_id, role))
                    elif len(parts) == 4 and parts[3] == "conflicts":
                        status = parse_qs(urlparse(self.path).query).get("status", [None])[0]
                        self._json(200, {"conflicts": service.list_conflicts(zone_id, role, status)})
                    elif len(parts) == 4 and parts[3] == "permits":
                        self._json(200, {"permits": service.list_permits(zone_id, role)})
                    else:
                        self._json(404, {"error": "not_found"})
                else:
                    self._json(404, {"error": "not_found"})
            except Exception as exc:
                self._send_error(exc)

        def do_POST(self) -> None:
            try:
                path = urlparse(self.path).path
                actor, role = self._identity()
                body = self._body()
                if path == "/api/items":
                    self._json(201, service.create_item(body, actor, role))
                elif path == "/api/zones":
                    self._json(201, service.create_zone(body, actor, role))
                elif path.startswith("/api/zones/"):
                    parts = urlparse(self.path).path.strip("/").split("/")
                    zone_id = self._zone_id(path)
                    if len(parts) == 4 and parts[3] == "batches":
                        self._json(202, service.submit_batch(zone_id, body, actor, role))
                    elif len(parts) == 4 and parts[3] == "recover":
                        self._json(200, service.recover_batches(zone_id, actor, role))
                    elif (len(parts) == 6 and parts[3] == "batches"
                          and parts[5] == "retry"):
                        ticket = unquote(parts[4])
                        self._json(200, service.retry_batch(zone_id, ticket, actor, role))
                    elif (len(parts) == 6 and parts[3] == "conflicts"
                          and parts[5] == "resolve"):
                        if not parts[4].isdigit():
                            self._json(404, {"error": "not_found"})
                            return
                        conflict_id = int(parts[4])
                        self._json(200, service.resolve_conflict(
                            zone_id, conflict_id, body, actor, role))
                    elif (len(parts) == 6 and parts[3] == "permits"
                          and parts[5] == "approve"):
                        if not parts[4].isdigit():
                            self._json(404, {"error": "not_found"})
                            return
                        permit_id = int(parts[4])
                        self._json(200, service.approve_permit(
                            zone_id, permit_id, body, actor, role))
                    else:
                        self._json(404, {"error": "not_found"})
                elif path.startswith("/api/items/") and path.endswith("/records"):
                    item_id = int(path.split("/")[3])
                    self._json(201, service.add_record(item_id, body, actor, role))
                elif path.startswith("/api/items/") and path.endswith("/transition"):
                    item_id = int(path.split("/")[3])
                    target = body.get("target")
                    expected = body.get("expected_version")
                    self._json(200, service.transition(
                        item_id, target, expected, actor, role))
                else:
                    self._json(404, {"error": "not_found"})
            except Exception as exc:
                self._send_error(exc)

    return Handler
