#!/usr/bin/env python3
"""Synthetic-only TLS responding recorder for pinned Vault-compatible clients."""

from __future__ import annotations

import argparse
import hashlib
import json
import signal
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit


SAFE_HEADER_NAMES = {
    "content-type",
    "user-agent",
    "x-vault-namespace",
    "x-vault-request",
    "x-vault-token",
}


def value_shape(value: object) -> object:
    if isinstance(value, dict):
        return {key: value_shape(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [value_shape(item) for item in value[:1]]
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    return "string"


def route_class(method: str, target: str) -> str:
    path = urlsplit(target).path
    if path.startswith("/v1/sys/internal/ui/mounts/"):
        return "mount-preflight"
    if path == "/v1/sys/seal-status":
        return "seal-status"
    if path == "/v1/sys/health":
        return "health"
    if path == "/v1/sys/leader":
        return "leader"
    if path == "/v1/auth/token/lookup-self":
        return "lookup-self"
    if path == "/v1/auth/approle/login":
        return "approle-login"
    if "/data/" in path and method == "GET":
        return "kv-read"
    return "unknown"


@dataclass(frozen=True)
class Response:
    action: str
    status: int = 200
    body: dict[str, object] | None = None


class RecorderState:
    def __init__(self, scenario: str, expected: list[str] | None = None):
        self.scenario = scenario
        self.expected = expected or []
        self.observed: list[str] = []
        self.out_of_order: list[dict[str, object]] = []
        self.lock = threading.Lock()

    def respond(self, method: str, target: str) -> Response:
        classification = route_class(method, target)
        with self.lock:
            index = len(self.observed)
            self.observed.append(classification)
            if index < len(self.expected) and classification != self.expected[index]:
                self.out_of_order.append(
                    {"index": index, "expected": self.expected[index], "actual": classification}
                )

        if self.scenario == "reset":
            return Response("reset")
        if self.scenario == "timeout":
            return Response("timeout")
        if self.scenario.startswith("fault-"):
            status = int(self.scenario.removeprefix("fault-"))
            return Response("reply", status, {"errors": [f"synthetic-{status}"]})
        if self.scenario == "sealed-503":
            return Response(
                "reply",
                503,
                {"initialized": True, "sealed": True, "standby": False, "version": "2.6.0"},
            )

        bodies: dict[str, dict[str, object]] = {
            "mount-preflight": {
                "data": {
                    "path": "secret/",
                    "type": "kv",
                    "options": {"version": "2"},
                }
            },
            "kv-read": {
                "data": {
                    "data": {"value": "OLSS_SYNTHETIC_VALUE_482f1a"},
                    "metadata": {
                        "created_time": "2026-07-16T00:00:00Z",
                        "custom_metadata": None,
                        "deletion_time": "",
                        "destroyed": False,
                        "version": 1,
                    },
                }
            },
            "seal-status": {
                "initialized": True,
                "sealed": False,
                "standby": False,
                "version": "2.6.0",
            },
            "health": {
                "initialized": True,
                "sealed": False,
                "standby": False,
                "version": "2.6.0",
            },
            "leader": {
                "ha_enabled": False,
                "is_self": True,
                "leader_address": "https://localhost",
                "leader_cluster_address": "",
                "performance_standby": False,
            },
            "lookup-self": {
                "data": {
                    "accessor": "OLSS_SYNTHETIC_ACCESSOR_9c21",
                    "policies": ["default"],
                    "ttl": 300,
                }
            },
            "approle-login": {
                "auth": {
                    "accessor": "OLSS_SYNTHETIC_ACCESSOR_9c21",
                    "client_token": "OLSS_SYNTHETIC_TOKEN_7d9f3c2a1b8e6d4f",
                    "lease_duration": 300,
                    "policies": ["default"],
                    "renewable": False,
                    "token_policies": ["default"],
                    "token_type": "service",
                },
                "data": None,
                "lease_duration": 0,
                "lease_id": "",
                "renewable": False,
            },
        }
        body = bodies.get(classification, {"errors": ["synthetic-not-found"]})
        return Response("reply", 200 if classification in bodies else 404, body)

    def summary(self) -> dict[str, object]:
        missing = self.expected[len(self.observed) :]
        return {
            "scenario": self.scenario,
            "observed": self.observed,
            "request_count": len(self.observed),
            "missing": missing,
            "out_of_order": self.out_of_order,
            "complete": not missing and not self.out_of_order,
        }


class RecorderHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "olss-recorder"
    sys_version = ""

    def do_GET(self) -> None:  # noqa: N802
        self._handle()

    def do_POST(self) -> None:  # noqa: N802
        self._handle()

    def do_PUT(self) -> None:  # noqa: N802
        self._handle()

    def _handle(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length) if length else b""
        body_json: object = None
        if body:
            try:
                body_json = json.loads(body)
            except (json.JSONDecodeError, UnicodeDecodeError):
                body_json = "non-json"
        state: RecorderState = self.server.state  # type: ignore[attr-defined]
        response = state.respond(self.command, self.path)
        target = urlsplit(self.path)
        record = {
            "method": self.command,
            "raw_target_hex": self.path.encode("utf-8", "surrogateescape").hex(),
            "path_hex": target.path.encode("utf-8", "surrogateescape").hex(),
            "query_keys": sorted(key for key, _value in parse_qsl(target.query, keep_blank_values=True)),
            "target_sha256": hashlib.sha256(
                self.path.encode("utf-8", "surrogateescape")
            ).hexdigest(),
            "route": route_class(self.command, self.path),
            "header_names": sorted(
                name.lower() for name in self.headers if name.lower() in SAFE_HEADER_NAMES
            ),
            "token_header_present": "X-Vault-Token" in self.headers,
            "body_shape": value_shape(body_json),
            "scripted_action": response.action,
            "scripted_status": response.status if response.action == "reply" else None,
        }
        with self.server.output_lock:  # type: ignore[attr-defined]
            with self.server.output.open("a", encoding="utf-8") as stream:  # type: ignore[attr-defined]
                stream.write(json.dumps(record, sort_keys=True) + "\n")

        if response.action == "reset":
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        if response.action == "timeout":
            time.sleep(self.server.timeout_seconds)  # type: ignore[attr-defined]
            return
        encoded = json.dumps(response.body, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(response.status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(encoded)))
        self.send_header("connection", "close")
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class RecorderServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ready", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--expected", default="")
    parser.add_argument("--timeout-seconds", type=float, default=2.0)
    args = parser.parse_args()

    expected = [item for item in args.expected.split(",") if item]
    state = RecorderState(args.scenario, expected)
    server = RecorderServer((args.host, args.port), RecorderHandler)
    server.state = state  # type: ignore[attr-defined]
    server.output = args.output  # type: ignore[attr-defined]
    server.output_lock = threading.Lock()  # type: ignore[attr-defined]
    server.timeout_seconds = args.timeout_seconds  # type: ignore[attr-defined]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)

    stopping = threading.Event()

    def stop(_signum: int, _frame: object) -> None:
        if not stopping.is_set():
            stopping.set()
            threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    ready_tmp = args.ready.with_suffix(args.ready.suffix + ".tmp")
    ready_tmp.write_text(str(server.server_port), encoding="ascii")
    ready_tmp.replace(args.ready)
    try:
        server.serve_forever(poll_interval=0.05)
    finally:
        server.server_close()
        args.summary.write_text(json.dumps(state.summary(), sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
