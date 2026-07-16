#!/usr/bin/env python3

import json
import socket
import ssl
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from recorder import RecorderState, route_class, value_shape


class StateTests(unittest.TestCase):
    def test_endpoint_state_machine_and_missing_steps(self) -> None:
        state = RecorderState("happy", ["mount-preflight", "kv-read"])
        first = state.respond("GET", "/v1/sys/internal/ui/mounts/secret/example")
        self.assertEqual(first.status, 200)
        self.assertFalse(state.summary()["complete"])
        second = state.respond("GET", "/v1/secret/data/example")
        self.assertEqual(second.body["data"]["metadata"]["version"], 1)
        self.assertTrue(state.summary()["complete"])

    def test_out_of_order_and_fault_actions(self) -> None:
        state = RecorderState("fault-403", ["mount-preflight"])
        response = state.respond("GET", "/v1/secret/data/example")
        self.assertEqual(response.status, 403)
        self.assertFalse(state.summary()["complete"])
        self.assertEqual(RecorderState("reset").respond("GET", "/").action, "reset")
        self.assertEqual(RecorderState("timeout").respond("GET", "/").action, "timeout")

    def test_routes_and_shapes_are_content_free(self) -> None:
        self.assertEqual(route_class("POST", "/v1/auth/approle/login"), "approle-login")
        self.assertEqual(route_class("GET", "/v1/sys/seal-status"), "seal-status")
        self.assertEqual(route_class("GET", "/v1/sys/health"), "health")
        self.assertEqual(route_class("GET", "/v1/sys/leader"), "leader")
        self.assertEqual(route_class("GET", "/v1/auth/token/lookup-self"), "lookup-self")
        self.assertEqual(value_shape({"secret": "canary", "n": 1}), {"n": "number", "secret": "string"})


class TlsLifecycleTests(unittest.TestCase):
    def test_tls_mode_and_clean_shutdown(self) -> None:
        recorder = Path(__file__).with_name("recorder.py")
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            key = directory / "key.pem"
            cert = directory / "cert.pem"
            output = directory / "raw.jsonl"
            ready = directory / "ready"
            summary = directory / "summary.json"
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-keyout", key, "-out", cert],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            process = subprocess.Popen(
                [str(recorder), "--cert", str(cert), "--key", str(key), "--output", str(output), "--ready", str(ready), "--summary", str(summary), "--scenario", "happy", "--expected", "health"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                for _ in range(100):
                    if ready.exists():
                        break
                    time.sleep(0.02)
                port = int(ready.read_text())
                context = ssl.create_default_context(cafile=str(cert))
                with socket.create_connection(("127.0.0.1", port)) as raw:
                    with context.wrap_socket(raw, server_hostname="localhost") as client:
                        client.sendall(b"GET /v1/sys/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                        response = b""
                        while chunk := client.recv(4096):
                            response += chunk
                self.assertIn(b"200 OK", response)
            finally:
                process.terminate()
                process.wait(timeout=5)
            self.assertTrue(json.loads(summary.read_text())["complete"])
            self.assertEqual(json.loads(output.read_text())["route"], "health")


if __name__ == "__main__":
    unittest.main()
