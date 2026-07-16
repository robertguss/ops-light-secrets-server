#!/usr/bin/env python3
"""Run synthetic compatibility captures and emit normalized, replayable evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
MATRIX = ROOT / "research/compat/client-matrix.json"
RECORDER = Path(__file__).with_name("recorder.py")
TOKEN = "OLSS_SYNTHETIC_TOKEN_7d9f3c2a1b8e6d4f"
ROLE_ID = "OLSS_SYNTHETIC_ROLE_18f3a9"
SECRET_ID = "OLSS_SYNTHETIC_SECRET_ID_42d8b7"
PATH_CASES = {
    "space": "space name",
    "utf8": "café",
    "percent-slash": "encoded%2Fslash",
    "percent-percent": "percent%25value",
    "dot": ".",
    "dotdot": "..",
    "leading-slash": "/leading",
    "trailing-slash": "trailing/",
    "double-slash": "double//slash",
    "plus": "plus+sign",
    "overlong": "a" * 1025,
}
FAULTS = ["fault-403", "fault-404", "fault-500", "sealed-503", "reset", "timeout"]
ACTIVE_STUBS: set["Stub"] = set()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def prepare_clients(archives: Path, destination: Path) -> dict[str, Path]:
    matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
    binaries: dict[str, Path] = {}
    destination.mkdir(mode=0o700)
    for entry in matrix["clients"]:
        archive = archives / entry["archive"]
        if sha256(archive) != entry["sha256"]:
            raise RuntimeError(f"checksum mismatch for {entry['archive']}")
        key = f"{entry['product']}-{entry['version']}"
        extracted = destination / key
        extracted.mkdir(mode=0o700)
        if entry["format"] == "zip":
            with zipfile.ZipFile(archive) as bundle:
                bundle.extract(entry["binary"], extracted)
        else:
            with tarfile.open(archive, "r:gz") as bundle:
                member = bundle.getmember(entry["binary"])
                bundle.extract(member, extracted, filter="data")
        binary = extracted / entry["binary"]
        binary.chmod(0o700)
        binaries[key] = binary
    return binaries


def generate_certificate(directory: Path) -> tuple[Path, Path]:
    key = directory / "server-key.pem"
    cert = directory / "test-ca-and-server.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-keyout", str(key), "-out", str(cert),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    key.chmod(0o600)
    cert.chmod(0o600)
    return cert, key


class Stub:
    def __init__(self, private: Path, cert: Path, key: Path, scenario: str, sequence: int):
        self.raw = private / f"raw-{sequence}.jsonl"
        self.ready = private / f"ready-{sequence}"
        self.summary = private / f"summary-{sequence}.json"
        self.process = subprocess.Popen(
            [
                sys.executable, str(RECORDER), "--cert", str(cert), "--key", str(key),
                "--output", str(self.raw), "--ready", str(self.ready), "--summary", str(self.summary),
                "--scenario", scenario, "--timeout-seconds", "1.5",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        ACTIVE_STUBS.add(self)
        for _ in range(250):
            if self.ready.exists() and self.ready.stat().st_size:
                try:
                    self.port = int(self.ready.read_text(encoding="ascii"))
                    break
                except ValueError:
                    pass
            if self.process.poll() is not None:
                ACTIVE_STUBS.discard(self)
                raise RuntimeError("recorder exited before ready")
            time.sleep(0.02)
        if not hasattr(self, "port"):
            self.close()
            raise RuntimeError("recorder did not become ready")

    def stop(self) -> tuple[list[dict[str, object]], dict[str, object]]:
        self.close()
        lines = self.raw.read_text(encoding="utf-8").splitlines() if self.raw.exists() else []
        records = [json.loads(line) for line in lines]
        summary = (
            json.loads(self.summary.read_text(encoding="utf-8"))
            if self.summary.exists()
            else {"scenario": "unknown", "observed": [], "request_count": 0,
                  "missing": [], "out_of_order": [], "complete": False}
        )
        return records, summary

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        ACTIVE_STUBS.discard(self)


def safe_env(cert: Path, port: int, path: Path | None = None) -> dict[str, str]:
    env = {
        "HOME": str(path or cert.parent),
        "LANG": "C.UTF-8",
        "PATH": str(path) if path else "/usr/bin:/bin",
        "VAULT_ADDR": f"https://localhost:{port}",
        "VAULT_CACERT": str(cert),
        "VAULT_CLIENT_TIMEOUT": "2s",
        "VAULT_MAX_RETRIES": "2",
        "VAULT_TOKEN": TOKEN,
        "FNOX_NON_INTERACTIVE": "true",
    }
    return env


def invoke(command: list[str], env: dict[str, str], private: Path, label: str) -> dict[str, object]:
    stdout = private / f"{label}.stdout"
    stderr = private / f"{label}.stderr"
    started = time.monotonic()
    outcome = "exit"
    status: int | None = None
    with stdout.open("wb") as out, stderr.open("wb") as err:
        try:
            completed = subprocess.run(command, env=env, stdout=out, stderr=err, timeout=10, check=False)
            status = completed.returncode
        except subprocess.TimeoutExpired:
            outcome = "driver-timeout"
    return {
        "outcome": outcome,
        "exit_status": status,
        "duration_ms": round((time.monotonic() - started) * 1000),
    }


def summarized_records(records: list[dict[str, object]]) -> list[dict[str, object]]:
    return [
        {
            "method": record["method"],
            "raw_target_hex": record["raw_target_hex"],
            "path_hex": record["path_hex"],
            "query_keys": record["query_keys"],
            "route": record["route"],
            "header_names": record["header_names"],
            "token_header_present": record["token_header_present"],
            "body_shape": record["body_shape"],
            "scripted_action": record["scripted_action"],
            "scripted_status": record["scripted_status"],
        }
        for record in records
    ]


def emit_step(client: str, scenario: str, result: dict[str, object], request_count: int) -> None:
    print(json.dumps({
        "schema": 1,
        "event": "capture_step",
        "client": client,
        "scenario": scenario,
        "step": "client-invocation",
        "status": result["exit_status"],
        "outcome": result["outcome"],
        "duration_ms": result["duration_ms"],
        "retry_count": max(request_count - 1, 0),
        "fixture_path": f"normalized:clients/{client}/{scenario}",
        "reproducer": "research/compat/capture/run_capture.py --archives <verified> --output <normalized>",
    }, sort_keys=True))


def direct_command(binary: Path, kind: str, path: str) -> list[str]:
    return [str(binary), "kv", "get", "-format=json", f"secret/{path}"]


def make_fnox_config(path: Path, address: str, value: str) -> None:
    path.write_text(
        "[providers.vault]\n"
        'type = "vault"\n'
        f'address = "{address}"\n'
        'path = "secret"\n'
        f'token = "{TOKEN}"\n\n'
        "[secrets.CAPTURE]\n"
        'provider = "vault"\n'
        f"value = {json.dumps(value, ensure_ascii=False)}\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


def install_wrapper(directory: Path, target: Path, argv_log: Path) -> None:
    wrapper = directory / "vault"
    wrapper.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$#\" \"$@\" >> {json.dumps(str(argv_log))}\n"
        f"exec {json.dumps(str(target))} \"$@\"\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o700)


def capture_direct(
    client: str, binary: Path, cert: Path, key: Path, private: Path, sequence: list[int]
) -> dict[str, object]:
    evidence: dict[str, object] = {
        "client": client, "tls_root": "VAULT_CACERT", "paths": [], "faults": [], "probes": []
    }
    for case, value in PATH_CASES.items():
        sequence[0] += 1
        stub = Stub(private, cert, key, "happy", sequence[0])
        result = invoke(direct_command(binary, client, value), safe_env(cert, stub.port), private, f"{client}-path-{case}")
        records, summary = stub.stop()
        emit_step(client, f"path-{case}", result, len(records))
        evidence["paths"].append({"case": case, "input_utf8_hex": value.encode().hex(), "process": result, "requests": summarized_records(records), "stub": summary})
    for fault in FAULTS:
        sequence[0] += 1
        stub = Stub(private, cert, key, fault, sequence[0])
        result = invoke(direct_command(binary, client, "capture"), safe_env(cert, stub.port), private, f"{client}-{fault}")
        records, summary = stub.stop()
        emit_step(client, fault, result, len(records))
        evidence["faults"].append({"scenario": fault, "process": result, "request_count": len(records), "routes": [record["route"] for record in records], "requests": summarized_records(records), "stub": summary})
    sequence[0] += 1
    stub = Stub(private, cert, key, "happy", sequence[0])
    command = [str(binary), "write", "-format=json", "auth/approle/login", f"role_id={ROLE_ID}", f"secret_id={SECRET_ID}"]
    result = invoke(command, safe_env(cert, stub.port), private, f"{client}-approle")
    records, summary = stub.stop()
    emit_step(client, "approle", result, len(records))
    evidence["approle"] = {"process": result, "requests": summarized_records(records), "stub": summary}
    probes = {
        "seal-status": [str(binary), "status", "-format=json"],
        "health": [str(binary), "read", "-format=json", "sys/health"],
        "lookup-self": [str(binary), "token", "lookup", "-format=json"],
    }
    for probe, command in probes.items():
        sequence[0] += 1
        stub = Stub(private, cert, key, "happy", sequence[0])
        result = invoke(command, safe_env(cert, stub.port), private, f"{client}-probe-{probe}")
        records, summary = stub.stop()
        emit_step(client, f"probe-{probe}", result, len(records))
        evidence["probes"].append(
            {"probe": probe, "process": result, "requests": summarized_records(records), "stub": summary}
        )
    return evidence


def capture_fnox(
    client: str, binary: Path, backend: str, backend_binary: Path, cert: Path, key: Path, private: Path, sequence: list[int]
) -> dict[str, object]:
    evidence: dict[str, object] = {"client": client, "backend_executable": backend, "tls_root": "VAULT_CACERT", "paths": [], "faults": []}
    wrapper_dir = private / f"wrapper-{client}-{backend}"
    wrapper_dir.mkdir(mode=0o700)
    argv_log = private / f"argv-{client}-{backend}.log"
    install_wrapper(wrapper_dir, backend_binary, argv_log)
    for case, value in PATH_CASES.items():
        sequence[0] += 1
        stub = Stub(private, cert, key, "happy", sequence[0])
        config = private / f"config-{client}-{backend}-{case}.toml"
        make_fnox_config(config, f"https://localhost:{stub.port}", f"{value}/value")
        command = [str(binary), "--config", str(config), "--no-daemon", "--non-interactive", "get", "CAPTURE"]
        result = invoke(command, safe_env(cert, stub.port, wrapper_dir), private, f"{client}-{backend}-path-{case}")
        records, summary = stub.stop()
        emit_step(f"{client}-{backend}", f"path-{case}", result, len(records))
        evidence["paths"].append({"case": case, "input_utf8_hex": value.encode().hex(), "process": result, "requests": summarized_records(records), "stub": summary})
    for fault in FAULTS:
        sequence[0] += 1
        stub = Stub(private, cert, key, fault, sequence[0])
        config = private / f"config-{client}-{backend}-{fault}.toml"
        make_fnox_config(config, f"https://localhost:{stub.port}", "capture/value")
        command = [str(binary), "--config", str(config), "--no-daemon", "--non-interactive", "get", "CAPTURE"]
        result = invoke(command, safe_env(cert, stub.port, wrapper_dir), private, f"{client}-{backend}-{fault}")
        records, summary = stub.stop()
        emit_step(f"{client}-{backend}", fault, result, len(records))
        evidence["faults"].append({"scenario": fault, "process": result, "request_count": len(records), "routes": [record["route"] for record in records], "requests": summarized_records(records), "stub": summary})
    argv_lines = argv_log.read_text(encoding="utf-8").splitlines() if argv_log.exists() else []
    commands: list[list[str]] = []
    index = 0
    while index < len(argv_lines):
        count = int(argv_lines[index])
        commands.append(argv_lines[index + 1 : index + 1 + count])
        index += count + 1
    evidence["subprocess_argv"] = commands
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archives", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    sequence = [0]
    interrupted = False

    def interrupt(_signum: int, _frame: object) -> None:
        nonlocal interrupted
        interrupted = True
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, interrupt)
    signal.signal(signal.SIGTERM, interrupt)
    try:
        with tempfile.TemporaryDirectory(prefix="olss-capture-") as private_name:
            private = Path(private_name)
            private.chmod(0o700)
            clients = prepare_clients(args.archives.resolve(), private / "clients")
            cert, key = generate_certificate(private)
            evidence = {
                "schema": 1,
                "synthetic_only": True,
                "raw_capture_retained": False,
                "platform": "linux-amd64",
                "clients": [],
            }
            evidence["clients"].append(capture_direct("vault-2.0.3", clients["vault-2.0.3"], cert, key, private, sequence))
            evidence["clients"].append(capture_direct("bao-2.6.0", clients["bao-2.6.0"], cert, key, private, sequence))
            for version in ["1.30.0", "1.29.0"]:
                name = f"fnox-{version}"
                for backend in ["vault", "bao"]:
                    evidence["clients"].append(capture_fnox(name, clients[name], backend, clients[f"{backend}-{'2.0.3' if backend == 'vault' else '2.6.0'}"], cert, key, private, sequence))
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    finally:
        for stub in list(ACTIVE_STUBS):
            stub.close()
    if interrupted:
        return 130
    print(json.dumps({"schema": 1, "event": "capture_complete", "clients": 6, "raw_retained": False, "output": str(output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
