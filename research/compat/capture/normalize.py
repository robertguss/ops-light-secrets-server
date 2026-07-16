#!/usr/bin/env python3
"""Fail-closed normalization for captured client traces."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


TOOL_VERSION = "client-trace-normalizer-v1"
CLIENTS = [
    ("vault-2.0.3", None), ("bao-2.6.0", None),
    ("fnox-1.30.0", "vault"), ("fnox-1.30.0", "bao"),
    ("fnox-1.29.0", "vault"), ("fnox-1.29.0", "bao"),
]
ROUTES = {"mount-preflight", "kv-read", "seal-status", "leader", "health",
          "lookup-self", "approle-login", "unknown"}
BODY_KEYS = {"accessor", "auth", "client_token", "created_time", "custom_metadata",
             "data", "deletion_time", "destroyed", "errors", "ha_enabled", "initialized",
             "is_self", "leader_address", "leader_cluster_address", "lease_duration",
             "lease_id", "metadata", "options", "path", "performance_standby", "policies",
             "renewable", "sealed", "standby", "token_policies", "token_type", "ttl", "type",
             "value", "version", "role_id", "secret_id"}
HEADER_NAMES = {"content-type", "user-agent", "x-vault-namespace", "x-vault-request",
                "x-vault-token"}
LEAF_SHAPES = {"string", "number", "boolean", "null", "non-json"}
SENSITIVE_MARKERS = ("BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY",
                     "/home/", "/Users/", "OLSS_SYNTHETIC_TOKEN_", "OLSS_SYNTHETIC_SECRET_ID_",
                     "OLSS_SYNTHETIC_ROLE_", "OLSS_SYNTHETIC_VALUE_", "OLSS_SYNTHETIC_ACCESSOR_")


class NormalizationError(ValueError):
    pass


def exact(value: dict[str, object], keys: set[str], context: str) -> None:
    if not isinstance(value, dict) or set(value) != keys:
        raise NormalizationError(f"schema mismatch: {context}")


def safe_text(value: object, context: str) -> str:
    if not isinstance(value, str) or any(marker in value for marker in SENSITIVE_MARKERS):
        raise NormalizationError(f"unsafe text: {context}")
    return value


def safe_hex(value: object, context: str) -> str:
    text = safe_text(value, context)
    if len(text) % 2 or not re.fullmatch(r"[0-9a-f]*", text):
        raise NormalizationError(f"invalid hex: {context}")
    return text


def body_shape(value: object) -> object:
    if isinstance(value, str):
        if value not in LEAF_SHAPES:
            raise NormalizationError("unknown body leaf")
        return value
    if isinstance(value, list):
        if len(value) > 1:
            raise NormalizationError("body list shape")
        return [body_shape(item) for item in value]
    if isinstance(value, dict):
        if not set(value).issubset(BODY_KEYS):
            raise NormalizationError("unknown body field")
        return {key: body_shape(value[key]) for key in sorted(value)}
    if value is None:
        return None
    raise NormalizationError("unknown body shape")


def clean_process(value: object) -> dict[str, object]:
    exact(value, {"outcome", "exit_status", "duration_ms"}, "process")  # type: ignore[arg-type]
    outcome = safe_text(value["outcome"], "process outcome")  # type: ignore[index]
    status = value["exit_status"]  # type: ignore[index]
    if outcome not in {"exit", "driver-timeout"} or (status is not None and not isinstance(status, int)):
        raise NormalizationError("invalid process")
    return {"outcome": outcome, "exit_status": status}


def clean_request(value: object) -> dict[str, object]:
    exact(value, {"method", "raw_target_hex", "path_hex", "query_keys", "route", "header_names",
                  "token_header_present", "body_shape", "scripted_action", "scripted_status"},
          "request")  # type: ignore[arg-type]
    method = safe_text(value["method"], "method")  # type: ignore[index]
    route = safe_text(value["route"], "route")  # type: ignore[index]
    action = safe_text(value["scripted_action"], "action")  # type: ignore[index]
    if method not in {"GET", "POST", "PUT"} or route not in ROUTES or action not in {"reply", "reset", "timeout"}:
        raise NormalizationError("request enum")
    headers = value["header_names"]  # type: ignore[index]
    queries = value["query_keys"]  # type: ignore[index]
    if not isinstance(headers, list) or not isinstance(queries, list):
        raise NormalizationError("request lists")
    normalized_headers = sorted({safe_text(item, "header").lower() for item in headers})
    if not set(normalized_headers).issubset(HEADER_NAMES):
        raise NormalizationError("unknown header")
    normalized_queries = sorted({safe_text(item, "query key") for item in queries})
    if any(not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", item) for item in normalized_queries):
        raise NormalizationError("query key")
    status = value["scripted_status"]  # type: ignore[index]
    if status is not None and (not isinstance(status, int) or not 100 <= status <= 599):
        raise NormalizationError("scripted status")
    present = value["token_header_present"]  # type: ignore[index]
    if not isinstance(present, bool):
        raise NormalizationError("token presence")
    return {
        "method": method,
        "raw_target_hex": safe_hex(value["raw_target_hex"], "raw target"),  # type: ignore[index]
        "path_hex": safe_hex(value["path_hex"], "path"),  # type: ignore[index]
        "query_keys": normalized_queries,
        "route": route,
        "header_names": normalized_headers,
        "token_header_present": present,
        "body_shape": body_shape(value["body_shape"]),  # type: ignore[index]
        "scripted_action": action,
        "scripted_status": status,
    }


def clean_stub(value: object) -> dict[str, object]:
    exact(value, {"scenario", "observed", "request_count", "missing", "out_of_order", "complete"},
          "stub")  # type: ignore[arg-type]
    observed = value["observed"]  # type: ignore[index]
    missing = value["missing"]  # type: ignore[index]
    order = value["out_of_order"]  # type: ignore[index]
    if not isinstance(observed, list) or not isinstance(missing, list) or not isinstance(order, list):
        raise NormalizationError("stub lists")
    if any(item not in ROUTES for item in observed + missing):
        raise NormalizationError("stub route")
    normalized_order = []
    for item in order:
        exact(item, {"index", "expected", "actual"}, "out-of-order")
        if item["expected"] not in ROUTES or item["actual"] not in ROUTES or not isinstance(item["index"], int):
            raise NormalizationError("out-of-order value")
        normalized_order.append(item)
    count = value["request_count"]  # type: ignore[index]
    complete = value["complete"]  # type: ignore[index]
    if not isinstance(count, int) or not isinstance(complete, bool) or count != len(observed):
        raise NormalizationError("stub summary")
    return {"scenario": safe_text(value["scenario"], "stub scenario"), "observed": observed,
            "request_count": count, "missing": missing, "out_of_order": normalized_order,
            "complete": complete}


def clean_run(value: object, keys: set[str], context: str) -> dict[str, object]:
    exact(value, keys, context)  # type: ignore[arg-type]
    output = {key: value[key] for key in keys - {"process", "requests", "stub"}}  # type: ignore[index]
    output["process"] = clean_process(value["process"])  # type: ignore[index]
    output["requests"] = [clean_request(item) for item in value["requests"]]  # type: ignore[index]
    output["stub"] = clean_stub(value["stub"])  # type: ignore[index]
    return {key: output[key] for key in sorted(output)}


def normalize_client(value: object, expected: tuple[str, str | None]) -> dict[str, object]:
    name, backend = expected
    direct = backend is None
    keys = {"client", "tls_root", "paths", "faults"} | (
        {"approle", "probes"} if direct else {"backend_executable", "subprocess_argv"})
    exact(value, keys, "client")  # type: ignore[arg-type]
    if value["client"] != name or value["tls_root"] != "VAULT_CACERT":  # type: ignore[index]
        raise NormalizationError("client identity")
    if not direct and value["backend_executable"] != backend:  # type: ignore[index]
        raise NormalizationError("backend identity")
    paths = []
    for item in value["paths"]:  # type: ignore[index]
        cleaned = clean_run(item, {"case", "input_utf8_hex", "process", "requests", "stub"}, "path")
        cleaned["case"] = safe_text(cleaned["case"], "path case")
        cleaned["input_utf8_hex"] = safe_hex(cleaned["input_utf8_hex"], "path input")
        paths.append(cleaned)
    faults = []
    for item in value["faults"]:  # type: ignore[index]
        cleaned = clean_run(item, {"scenario", "process", "request_count", "routes", "requests", "stub"}, "fault")
        cleaned["scenario"] = safe_text(cleaned["scenario"], "fault scenario")
        if cleaned["request_count"] != len(cleaned["requests"]):
            raise NormalizationError("fault count")
        if cleaned["routes"] != [request["route"] for request in cleaned["requests"]]:
            raise NormalizationError("fault routes")
        faults.append(cleaned)
    output: dict[str, object] = {"schema": 1, "client": name, "backend": backend or "direct",
                                "token_supply": "VAULT_TOKEN", "tls_root": "VAULT_CACERT",
                                "paths": paths, "faults": faults}
    if direct:
        output["approle"] = clean_run(value["approle"], {"process", "requests", "stub"}, "approle")  # type: ignore[index]
        probes = []
        for item in value["probes"]:  # type: ignore[index]
            cleaned = clean_run(item, {"probe", "process", "requests", "stub"}, "probe")
            cleaned["probe"] = safe_text(cleaned["probe"], "probe")
            probes.append(cleaned)
        output["probes"] = probes
    else:
        commands = value["subprocess_argv"]  # type: ignore[index]
        if not isinstance(commands, list):
            raise NormalizationError("subprocess argv")
        normalized_commands = []
        for command in commands:
            if not isinstance(command, list) or len(command) != 4 or command[:3] != ["kv", "get", "-field=value"]:
                raise NormalizationError("subprocess command")
            normalized_commands.append([safe_text(part, "subprocess argument") for part in command])
        output["subprocess_argv"] = normalized_commands
    return output


def encoded(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def normalize(source: Path, output: Path) -> None:
    root = json.loads(source.read_text(encoding="utf-8"))
    exact(root, {"schema", "synthetic_only", "raw_capture_retained", "platform", "clients"}, "root")
    if root["schema"] != 1 or root["synthetic_only"] is not True or root["raw_capture_retained"] is not False:
        raise NormalizationError("root markers")
    if root["platform"] != "linux-amd64" or not isinstance(root["clients"], list) or len(root["clients"]) != 6:
        raise NormalizationError("root matrix")
    if output.exists() and any(output.iterdir()):
        raise NormalizationError("output must be empty")
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    files = []
    for raw, expected in zip(root["clients"], CLIENTS, strict=True):
        fixture = normalize_client(raw, expected)
        suffix = expected[1] or "direct"
        filename = f"{expected[0]}-{suffix}.json"
        content = encoded(fixture)
        (output / filename).write_bytes(content)
        files.append({"path": filename, "sha256": hashlib.sha256(content).hexdigest()})
    manifest = {"schema": 1, "tool_version": TOOL_VERSION, "source_schema": 1,
                "provenance": {"harness_schema": 1, "scanner": "full-artifact-v1",
                               "capture_platform": "linux-amd64"}, "files": files}
    (output / "manifest.json").write_bytes(encoded(manifest))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    normalize(args.input, args.output)
    print(json.dumps({"schema": 1, "event": "normalization_complete", "files": 7}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
