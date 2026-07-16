#!/usr/bin/env python3
"""Replay stable semantic assertions over normalized compatibility observations."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


PATH_CASES = [
    "space", "utf8", "percent-slash", "percent-percent", "dot", "dotdot",
    "leading-slash", "trailing-slash", "double-slash", "plus", "overlong",
]
FAULT_COUNTS = {
    "fault-403": 1,
    "fault-404": 2,
    "fault-500": 2,
    "sealed-503": 2,
    "reset": 2,
    "timeout": 1,
}
SENTINELS = ["OLSS_SYNTHETIC_TOKEN", "OLSS_SYNTHETIC_SECRET", "OLSS_SYNTHETIC_ROLE",
             "OLSS_SYNTHETIC_VALUE", "OLSS_SYNTHETIC_ACCESSOR"]


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def stable_requests(path: dict[str, object]) -> list[dict[str, object]]:
    return path["requests"]  # type: ignore[return-value]


def validate(path: Path) -> None:
    raw = path.read_text(encoding="utf-8")
    for sentinel in SENTINELS:
        check(sentinel not in raw, f"secret sentinel leaked: {sentinel}")
    evidence = json.loads(raw)
    check(evidence["schema"] == 1, "schema")
    check(evidence["synthetic_only"] is True, "synthetic-only marker")
    check(evidence["raw_capture_retained"] is False, "raw-retention marker")
    check(evidence["platform"] == "linux-amd64", "capture platform")
    clients = evidence["clients"]
    identities = [(item["client"], item.get("backend_executable", "direct")) for item in clients]
    check(identities == [
        ("vault-2.0.3", "direct"), ("bao-2.6.0", "direct"),
        ("fnox-1.30.0", "vault"), ("fnox-1.30.0", "bao"),
        ("fnox-1.29.0", "vault"), ("fnox-1.29.0", "bao"),
    ], "client matrix")

    direct = clients[:2]
    for client in direct:
        check(client["tls_root"] == "VAULT_CACERT", "direct TLS root")
        check([item["case"] for item in client["paths"]] == PATH_CASES, "direct path cases")
        for item in client["paths"]:
            requests = stable_requests(item)
            check(len(requests) == 2, f"direct request count: {item['case']}")
            check([request["route"] for request in requests] == ["mount-preflight", "kv-read"]
                  if item["case"] not in {"dot", "dotdot"} else
                  [request["route"] for request in requests] in
                  (["mount-preflight", "unknown"], ["unknown", "unknown"]),
                  f"direct routes: {item['case']}")
            for request in requests:
                check(request["token_header_present"] is True, "token header presence")
        check({item["scenario"]: item["request_count"] for item in client["faults"]}
              == FAULT_COUNTS, "direct fault retries")
        check(client["approle"]["process"]["exit_status"] == 0, "AppRole status")
        check([request["route"] for request in client["approle"]["requests"]]
              == ["approle-login"], "AppRole route")
        check({item["probe"]: [request["route"] for request in item["requests"]]
               for item in client["probes"]} == {
                   "seal-status": ["seal-status", "leader"], "health": ["health"],
                   "lookup-self": ["lookup-self"],
               }, "probe routes")

    direct_paths = {item["case"]: stable_requests(item) for item in direct[0]["paths"]}
    check(direct_paths == {item["case"]: stable_requests(item) for item in direct[1]["paths"]},
          "Vault/Bao wire equivalence")
    for client in clients[2:]:
        check(client["tls_root"] == "VAULT_CACERT", "fnox TLS root")
        check([item["case"] for item in client["paths"]] == PATH_CASES, "fnox path cases")
        commands = client["subprocess_argv"]
        check(len(commands) == 14, "fnox subprocess count")
        check(all(command[:3] == ["kv", "get", "-field=value"] for command in commands),
              "fnox exact subprocess shape")
        emitted = {item["case"]: stable_requests(item) for item in client["paths"]
                   if stable_requests(item)}
        check(set(emitted) == set(PATH_CASES) - {"leading-slash", "trailing-slash", "double-slash"},
              "fnox client-side rejection set")
        check(emitted == {case: direct_paths[case] for case in emitted}, "fnox wire equivalence")
        check({item["scenario"]: item["request_count"] for item in client["faults"]}
              == FAULT_COUNTS, "fnox fault retries")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("observations", type=Path)
    args = parser.parse_args()
    validate(args.observations)
    print(json.dumps({"schema": 1, "event": "capture_replay_pass", "clients": 6}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
